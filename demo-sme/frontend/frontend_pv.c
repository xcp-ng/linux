// SPDX-License-Identifier: GPL-2.0-only
/*
 * Implementation of pv front driver for demo-sme
*/

#include <linux/module.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/device.h>

#include <xen/xen.h>
#include <xen/events.h>
#include <xen/interface/io/ring.h>
#include <xen/grant_table.h>
#include <xen/xenbus.h>
#include <xen/page.h>
#include <xen/platform_pci.h>
#include "../pv_device.h"

struct xensme_front_info {
	struct xenbus_device *dev;
	struct smepv_front_ring ring;
	grant_ref_t gref;
	unsigned int evtchn;
	domid_t backend_id;
	int irq;
};

static irqreturn_t smefront_irq_fn(int irq, void *dev_id)
{
	struct xensme_front_info *info = dev_id;
	unsigned int eoiflag = XEN_EOI_FLAG_SPURIOUS;
	char *shared_ring_buffer;

    if (info) {
        shared_ring_buffer = (char *)info->ring.sring;
        // The first byte should indicate if new data is present
        if (shared_ring_buffer[0] != 0) {
            pr_info("New data in shared ring: %s\n", shared_ring_buffer + 1);
            // Reset the first byte to indicate data has been processed
            shared_ring_buffer[0] = 0;
		}
    }

	// Enable/disable of preempt is a workaround, for production use-case proper
	// locking should be used
	preempt_disable();
    xen_irq_lateeoi(irq, eoiflag);
	preempt_enable();

    return IRQ_HANDLED;
}

// This function is used to setup the shared ring and an event channel
static int setup_shared_ring(struct xensme_front_info *info)
{
	struct xenbus_device *dev = info->dev;
	struct smepv_sring *sring;
	int err;

	err = xenbus_setup_ring(dev, GFP_KERNEL, (void **)&sring, 1,
				&info->gref);
	if (err < 0) {
		pr_err("xenbus_setup_ring failed: %d\n", err);
		return err;
	}

	XEN_FRONT_RING_INIT(&info->ring, sring, XEN_PAGE_SIZE);

	err = xenbus_alloc_evtchn(dev, &info->evtchn);
	if (err < 0) {
		pr_err("xenbus_alloc_evtchn failed: %d\n", err);
		return err;
	}

	err = bind_evtchn_to_irq_lateeoi(info->evtchn);
	if (err < 0) {
		xenbus_dev_fatal(dev, err,"bind_evtchn_to_irq failed");
		goto free_gnttab;
	}

	info->irq = err;
	err = request_threaded_irq(info->irq, NULL,smefront_irq_fn ,
				   IRQF_ONESHOT, "smefront", info);
	if (err) {
		xenbus_dev_fatal(dev, err, "request_threaded_irq");
		goto free_irq;
	}

	return 0;

free_irq:
	unbind_from_irqhandler(info->irq, info);
free_gnttab:
	xenbus_teardown_ring((void **)&sring, 1, &info->gref);

	return err;
}

static void free_shared_ring(struct xensme_front_info *info)
{
	if (!info)
		return;
	xenbus_teardown_ring((void **)&info->ring.sring, 1, &info->gref);

	if (info->irq)
		unbind_from_irqhandler(info->irq, info);

	kfree(info);
}

static int smefront_init_ring(struct xensme_front_info *info)
{
	struct xenbus_device *dev = info->dev;
	struct xenbus_transaction xbt;
	int err;

	err = setup_shared_ring(info);
	if (err)
		return err;
	pr_debug("%s: %u %u\n", __func__, info->gref, info->evtchn);

again:
	err = xenbus_transaction_start(&xbt);
	if (err)
		xenbus_dev_fatal(dev, err, "starting transaction");

	err = xenbus_printf(xbt, dev->nodename, "gref", "%u", info->gref);
	if (err) {
		xenbus_dev_fatal(dev, err, "%s", "writing gref");
		goto fail;
	}

	err = xenbus_printf(xbt, dev->nodename, "event-channel", "%u",
			    info->evtchn);

	if (err) {
		xenbus_dev_fatal(dev, err, "%s", "writing event-channel");
		goto fail;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err) {
		if (err == -EAGAIN)
			goto again;
		xenbus_dev_fatal(dev, err, "completing transaction");
		goto free_sring;
	}

	return 0;

fail:
	xenbus_transaction_end(xbt, 1);
free_sring:
	free_shared_ring(info);

	return err;
}

// This is called on a state change of the backend driver
static void sme_backend_changed(struct xenbus_device *dev,
				enum xenbus_state backend_state)
{
	struct xensme_front_info *info = dev_get_drvdata(&dev->dev);

	pr_debug("%s: %p %u %u\n", __func__, dev, dev->state, backend_state);

	switch (backend_state) {
	case XenbusStateInitialising:
		xenbus_switch_state(dev, XenbusStateInitialising);
		break;
	case XenbusStateInitialised:
	case XenbusStateReconfiguring:
	case XenbusStateReconfigured:
	case XenbusStateUnknown:
		break;

	case XenbusStateInitWait:
		if (dev->state != XenbusStateInitialising)
			break;
		if (setup_shared_ring(info))
			break;

		xenbus_switch_state(dev, XenbusStateConnected);
		break;

	case XenbusStateConnected:
		pr_info("Backend says it is connected as well.\n");
		break;

	case XenbusStateClosed:
		if (dev->state == XenbusStateClosed)
			break;
		fallthrough;
	case XenbusStateClosing:
		xenbus_frontend_closed(dev);
		break;
	}
}

static int smefront_probe(struct xenbus_device *dev,
			  const struct xenbus_device_id *id)
{
	struct xensme_front_info *info;
	int err;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating smeinfo structure");
		return -ENOMEM;
	}

	dev_set_drvdata(&dev->dev, info);
	info->dev = dev;

	err = smefront_init_ring(info);
	if (err) {
		free_shared_ring(info);
		return err;
	}

	xenbus_switch_state(dev, XenbusStateInitialised);
	return 0;
}

static int smefront_remove(struct xenbus_device *dev)
{
	struct xensme_front_info *info = dev_get_drvdata(&dev->dev);

	if (info) {
		free_shared_ring(info);
		kfree(info);
	}
	return 0;
}

static const struct xenbus_device_id smefront_ids[] = { { "sme" }, { "" } };

static struct xenbus_driver smefront_driver = {
	.ids = smefront_ids,
	.probe = smefront_probe,
	.remove = smefront_remove,
	.otherend_changed = sme_backend_changed,
};

static int __init xen_smefront_init(void)
{
	if (!xen_domain())
		return -ENODEV;

	if (!xen_has_pv_devices())
		return -ENODEV;

	printk(KERN_NOTICE "SME-demo frontend driver loaded");

	return xenbus_register_frontend(&smefront_driver);
}
module_init(xen_smefront_init);

static void __exit xen_smefront_exit(void)
{
	xenbus_unregister_driver(&smefront_driver);
	printk(KERN_NOTICE "SME-demo frontend driver unloaded");
}
module_exit(xen_smefront_exit);

MODULE_AUTHOR("Vaishali Thakkar");
MODULE_DESCRIPTION("Xen PV frontend sme-demo driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("xen:sme");
