// SPDX-License-Identifier: GPL-2.0-only
/*
 * Implementation of pv backend driver for demo-sme
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include "../pv_device.h"
#include <xen/interface/memory.h>
#include <xen/events.h>
#include <xen/page.h>
#include <xen/xen.h>
#include <xen/xenbus.h>

struct xensme_backend_info {
	struct xenbus_device *dev;
	struct smepv_back_ring ring;
	grant_ref_t gref;
	unsigned int evtchn;
	unsigned int irq;
	domid_t frontend_domid;
};

#define MAX_SIZE 1024
static char sme_id_buffer[MAX_SIZE];
static size_t sme_id_len = 0;
static char sme_text_buffer[MAX_SIZE];
static size_t sme_text_len = 0;

static bool xenmem_encrypt_state = false;
unsigned long shared_page_pfn;
static char *shared_ring_buffer;
static unsigned int global_irq = 0;

static ssize_t sme_id_read(struct file *filp, char __user *buffer,
                           size_t len, loff_t *offset)
{
    return simple_read_from_buffer(buffer, len, offset, sme_id_buffer, sme_id_len);
}

static ssize_t sme_id_write(struct file *filp, const char __user *buffer,
                           size_t count, loff_t *offp)
{
    struct xensme_backend_info *info;
	long int domid;

    ssize_t result = simple_write_to_buffer(sme_id_buffer, sizeof(sme_id_buffer), offp, buffer, count);
    if (result < 0)
        return result;

    sme_id_buffer[result] = '\0'; // Null-terminate the buffer
	sme_id_len = count;

    if (kstrtol(sme_id_buffer, 10, &domid) != 0 || domid < 0) {
        printk(KERN_WARNING "backend_module: Invalid input for domid\n");
        return -EINVAL;
    }

    info->frontend_domid = (domid_t)domid;

    return result;
}

static ssize_t sme_text_read(struct file *filp, char __user *buffer,
                             size_t len, loff_t *offset)
{
    return simple_read_from_buffer(buffer, len, offset, sme_text_buffer, sme_text_len);
}

static ssize_t sme_text_write(struct file *filp, const char __user *buffer,
                              size_t len, loff_t *offset)
{ 
	ssize_t ret;
	
	sme_text_len = min(len, (size_t)MAX_SIZE);
	// Clear the shared_ring_buffer and text_buffer before writing new data
	memset(shared_ring_buffer, 0, MAX_SIZE);
	memset(sme_text_buffer, 0 , MAX_SIZE);

	ret = simple_write_to_buffer(sme_text_buffer, MAX_SIZE,
									offset, buffer, sme_text_len);

	pr_info("write to proc_sme_text succeded");
	if (ret > 0) {
		memcpy(shared_ring_buffer+1, sme_text_buffer, sme_text_len);
		// Use the first byte as a flag to indicate new data
		shared_ring_buffer[0] =1 ;
		notify_remote_via_irq(global_irq);
	} else if (len > MAX_SIZE) {
		printk(KERN_WARNING "sme_text_write: Input data exceeds buffer size\n");
		return -EINVAL;
	}

	return ret;
}

static ssize_t xenmem_encrypt_write(struct file *filp, const char __user *buffer, size_t count, loff_t *offp)
{
    char buf[10];
    xen_mem_encrypt_op_t opt;
    int ret;

    if (count > sizeof(buf) - 1)
        return -EINVAL;

    if (copy_from_user(buf, buffer, count))
        return -EFAULT;

    buf[count] = '\0';
	if (buf[count - 1] == '\n')
        buf[count - 1] = '\0';
	
    if (strcmp(buf, "on") == 0) {
		opt.op = XENMEM_encrypt_on;
		xenmem_encrypt_state = true;
     } else if (strcmp(buf, "off") == 0) {
        opt.op = XENMEM_encrypt_off;
		xenmem_encrypt_state = false;
     } else {
        return -EINVAL; // Invalid input
    }

	opt.domid = 0;
	opt.pfn = shared_page_pfn; 
	// printk(KERN_INFO "XENMEM_encrypt_op: op = %d, domid = %d, pfn = %llu\n", opt.op, opt.domid, opt.pfn);
	
	ret = HYPERVISOR_memory_op(XENMEM_encrypt_op, &opt);
	printk(KERN_INFO "Making Xen hypercall for encryption: op = %d\n", opt.op);
	if (ret) {
    	printk(KERN_ERR "Xen hypercall failed: %d\n", ret);
    	return -EIO;
	}

    return count;
}

static ssize_t xenmem_encrypt_read(struct file *filp, char __user *buffer, size_t len, loff_t *offset)
{
    char state_str[4];
    int state_len;

    state_len = snprintf(state_str, sizeof(state_str), "%s\n",
						xenmem_encrypt_state ? "on" : "off");

	return simple_read_from_buffer(buffer, len, offset, state_str, state_len);
}

static struct proc_ops sme_id_fops = {
    .proc_read = sme_id_read,
    .proc_write = sme_id_write,
};

static struct proc_ops sme_text_fops = {
    .proc_read = sme_text_read,
    .proc_write = sme_text_write,
};

static struct proc_ops xenmem_encrypt_fops = {
    .proc_read = xenmem_encrypt_read,
    .proc_write = xenmem_encrypt_write,
};

static irqreturn_t smeback_irq_fn(int irq, void *dev_id) {
	unsigned int eoi_flags = XEN_EOI_FLAG_SPURIOUS;

    xen_irq_lateeoi(irq, eoi_flags);
	pr_info("smeback_irq_fn exited");
    return IRQ_HANDLED;
}

static int backend_connect(struct xensme_backend_info *info)
{
	struct xenbus_device *dev = info->dev;
	struct smepv_sring *sring;
	unsigned int gref;
	evtchn_port_t evtchn;
	void *addr;
	phys_addr_t phys_addr;
	int err;
	struct page *page;
	
	pr_info("connecting the backend now\n");	
	err = xenbus_gather(XBT_NIL, dev->otherend, "gref", "%u", &gref,
		"event-channel", "%u", &evtchn, NULL);
	if (err) {
		xenbus_dev_fatal(dev, err, "reading %s gref", dev->otherend);
		return err;
	}

	err = xenbus_printf(XBT_NIL, dev->nodename, "gref", "%u", gref);
	if (err) {
		xenbus_dev_fatal(dev, err, "%s", "writing gref");
		return err;
	}
	
	err = xenbus_printf(XBT_NIL, dev->nodename, "event-channel", "%u", evtchn);
	if (err) {
		xenbus_dev_fatal(dev, err, "%s", "writing event-channel");
		return err;
	}
	
	err = xenbus_map_ring_valloc(dev, &gref, 1, &addr);
	if (err)
		return err;
	
	page = vmalloc_to_page(addr);
	if(!page)
		return -EINVAL;

	phys_addr = page_to_phys(page);
	shared_page_pfn = phys_addr >> PAGE_SHIFT;
	// pr_info("backend_connect: PFN = %lu (0x%lx)", shared_page_pfn, shared_page_pfn);

	sring = (struct smepv_sring *)addr;
	BACK_RING_INIT(&info->ring, sring, XEN_PAGE_SIZE);
	
	shared_ring_buffer = (char *)info->ring.sring;
	err = bind_interdomain_evtchn_to_irq_lateeoi(dev, evtchn);
	if (err < 0) {
			pr_err("bind_interdomain_evtchn_to_irq_lateeoi failed: %d\n", err);
          	goto unmap_page;
	}
	
	info->irq = err;
	err = request_threaded_irq(info->irq, NULL, smeback_irq_fn,
								IRQF_ONESHOT, "smeback", info);
	if (err)
		goto free_irq;

	global_irq = info->irq;

	return 0;

free_irq:
	unbind_from_irqhandler(info->irq, info);
	info->irq = 0;
unmap_page:
	xenbus_unmap_ring_vfree(dev, addr);

	return err;
}

static void backend_disconnect(struct xensme_backend_info *info)
{
	unbind_from_irqhandler(info->irq, info);
	info->irq = 0;
	xenbus_unmap_ring_vfree(info->dev, info->ring.sring);
}

static void sme_frontend_changed(struct xenbus_device *dev,
				 enum xenbus_state frontend_state)
{
	struct xensme_backend_info *info;

	info = dev_get_drvdata(&dev->dev);
	if (!info) {
		pr_info("info is null in sme_frontend_changed");
	}

	switch (frontend_state) {
	case XenbusStateInitialising:
		break;

	case XenbusStateInitialised:
		backend_connect(info);
		xenbus_switch_state(dev, XenbusStateConnected);
		break;

	case XenbusStateConnected:
		if (info)
			global_irq = info->irq;
		if (dev->state == XenbusStateConnected)
			break;

		xenbus_switch_state(dev, XenbusStateConnected);
		break;

	case XenbusStateClosing:
		backend_disconnect(info);
		xenbus_switch_state(dev, XenbusStateClosing);
		break;

	case XenbusStateClosed:
		xenbus_switch_state(dev, XenbusStateClosed);
		if (xenbus_dev_is_online(dev))
			break;
		fallthrough;
	case XenbusStateUnknown:
		// xenbus_switch_state(dev, XenbusStateClosed);
		device_unregister(&dev->dev);
		break;

	default:
		xenbus_dev_fatal(dev, -EINVAL, "saw state %s (%d) at frontend",
							xenbus_strstate(frontend_state),
							frontend_state);
		break;
	}
}
static int xensme_backend_probe(struct xenbus_device *dev,
				const struct xenbus_device_id *id)
{
	struct xensme_backend_info *info;
	int err;

	printk(KERN_NOTICE "Backend probe called\n");

	info = kzalloc(sizeof(struct xensme_backend_info), GFP_KERNEL);

	if (!info) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating backend structure");
		return -ENOMEM;
	}
	pr_debug("%s %p %d\n", __func__, dev, dev->otherend_id);
	
	info->dev = dev;
	dev_set_drvdata(&dev->dev, info);
	info->frontend_domid = dev->otherend_id;

	pr_info("connecting with dom_id %d", dev->otherend_id); //debug
	err = xenbus_switch_state(dev, XenbusStateInitWait);
	if (err)
		goto fail;

	return 0;
fail:
	pr_warn("%s failed\n", __func__);
	return err;
}

static int xensme_backend_remove(struct xenbus_device *dev)
{
    struct xensme_backend_info *info = dev_get_drvdata(&dev->dev);

    if (info)
        kfree(info);

    printk(KERN_INFO "xensme_backend: Device removed\n");
    return 0;
}

static const struct xenbus_device_id xensme_backend_ids[] = { { "sme" },
							      { "" } };

static struct xenbus_driver xensme_backend_driver = {
	.ids = xensme_backend_ids,
	.probe = xensme_backend_probe,
	.remove = xensme_backend_remove,
	.otherend_changed = sme_frontend_changed,
};

static int __init xensme_backend_init(void)
{
	struct proc_dir_entry *sme_dir;
	if (!xen_domain())
		return -ENODEV;
    
    sme_dir = proc_mkdir("sme", NULL);
    if (!sme_dir)
        return -ENOMEM;

    if (!proc_create("sme_id", 0666, sme_dir, &sme_id_fops))
        return -ENOMEM;

    if (!proc_create("sme_text", 0666, sme_dir, &sme_text_fops))
        return -ENOMEM;

    if (!proc_create("xenmem_encrypt", 0666, sme_dir, &xenmem_encrypt_fops))
        return -ENOMEM;

    pr_info("Backend PV driver initialized\n");

    return xenbus_register_backend(&xensme_backend_driver);
}
module_init(xensme_backend_init);

static void __exit xensme_backend_exit(void)
{
	remove_proc_entry("sme/sme_id", NULL);
	remove_proc_entry("sme/sme_text", NULL);
	remove_proc_entry("sme/xenmem_encrypt", NULL);
	remove_proc_entry("sme", NULL);

	pr_info("Backend PV driver exited\n");

	xenbus_unregister_driver(&xensme_backend_driver);
}
module_exit(xensme_backend_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Backend PV Driver for SME demo");
