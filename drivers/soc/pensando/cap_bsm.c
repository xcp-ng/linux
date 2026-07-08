// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019-2021, Pensando Systems Inc.
 */

#include <linux/export.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/io.h>
#include "bsm_dev.h"
#include "cap_soc.h"

struct bsm {
	void __iomem *base;
	resource_size_t phys;
	uint32_t val;
	bool read_only;
};

#define BSM_MAX_INSTANCES 4
static struct bsm bsm_instances[BSM_MAX_INSTANCES];
static int bsm_count;

#define BSM_SHOW_INT(n, s) \
	static ssize_t n##_show(struct device *dev,			\
			struct device_attribute *attr, char *buf)	\
	{								\
		struct bsm *b = dev_get_drvdata(dev);			\
		int val = (b->val >> BSM_##s##_LSB) & BSM_##s##_MASK;	\
		return sprintf(buf, "%d\n", val);			\
	}								\
	static DEVICE_ATTR_RO(n)

BSM_SHOW_INT(wdt,      WDT);
BSM_SHOW_INT(attempt,  ATTEMPT);
BSM_SHOW_INT(stage,    STAGE);
BSM_SHOW_INT(running,  RUNNING);
BSM_SHOW_INT(autoboot, AUTOBOOT);

static const char *fwnames[4] = {
	"mainfwa", "mainfwb", "goldfw", "diagfw"
};

#define BSM_SHOW_FWID(n, s) \
	static ssize_t n##_show(struct device *dev,			\
			struct device_attribute *attr, char *buf)	\
	{								\
		struct bsm *b = dev_get_drvdata(dev);			\
		int val = (b->val >> BSM_##s##_LSB) & BSM_##s##_MASK;	\
		return sprintf(buf, "%s\n", fwnames[val & 0x3]);	\
	}								\
	static DEVICE_ATTR_RO(n)

BSM_SHOW_FWID(fwid,  FWID);
BSM_SHOW_FWID(track, TRACK);

static ssize_t success_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct bsm *b = dev_get_drvdata(dev);
	long val;

	if (b->read_only)
		return -EPERM;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;
	if (val) {
		b->val &= ~(1 << BSM_RUNNING_LSB);
		writel(b->val, b->base);
	}

	return count;
}
static DEVICE_ATTR_WO(success);

static const struct device_attribute *bsm_attrs[] = {
	&dev_attr_wdt,
	&dev_attr_fwid,
	&dev_attr_attempt,
	&dev_attr_track,
	&dev_attr_stage,
	&dev_attr_running,
	&dev_attr_autoboot,
	&dev_attr_success,
};

static const struct of_device_id bsm_of_match[] = {
	{ .compatible = "pensando,bsm" },
	{ }
};

static int bsm_probe(struct platform_device *pdev)
{
	struct kobject *pensando_kobj;
	struct resource *res;
	struct bsm *b = NULL;
	const char *symlink_name;
	int i, r = 0;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -ENODEV;

	/* Find the pre-mapped instance from early init by physical address */
	for (i = 0; i < bsm_count; i++) {
		if (bsm_instances[i].phys == res->start) {
			b = &bsm_instances[i];
			break;
		}
	}
	if (!b) {
		pr_err("bsm: no early-init data for %pa\n", &res->start);
		return -ENODEV;
	}

	platform_set_drvdata(pdev, b);

	pensando_kobj = pensando_fw_kobj_get();
	if (!pensando_kobj)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(bsm_attrs); i++) {
		r = device_create_file(&pdev->dev, bsm_attrs[i]);
		if (r) {
			pr_err("failed to create sysfs file\n");
			return r;
		}
	}

	symlink_name = pdev->dev.of_node ? pdev->dev.of_node->name : dev_name(&pdev->dev);
	r = sysfs_create_link(pensando_kobj, &pdev->dev.kobj, symlink_name);
	if (r) {
		pr_err("failed to create sysfs symlink\n");
		kobject_put(pensando_kobj);
		return r;
	}
	return 0;
}

static struct platform_driver bsm_driver = {
	.driver = {
		.name = "elba-bsm",
		.of_match_table = bsm_of_match,
		.suppress_bind_attrs = true,
	},
	.probe = bsm_probe,
};
builtin_platform_driver(bsm_driver);

/*
 * Boot State Machine init.
 * Find all BSM nodes in device tree, map their registers, and if
 * auto-booting set the BSM_RUNNING bit to continue BSM protection.
 * The bit will be cleared when userland comes up.
 */
static int __init cap_bsm_init(void)
{
	const struct of_device_id *match;
	struct device_node *np = NULL;
	struct resource res;

	while ((np = of_find_matching_node_and_match(np, bsm_of_match, &match))) {
		struct bsm *b;

		if (bsm_count >= BSM_MAX_INSTANCES) {
			pr_warn("bsm: too many BSM instances, skipping %s\n", np->name);
			of_node_put(np);
			break;
		}

		if (of_address_to_resource(np, 0, &res) < 0) {
			pr_err("bsm: failed to get registers for %s\n", np->name);
			continue;
		}

		b = &bsm_instances[bsm_count];
		b->phys = res.start;
		b->read_only = of_property_read_bool(np, "read-only");
		b->base = ioremap(res.start, resource_size(&res));
		if (!b->base) {
			pr_err("bsm: failed to map register for %s\n", np->name);
			continue;
		}

		b->val = readl(b->base);
#ifdef CONFIG_PENSANDO_SOC_BSM_ENABLE
		if (!b->read_only && (b->val & (1 << BSM_AUTOBOOT_LSB))) {
			b->val |= 1 << BSM_RUNNING_LSB;
			writel(b->val, b->base);
		}
#endif
		bsm_count++;
	}

	return 0;
}
early_initcall(cap_bsm_init);
