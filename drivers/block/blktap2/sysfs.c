#include <linux/types.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

#include "blktap.h"

int blktap_debug_level = 1;

static struct class *class = NULL;

static ssize_t
blktap_sysfs_set_name(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
	struct blktap *tap;

	tap = dev_get_drvdata(dev);
	if (!tap)
		return 0;

	if (size >= BLKTAP_NAME_MAX)
		return -ENAMETOOLONG;

	if (strnlen(buf, size) != size)
		return -EINVAL;

	strcpy(tap->name, buf);

	return size;
}

static ssize_t
blktap_sysfs_get_name(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct blktap *tap;
	ssize_t size;

	tap = dev_get_drvdata(dev);
	if (!tap)
		return 0;

	if (tap->name[0])
		size = sprintf(buf, "%s\n", tap->name);
	else
		size = sprintf(buf, "%d\n", tap->minor);

	return size;
}
static DEVICE_ATTR(name, S_IRUGO|S_IWUSR,
		   blktap_sysfs_get_name, blktap_sysfs_set_name);

static ssize_t 
blktap_sysfs_debug_device(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct blktap *tap;
	char *s = buf, *end = buf + PAGE_SIZE;

	tap = dev_get_drvdata(dev);
	if (!tap)
		return 0;

	s += blktap_control_debug(tap, s, end - s);

	s += blktap_request_debug(tap, s, end - s);

	s += blktap_device_debug(tap, s, end - s);

	s += blktap_ring_debug(tap, s, end - s);

	return s - buf;
}
static DEVICE_ATTR(debug, S_IRUGO, blktap_sysfs_debug_device, NULL);

static ssize_t
blktap_sysfs_show_task(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct blktap *tap;
	ssize_t rv = 0;

	tap = dev_get_drvdata(dev);
	if (!tap)
		return 0;

	if (tap->ring.task)
		rv = sprintf(buf, "%d\n", tap->ring.task->pid);

	return rv;
}
static DEVICE_ATTR(task, S_IRUGO, blktap_sysfs_show_task, NULL);

static ssize_t
blktap_sysfs_show_pool(struct device *dev,
		       struct device_attribute *attr,
		       char *buf)
{
	struct blktap *tap = dev_get_drvdata(dev);
	return sprintf(buf, "%s\n", kobject_name(&tap->pool->kobj));
}

static ssize_t
blktap_sysfs_store_pool(struct device *dev,
			struct device_attribute *attr,
			const char *buf, size_t size)
{
	struct blktap *tap = dev_get_drvdata(dev);
	struct blktap_page_pool *pool, *tmp = tap->pool;

	if (tap->device.gd)
		return -EBUSY;

	pool = blktap_page_pool_get_by_name(buf);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	tap->pool = pool;
	blktap_page_pool_put(tmp);

	return size;
}
DEVICE_ATTR(pool, S_IRUSR|S_IWUSR,
	    blktap_sysfs_show_pool, blktap_sysfs_store_pool);

int
blktap_sysfs_create(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;
	struct device *dev;
	int err = 0;

	dev = device_create(class, NULL, ring->devno,
			    tap, "blktap/blktap%d", tap->minor);
	if (IS_ERR(dev))
		err = PTR_ERR(dev);
	if (!err)
		err = device_create_file(dev, &dev_attr_name);
	if (!err)
		err = device_create_file(dev, &dev_attr_debug);
	if (!err)
		err = device_create_file(dev, &dev_attr_task);
	if (!err)
		err = device_create_file(dev, &dev_attr_pool);
	if (!err)
		ring->dev = dev;
	else
		device_unregister(dev);

	return err;
}

void
blktap_sysfs_destroy(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;
	struct device *dev;

	dev = ring->dev;

	if (!dev)
		return;

	dev_set_drvdata(dev, NULL);
	device_unregister(dev);
	ring->dev = NULL;
}

static ssize_t
verbosity_show(struct class *class, struct class_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", blktap_debug_level);
}

static ssize_t
verbosity_store(struct class *class, struct class_attribute *attr,
		const char *buf, size_t size)
{
	int level;

	if (sscanf(buf, "%d", &level) == 1) {
		blktap_debug_level = level;
		return size;
	}

	return -EINVAL;
}
static CLASS_ATTR_RW(verbosity);

static ssize_t
devices_show(struct class *class, struct class_attribute *attr, char *buf)
{
	int i, ret;
	struct blktap *tap;

	mutex_lock(&blktap_lock);

	ret = 0;
	for (i = 0; i < blktap_max_minor; i++) {
		tap = blktaps[i];
		if (!tap)
			continue;

		if (!test_bit(BLKTAP_DEVICE, &tap->dev_inuse))
			continue;

		ret += sprintf(buf + ret, "%d %s\n", tap->minor, tap->name);
	}

	mutex_unlock(&blktap_lock);

	return ret;
}
static CLASS_ATTR_RO(devices);

void
blktap_sysfs_exit(void)
{
	if (class)
		class_destroy(class);
}

int __init
blktap_sysfs_init(void)
{
	struct class *cls;
	int err = 0;

	cls = class_create(THIS_MODULE, "blktap2");
	if (IS_ERR(cls))
		err = PTR_ERR(cls);
	if (!err)
		err = class_create_file(cls, &class_attr_verbosity);
	if (!err)
		err = class_create_file(cls, &class_attr_devices);
	if (!err)
		class = cls;
	else
		class_destroy(cls);

	return err;
}
