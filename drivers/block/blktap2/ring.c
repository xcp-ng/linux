
#include <linux/device.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/blkdev.h>
#include <linux/module.h>

#include "blktap.h"

int blktap_ring_major;
static struct cdev blktap_ring_cdev;

 /* 
  * BLKTAP - immediately before the mmap area,
  * we have a bunch of pages reserved for shared memory rings.
  */
#define RING_PAGES 1

static void
blktap_ring_read_response(struct blktap *tap,
			  const blktap_ring_rsp_t *rsp)
{
	struct blktap_ring *ring = &tap->ring;
	struct blktap_request *request;
	int usr_idx;
	blk_status_t status;

	request = NULL;

	usr_idx = rsp->id;
	if (usr_idx < 0 || usr_idx >= BLKTAP_RING_SIZE) {
		status = BLK_STS_IOERR;
		goto invalid;
	}

	request = ring->pending[usr_idx];

	if (!request) {
		status = BLK_STS_IOERR;
		goto invalid;
	}

	if (rsp->operation != request->operation) {
		status = BLK_STS_IOERR;
		goto invalid;
	}

	dev_dbg(ring->dev,
		"request %d [%p] response: %d\n",
		request->usr_idx, request, rsp->status);

	status = rsp->status == BLKTAP_RSP_OKAY ? BLK_STS_OK : BLK_STS_IOERR;
end_request:
	blktap_device_end_request(tap, request, status);
	return;

invalid:
	dev_warn(ring->dev,
		 "invalid response, idx:%d status:%d op:%d/%d: status %u\n",
		 usr_idx, rsp->status,
		 rsp->operation, request->operation,
		 status);
	if (request)
		goto end_request;
}

static void
blktap_read_ring(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;
	blktap_ring_rsp_t rsp;
	RING_IDX rc, rp;

	/* for each outstanding message on the ring  */
	rp = ring->ring.sring->rsp_prod;
	rmb();

	for (rc = ring->ring.rsp_cons; rc != rp; rc++) {
		memcpy(&rsp, RING_GET_RESPONSE(&ring->ring, rc), sizeof(rsp));
		blktap_ring_read_response(tap, &rsp);
	}

	ring->ring.rsp_cons = rc;
}

#define MMAP_VADDR(_start, _req, _seg)				\
	((_start) +						\
	 ((_req) * BLKTAP_SEGMENT_MAX * BLKTAP_PAGE_SIZE) +	\
	 ((_seg) * BLKTAP_PAGE_SIZE))

static int blktap_ring_fault(struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}

static void
blktap_ring_fail_pending(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;
	struct blktap_request *request;
	int usr_idx;

	for (usr_idx = 0; usr_idx < BLKTAP_RING_SIZE; usr_idx++) {
		request = ring->pending[usr_idx];
		if (!request)
			continue;

		blktap_device_end_request(tap, request, BLK_STS_IOERR);
	}
}

static void
blktap_ring_vm_close(struct vm_area_struct *vma)
{
	struct blktap *tap = vma->vm_private_data;
	struct blktap_ring *ring = &tap->ring;
	struct page *page = virt_to_page(ring->ring.sring);

	blktap_ring_fail_pending(tap);

	zap_page_range(vma, vma->vm_start, PAGE_SIZE);
	ClearPageReserved(page);
	__free_page(page);

	ring->vma = NULL;

	if (test_bit(BLKTAP_SHUTDOWN_REQUESTED, &tap->dev_inuse))
		blktap_control_destroy_tap(tap);
}

static struct vm_operations_struct blktap_ring_vm_operations = {
	.close    = blktap_ring_vm_close,
	.fault    = blktap_ring_fault,
};

int
blktap_ring_map_segment(struct blktap *tap,
			struct blktap_request *request,
			int seg)
{
	struct blktap_ring *ring = &tap->ring;
	unsigned long uaddr;

	uaddr = MMAP_VADDR(ring->user_vstart, request->usr_idx, seg);
	return vm_insert_page(ring->vma, uaddr, request->pages[seg]);
}

int
blktap_ring_map_request(struct blktap *tap,
			struct blktap_request *request)
{
	int seg, err = 0;
	int write;

	write = request->operation == BLKTAP_OP_WRITE;

	for (seg = 0; seg < request->nr_pages; seg++) {
		if (write)
			blktap_request_bounce(tap, request, seg, write);

		err = blktap_ring_map_segment(tap, request, seg);
		if (err)
			break;
	}

	if (err)
		blktap_ring_unmap_request(tap, request);

	return err;
}

void
blktap_ring_unmap_request(struct blktap *tap,
			  struct blktap_request *request)
{
	struct blktap_ring *ring = &tap->ring;
	unsigned long uaddr;
	unsigned size;
	int seg, read;

	uaddr = MMAP_VADDR(ring->user_vstart, request->usr_idx, 0);
	size  = request->nr_pages << PAGE_SHIFT;
	read  = request->operation == BLKTAP_OP_READ;

	if (read)
		for (seg = 0; seg < request->nr_pages; seg++)
			blktap_request_bounce(tap, request, seg, !read);

	zap_page_range(ring->vma, uaddr, size);
}

void
blktap_ring_free_request(struct blktap *tap,
			 struct blktap_request *request)
{
	struct blktap_ring *ring = &tap->ring;

	ring->pending[request->usr_idx] = NULL;
	ring->n_pending--;

	blktap_request_free(tap, request);
}

struct blktap_request*
blktap_ring_make_request(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;
	struct blktap_request *request;
	int usr_idx;

	if (RING_FULL(&ring->ring))
		return ERR_PTR(-ENOSPC);

	request = blktap_request_alloc(tap);
	if (!request)
		return ERR_PTR(-ENOMEM);

	for (usr_idx = 0; usr_idx < BLKTAP_RING_SIZE; usr_idx++)
		if (!ring->pending[usr_idx])
			break;

	BUG_ON(usr_idx >= BLKTAP_RING_SIZE);

	request->tap     = tap;
	request->usr_idx = usr_idx;

	ring->pending[usr_idx] = request;
	ring->n_pending++;

	return request;
}

void
blktap_ring_submit_request(struct blktap *tap,
			   struct blktap_request *request)
{
	struct blktap_ring *ring = &tap->ring;
	blktap_ring_req_t *breq;
	struct scatterlist *sg;
	int i, nsecs = 0;

	dev_dbg(ring->dev,
		"request %d [%p] submit\n", request->usr_idx, request);

	breq = RING_GET_REQUEST(&ring->ring, ring->ring.req_prod_pvt);

	breq->id            = request->usr_idx;
	breq->sector_number = blk_rq_pos(request->rq);
	breq->__pad         = 0;
	breq->operation     = request->operation;
	breq->nr_segments   = request->nr_pages;

	blktap_for_each_sg(sg, request, i) {
		struct blktap_segment *seg = &breq->seg[i];
		int first, count;

		count = sg->length >> 9;
		first = sg->offset >> 9;

		seg->first_sect = first;
		seg->last_sect  = first + count - 1;

		nsecs += count;
	}

	ring->ring.req_prod_pvt++;

	do_gettimeofday(&request->time);


	if (request->operation == BLKTAP_OP_WRITE) {
		tap->stats.st_wr_sect += nsecs;
		tap->stats.st_wr_req++;
	}

	if (request->operation == BLKTAP_OP_READ) {
		tap->stats.st_rd_sect += nsecs;
		tap->stats.st_rd_req++;
	}
}

static int
blktap_ring_open(struct inode *inode, struct file *filp)
{
	struct blktap *tap = NULL;
	int minor;

	minor = iminor(inode);

	if (minor < blktap_max_minor)
		tap = blktaps[minor];

	if (!tap)
		return -ENXIO;

	if (test_bit(BLKTAP_SHUTDOWN_REQUESTED, &tap->dev_inuse))
		return -ENXIO;

	if (tap->ring.task)
		return -EBUSY;

	filp->private_data = tap;
	tap->ring.task = current;

	return 0;
}

static int
blktap_ring_release(struct inode *inode, struct file *filp)
{
	struct blktap *tap = filp->private_data;

	blktap_device_destroy_sync(tap);

	tap->ring.task = NULL;

	if (test_bit(BLKTAP_SHUTDOWN_REQUESTED, &tap->dev_inuse))
		blktap_control_destroy_tap(tap);

	return 0;
}

static int
blktap_ring_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct blktap *tap = filp->private_data;
	struct blktap_ring *ring = &tap->ring;
	struct blktap_sring *sring;
	struct page *page = NULL;
	int err;

	if (ring->vma)
		return -EBUSY;

	page = alloc_page(GFP_KERNEL|__GFP_ZERO);
	if (!page)
		return -ENOMEM;

	SetPageReserved(page);

	err = vm_insert_page(vma, vma->vm_start, page);
	if (err)
		goto fail;

	sring = page_address(page);
	SHARED_RING_INIT(sring);
	FRONT_RING_INIT(&ring->ring, sring, PAGE_SIZE);

	ring->ring_vstart = vma->vm_start;
	ring->user_vstart = ring->ring_vstart + PAGE_SIZE;

	vma->vm_private_data = tap;

	vma->vm_flags |= VM_DONTCOPY | VM_DONTEXPAND | VM_DONTDUMP;

	vma->vm_ops = &blktap_ring_vm_operations;

	ring->vma = vma;
	return 0;

fail:
	if (page) {
		zap_page_range(vma, vma->vm_start, PAGE_SIZE);
		ClearPageReserved(page);
		__free_page(page);
	}

	return err;
}

static bool
blktap_ring_vma_valid(struct blktap_ring *ring)
{
	/* Current process has mapped this ring? */
	return ring->vma && ring->vma->vm_mm == current->mm;
}

static long
__blktap_ring_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct blktap *tap = filp->private_data;
	struct blktap_ring *ring = &tap->ring;
	void __user *ptr = (void *)arg;
	int err;

	BTDBG("%d: cmd: %u, arg: %lu\n", tap->minor, cmd, arg);

	if (!blktap_ring_vma_valid(ring))
		return -EACCES;

	switch(cmd) {
	case BLKTAP_IOCTL_RESPOND:

		blktap_read_ring(tap);
		return 0;

	case BLKTAP_IOCTL_CREATE_DEVICE_COMPAT: {
		struct blktap_device_info info;
		struct blktap2_params params;

		if (copy_from_user(&params, ptr, sizeof(params)))
			return -EFAULT;

		info.capacity             = params.capacity;
		info.sector_size          = params.sector_size;
		info.physical_sector_size = params.sector_size;
		info.flags                = 0;

		err = blktap_device_create(tap, &info);
		if (err)
			return err;

		if (params.name[0])
			strlcpy(tap->name, params.name, sizeof(tap->name));

		return 0;
	}

	case BLKTAP_IOCTL_CREATE_DEVICE: {
		struct blktap_device_info info;

		if (copy_from_user(&info, ptr, sizeof(info)))
			return -EFAULT;

		return blktap_device_create(tap, &info);
	}

	case BLKTAP_IOCTL_REMOVE_DEVICE:

		return blktap_device_destroy(tap);
	}

	return -ENOIOCTLCMD;
}

static long
blktap_ring_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret;

	down_read(&current->mm->mmap_sem);
	ret = __blktap_ring_ioctl(filp, cmd, arg);
	up_read(&current->mm->mmap_sem);

	return ret;
}


static unsigned int blktap_ring_poll(struct file *filp, poll_table *wait)
{
	struct blktap *tap = filp->private_data;
	struct blktap_ring *ring = &tap->ring;
	int work;

	poll_wait(filp, &ring->poll_wait, wait);

	down_read(&current->mm->mmap_sem);
	if (blktap_ring_vma_valid(ring) && tap->device.gd)
		blktap_device_run_queue(tap);
	up_read(&current->mm->mmap_sem);

	work = ring->ring.req_prod_pvt - ring->ring.sring->req_prod;
	RING_PUSH_REQUESTS(&ring->ring);

	if (work ||
	    test_and_clear_bit(BLKTAP_DEVICE_CLOSED, &tap->dev_inuse))
		return POLLIN | POLLRDNORM;

	return 0;
}

static struct file_operations blktap_ring_file_operations = {
	.owner    = THIS_MODULE,
	.open     = blktap_ring_open,
	.release  = blktap_ring_release,
	.unlocked_ioctl = blktap_ring_ioctl,
	.mmap     = blktap_ring_mmap,
	.poll     = blktap_ring_poll,
};

void
blktap_ring_kick_user(struct blktap *tap)
{
	wake_up(&tap->ring.poll_wait);
}

int
blktap_ring_destroy(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;

	if (ring->task || ring->vma)
		return -EBUSY;

	return 0;
}

int
blktap_ring_create(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;

	init_waitqueue_head(&ring->poll_wait);
	ring->devno = MKDEV(blktap_ring_major, tap->minor);

	return 0;
}

size_t
blktap_ring_debug(struct blktap *tap, char *buf, size_t size)
{
	struct blktap_ring *ring = &tap->ring;
	char *s = buf, *end = buf + size;
	int usr_idx;

	s += snprintf(s, end - s,
		      "begin pending:%d\n", ring->n_pending);

	for (usr_idx = 0; usr_idx < BLKTAP_RING_SIZE; usr_idx++) {
		struct blktap_request *request;
		struct timeval *time;
		int write;

		request = ring->pending[usr_idx];
		if (!request)
			continue;

		write = request->operation == BLKTAP_OP_WRITE;
		time  = &request->time;

		s += snprintf(s, end - s,
			      "%02d: usr_idx:%02d "
			      "op:%c nr_pages:%02d time:%lu.%09lu\n",
			      usr_idx, request->usr_idx,
			      write ? 'W' : 'R', request->nr_pages,
			      time->tv_sec, time->tv_usec);
	}

	s += snprintf(s, end - s, "end pending\n");

	return s - buf;
}


int __init
blktap_ring_init(void)
{
	dev_t dev = 0;
	int err;

	cdev_init(&blktap_ring_cdev, &blktap_ring_file_operations);
	blktap_ring_cdev.owner = THIS_MODULE;

	err = alloc_chrdev_region(&dev, 0, MAX_BLKTAP_DEVICE, "blktap2");
	if (err < 0) {
		BTERR("error registering ring devices: %d\n", err);
		return err;
	}

	err = cdev_add(&blktap_ring_cdev, dev, MAX_BLKTAP_DEVICE);
	if (err) {
		BTERR("error adding ring device: %d\n", err);
		unregister_chrdev_region(dev, MAX_BLKTAP_DEVICE);
		return err;
	}

	blktap_ring_major = MAJOR(dev);
	BTINFO("blktap ring major: %d\n", blktap_ring_major);

	return 0;
}

void
blktap_ring_exit(void)
{
	if (!blktap_ring_major)
		return;

	cdev_del(&blktap_ring_cdev);
	unregister_chrdev_region(MKDEV(blktap_ring_major, 0),
				 MAX_BLKTAP_DEVICE);

	blktap_ring_major = 0;
}
