// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kexec.h>
#include <linux/pci.h>
#include <linux/device.h>

/*
 * A private copy of the public Xen headers to be independent of the rest of
 * the kernel. This file must not include any headers that include the
 * kernel's customized Xen headers (include/xen/interface).
 */

/* Pretend to be Xen tools to get access to domctls and sysctls. */
#define __XEN_TOOLS__

#include "public-xen/xen.h"
#include "public-xen/domctl.h"
#include "public-xen/kexec.h"
#include "public-xen/sysctl.h"
#include "public-xen/pv-iommu.h"
#include "public-xen/memory.h"
#include "public-xen/platform.h"
#include "public-xen/sched.h"
#include "public-xen/version.h"
#include "public-xen/xsm/flask_op.h"
#include "public-xen/hvm/hvm_op.h"

#include "filter-hypercall.h"

/*
 * This is used for filtering hypercalls originating from userspace.
 * It needs to be done in the kernel since Xen cannot differentiate between
 * calls originating in userspace and calls originating from the kernel.
 *
 * In general, all pointers need to be checked to make sure they point at
 * a valid userspace address.
 * Any memory containing a pointer needs to be bounced into kernel memory to
 * avoid userspace changing the pointer address after it has been checked.
 * After the hypercall, any memory that has been bounced needs to be copied
 * back into the original location.
 *
 * This should only be used to protect against specific userspace attacks.
 * Other security/safety checks should be done in Xen instead.
 */

#define MAX_BOUNCE_LEN (32 * 1024)
#define MAX_BOUNCE_LEN_IOMMU (256 * 1024)
#define MAX_PTR_CHECK_LEN (128 * 1024 * 1024)

static int __pre_hypercall(struct filtercall *fc, struct multicall_entry *mc,
			   unsigned int level);
static int __post_hypercall(struct filtercall *fc, struct multicall_entry *mc,
			    struct multicall_entry *mc_orig);

/*
 * Bounce a buffer from userspace.
 * Returns 0 on success or -errno on error.
 * On success, "to" is a valid kernel buffer.
 * It should be freed with kvfree().
 */
static int bounce_size(void *from, void **to, size_t size, size_t max_size)
{
	void *buf;

	if (size > max_size)
		return -ENOMEM;

	buf = kvmalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, from, size)) {
		kvfree(buf);
		return -EFAULT;
	}

	*to = buf;

	return 0;
}

static int bounce(void *from, void **to, size_t size)
{
	return bounce_size(from, to, size, MAX_BOUNCE_LEN);
}

/*
 * Returns true if the given address range is non-NULL and does not point at
 * valid memory for the current process.
 */
static bool ptr_bad(const void *p, size_t n, size_t size)
{
	/*
	 * Guest handles are often NULL.
	 * We just pass these through and let Xen handle them properly.
	 */
	if (!p)
		return false;

	if (!n || !size)
		return false;

	if (n > MAX_PTR_CHECK_LEN / size)
		return true;

	return !access_ok(p, n * size);
}

static int pre_xen_version(int cmd, void *uptr, void **kptr)
{
	size_t size = 0;

	switch (cmd) {
	case XENVER_version:
	case XENVER_pagesize:
		break;
	case XENVER_extraversion:
		size = sizeof(xen_extraversion_t);
		break;
	case XENVER_compile_info:
		size = sizeof(xen_compile_info_t);
		break;
	case XENVER_capabilities:
		size = sizeof(xen_capabilities_info_t);
		break;
	case XENVER_changeset:
		size = sizeof(xen_changeset_info_t);
		break;
	case XENVER_platform_parameters:
		size = sizeof(xen_platform_parameters_t);
		break;
	case XENVER_get_features:
		size = sizeof(xen_feature_info_t);
		break;
	case XENVER_guest_handle:
		size = sizeof(xen_domain_handle_t);
		break;
	case XENVER_commandline:
		size = sizeof(xen_commandline_t);
		break;
	case XENVER_build_id:
	case XENVER_extraversion2:
	case XENVER_capabilities2:
	case XENVER_changeset2:
	case XENVER_commandline2:
	{
		if (uptr) {
			uint32_t len;
			int ret;

			if (copy_from_user(&len, uptr, sizeof(len)))
				return -EFAULT;

			ret = bounce(uptr, kptr, sizeof(xen_build_id_t) + len);
			if (ret)
				return ret;

			if (len != ((xen_varbuf_t *)*kptr)->len) {
				kvfree(*kptr);
				*kptr = NULL;
				return -EPERM;
			}

			return 0;
		}
		break;
	}
	default:
		pr_warn("filter-hypercall: Unimplemented xen_version op: %u\n",
			cmd);
		/* Unknown xenver return -ENOSYS in Xen. */
		return -ENOSYS;
	}

	return !ptr_bad(uptr, 1, size) ? 0 : -EFAULT;
}

static int post_xen_version(unsigned long cmd, void *uptr, void *kptr)
{
	size_t size;
	int ret = 0;

	if (!kptr)
		return 0;

	switch (cmd) {
	case XENVER_build_id:
	case XENVER_extraversion2:
	case XENVER_capabilities2:
	case XENVER_changeset2:
	case XENVER_commandline2:
		break;
	default:
		return 0;
	}

	size = sizeof(xen_varbuf_t) + ((xen_varbuf_t *)kptr)->len;
	if (copy_to_user(uptr, kptr, size))
		ret = -EFAULT;

	kvfree(kptr);

	return ret;
}

#define MEMOP_EXTENT_SHIFT 6 /* cmd[:6] == start_extent */
#define MEMOP_CMD_MASK     ((1 << MEMOP_EXTENT_SHIFT) - 1)

struct __packed e820entry {
	uint64_t addr;
	uint64_t size;
	uint32_t type;
};

ssize_t memory_op_size(int op)
{
	switch (op) {
	case XENMEM_maximum_ram_page:
	case XENMEM_get_sharing_freed_pages:
	case XENMEM_get_sharing_shared_pages:
		return 0;
	case XENMEM_current_reservation:
	case XENMEM_maximum_reservation:
	case XENMEM_maximum_gpfn:
		return sizeof(struct xen_memory_domain);
	case XENMEM_populate_physmap:
	case XENMEM_increase_reservation:
	case XENMEM_decrease_reservation:
	case XENMEM_claim_pages:
		return sizeof(xen_memory_reservation_t);
	case XENMEM_memory_map:
	case XENMEM_machine_memory_map:
		return sizeof(xen_memory_map_t);
	case XENMEM_set_memory_map:
		return sizeof(xen_foreign_memory_map_t);
	case XENMEM_set_pod_target:
	case XENMEM_get_pod_target:
		return sizeof(xen_pod_target_t);
	case XENMEM_reserved_device_memory_map:
		return sizeof(xen_reserved_device_memory_map_t);
	case XENMEM_add_to_physmap:
		return sizeof(xen_add_to_physmap_t);
	}

	return -1;
}

static int pre_memory_op(unsigned long cmd, void *uptr, void **kptr)
{
	ssize_t size;
	int ret, op;

	*kptr = NULL;

	op = cmd & MEMOP_CMD_MASK;

	size = memory_op_size(op);
	if (unlikely(size < 0)) {
		pr_warn("filter-hypercall: Unimplemented memory op: %d\n", op);
		/* Unknown xenmem return -ENOSYS in Xen. */
		return -ENOSYS;
	}
	if (size == 0)
		return 0;

	ret = bounce(uptr, kptr, size);
	if (ret)
		return ret;

	ret = -EFAULT;
	switch (op) {
	case XENMEM_populate_physmap:
	case XENMEM_increase_reservation:
	case XENMEM_decrease_reservation:
	case XENMEM_claim_pages:
	{
		xen_memory_reservation_t *reservation = *kptr;

		if (ptr_bad(reservation->extent_start.p,
			    reservation->nr_extents, sizeof(xen_pfn_t)))
			goto err;
		break;
	}
	case XENMEM_set_memory_map:
	{
		xen_foreign_memory_map_t *map = *kptr;

		if (ptr_bad(map->map.buffer.p,
			    map->map.nr_entries, sizeof(struct e820entry)))
			goto err;
		break;
	}
	case XENMEM_memory_map:
	case XENMEM_machine_memory_map:
	{
		xen_memory_map_t *map = *kptr;

		if (ptr_bad(map->buffer.p,
			    map->nr_entries, sizeof(struct e820entry)))
			goto err;
		break;
	}
	case XENMEM_reserved_device_memory_map:
	{
		xen_reserved_device_memory_map_t *map = *kptr;

		if (ptr_bad(map->buffer.p,
			    map->nr_entries, sizeof(xen_reserved_device_memory_t)))
			goto err;
		break;
	}
	}

	return 0;

err:
	kvfree(*kptr);
	return ret;
}

static int post_memory_op(unsigned long cmd, void *uptr, void *kptr)
{
	size_t size = 0;
	int op, ret = 0;


	op = cmd & MEMOP_CMD_MASK;

	size = memory_op_size(op);
	BUG_ON(size < 0);

	if (size == 0)
		return 0;

	if (copy_to_user(uptr, kptr, size))
		ret = -EFAULT;

	kvfree(kptr);

	return ret;
}

#ifdef CONFIG_SIGNED_PE_FILE_VERIFICATION
#define KEXEC_SEGMENT_SIZE_MAX (128 * 1024 * 1024)
#define KERNEL_SEGMENT_IDX 0

static int pre_kexec_load(void *uptr, void **kptr)
{
	xen_kexec_load_t *data;
	xen_kexec_segment_t *segments = NULL, *usegs;
	unsigned int seg_idx;
	int rc;

	rc = bounce(uptr, kptr, sizeof(*data));
	if (rc)
		return rc;

	data = *kptr;

	if (data->nr_segments > KEXEC_SEGMENT_MAX) {
		rc = -EINVAL;
		goto out;
	}

	segments = kmalloc_array(data->nr_segments, sizeof(xen_kexec_segment_t),
				 GFP_KERNEL);
	if (!segments) {
		rc = -ENOMEM;
		goto out;
	}

	usegs = (xen_kexec_segment_t *)data->segments.h.p;
	for (seg_idx = 0; seg_idx < data->nr_segments; seg_idx++) {
		xen_kexec_segment_t kseg;
		void *ptr;

		if (copy_from_user(&kseg, &usegs[seg_idx], sizeof(kseg))) {
			rc = -EFAULT;
			goto out;
		}

		set_xen_guest_handle(segments[seg_idx].buf.h, kseg.buf.h.p);
		segments[seg_idx].buf_size = kseg.buf_size;
		segments[seg_idx].dest_maddr = kseg.dest_maddr;
		segments[seg_idx].dest_size = kseg.dest_size;

		if (kseg.buf_size > 0) {
			if (kseg.buf_size > KEXEC_SEGMENT_SIZE_MAX) {
				rc = -EINVAL;
				goto out;
			}

			ptr = kvmalloc(kseg.buf_size, GFP_KERNEL);
			if (!ptr) {
				rc = -ENOMEM;
				goto out;
			}
			set_xen_guest_handle(segments[seg_idx].buf.h, ptr);

			if (copy_from_user(ptr, kseg.buf.h.p, kseg.buf_size)) {
				rc = -EFAULT;
				kvfree(ptr);
				goto out;
			}
		}
	}

	rc = verify_pefile_signature(segments[KERNEL_SEGMENT_IDX].buf.h.p, segments[KERNEL_SEGMENT_IDX].buf_size,
				     VERIFY_USE_SECONDARY_KEYRING,
				     VERIFYING_KEXEC_PE_SIGNATURE);
	if (rc == -ENOKEY && IS_ENABLED(CONFIG_INTEGRITY_PLATFORM_KEYRING)) {
		rc = verify_pefile_signature(segments[KERNEL_SEGMENT_IDX].buf.h.p, segments[KERNEL_SEGMENT_IDX].buf_size,
					     VERIFY_USE_PLATFORM_KEYRING,
					     VERIFYING_KEXEC_PE_SIGNATURE);
	}
	if (rc)
		goto out;

	set_xen_guest_handle(data->segments.h, segments);
	return 0;

out:
	if (segments) {
		while (seg_idx--) {
			if (segments[seg_idx].buf.h.p && segments[seg_idx].buf_size > 0)
				kvfree(segments[seg_idx].buf.h.p);
		}
		kfree(segments);
	}

	kvfree(*kptr);
	*kptr = NULL;
	return rc;
}
#else
static int pre_kexec_load(void *uptr, void **kptr)
{
	return -EPERM;
}
#endif

static int pre_kexec_op(unsigned long op, void *uptr, void **kptr)
{
	size_t size = 0;

	switch (op) {
	case KEXEC_CMD_kexec:
		size = sizeof(xen_kexec_exec_t);
		break;
	case KEXEC_CMD_kexec_get_range:
		size = sizeof(xen_kexec_range_t);
		break;
	case KEXEC_CMD_kexec_unload:
		size = sizeof(xen_kexec_unload_t);
		break;
	case KEXEC_CMD_kexec_status:
		size = sizeof(xen_kexec_status_t);
		break;
	case KEXEC_CMD_kexec_load:
		return pre_kexec_load(uptr, kptr);
	default:
		pr_warn("filter-hypercall: Unimplemented kexec_op: %lu\n", op);
		/* Unknown kexec ops might return 0, adjust here for sanity */
		return -EOPNOTSUPP;
	}

	return !ptr_bad(uptr, 1, size) ? 0 : -EFAULT;
}

static int post_kexec_op(unsigned long op, void *uptr, void *kptr)
{
	xen_kexec_segment_t *segments;
	xen_kexec_load_t *data = kptr;

	if (op != KEXEC_CMD_kexec_load)
		return 0;

	if (data->nr_segments) {
		uint32_t i;

		segments = (xen_kexec_segment_t *)data->segments.h.p;
		for (i = 0; i < data->nr_segments; i++) {
			if (segments[i].buf.h.p && segments[i].buf_size > 0)
				kvfree(segments[i].buf.h.p);
		}
		kfree(segments);
	}
	kvfree(data);

	return 0;
}

static int pre_physdev_op(int cmd, void *uptr)
{
	size_t size = 0;

	switch (cmd) {
	case PHYSDEVOP_map_pirq:
		size = sizeof(physdev_map_pirq_t);
		break;
	case PHYSDEVOP_unmap_pirq:
		size = sizeof(physdev_unmap_pirq_t);
		break;
	default:
		pr_warn("filter-hypercall: Unimplemented physdev op: %d\n",
			cmd);
		/* Unknown physdev ops return -ENOSYS in Xen. */
		return -ENOSYS;
	}

	return !ptr_bad(uptr, 1, size) ? 0 : -EFAULT;
}

static int pre_hvm_op(unsigned long op, void *uptr)
{
	size_t size = 0;

	switch (op) {
		case HVMOP_set_param:
		case HVMOP_get_param:
			size = sizeof(xen_hvm_param_t);
			break;
		default:
			pr_warn("filter-hypercall: Unimplemented hvm op: %lu\n",
				op);
			/* Unknown hvm ops return -ENOSYS in Xen. */
			return -ENOSYS;
	}

	return !ptr_bad(uptr, 1, size) ? 0 : -EFAULT;
}

static int pre_iommu_op(void *uptr, unsigned int count, void **kptr,
			unsigned int level)
{
	int ret;
	unsigned int n;
	const struct pv_iommu_op *op;

	if (ptr_bad(uptr, count, sizeof(struct pv_iommu_op)))
		return -EFAULT;

	ret = bounce_size(uptr, kptr, sizeof(struct pv_iommu_op) * count,
			  level <= 1 ? MAX_BOUNCE_LEN_IOMMU: MAX_BOUNCE_LEN);
	if (ret)
		return ret;

	for (n = 0, op = *kptr; n < count; ++n, ++op) {
		switch (op->subop_id) {
		case IOMMUOP_lookup_foreign_page:
		case IOMMUOP_unmap_foreign_page:
			break;
		default:
			kvfree(*kptr);
			*kptr = NULL;
			/* Unknown iommu ops return -ENODEV in Xen. */
			return -ENODEV;
		}
	}
	return 0;
}

static int post_iommu_op(struct pv_iommu_op *ops, struct pv_iommu_op *orig_ops,
			 unsigned int count)
{
	int ret = 0;

	if (orig_ops) {
		size_t size = sizeof(*ops) * count;

		if (copy_to_user(orig_ops, ops, size))
			ret = -EFAULT;
	}
	kvfree(ops);
	return ret;
}

static int pre_sched_op(int cmd, void *uptr)
{
	size_t size = 0;

	switch (cmd) {
		case SCHEDOP_remote_shutdown:
			size = sizeof(sched_remote_shutdown_t);
			break;
		case SCHEDOP_watchdog:
			size = sizeof(sched_watchdog_t);
			break;
		default:
			pr_warn("filter-hypercall: Unimplemented sched_op: %d\n",
				cmd);
			/* Unknown sched ops return -ENOSYS in Xen. */
			return -ENOSYS;
	}

	return !ptr_bad(uptr, 1, size) ? 0 : -EFAULT;
}

static int pre_platform_op(void *uptr, void **kptr)
{
	struct xen_platform_op *op;
	int ret;

	*kptr = NULL;

	ret = bounce(uptr, kptr, sizeof(*op));
	if (ret)
		return ret;

	op = *kptr;

	ret = -EFAULT;
	switch (op->cmd) {
	case XENPF_get_cpu_version:
	case XENPF_get_ucode_revision:
		break;
	case XENPF_microcode_update:
		if (ptr_bad(op->u.microcode.data.p, op->u.microcode.length, 1))
			goto err;
		break;
	case XENPF_microcode_update2:
		if (ptr_bad(op->u.microcode2.data.p, op->u.microcode2.length, 1))
			goto err;
		break;
	case XENPF_resource_op:
		if (ptr_bad(op->u.resource_op.entries.p, op->u.resource_op.nr_entries,
                            sizeof(xenpf_resource_entry_t)))
			goto err;
		break;
	default:
		pr_warn("filter-hypercall: Unimplemented platform op: %u\n",
			op->cmd);
		/* Unknown platform ops return -ENOSYS in Xen. */
		ret = -ENOSYS;
		goto err;
	}

	return 0;

err:
	kvfree(*kptr);
	return ret;
}

static int post_platform_op(void *uptr, void *kptr)
{
	int ret = 0;

	if (copy_to_user(uptr, kptr, sizeof(struct xen_platform_op)))
		ret = -EFAULT;

	kvfree(kptr);

	return ret;
}

static int pre_domctl(void *uptr, void **kptr, unsigned int level)
{
	struct xen_domctl *op;
	int ret;

	ret = bounce(uptr, kptr, sizeof(*op));
	if (ret)
		return ret;

	op = *kptr;

	ret = -EFAULT;
	switch (op->cmd) {
	case XEN_DOMCTL_setdomainhandle:
	case XEN_DOMCTL_getdomaininfo:
	case XEN_DOMCTL_get_runstate_info:
	case XEN_DOMCTL_getvcpuinfo:
	case XEN_DOMCTL_destroydomain:
	case XEN_DOMCTL_pausedomain:
	case XEN_DOMCTL_max_mem:
	case XEN_DOMCTL_max_vcpus:
	case XEN_DOMCTL_settscinfo:
	case XEN_DOMCTL_gettscinfo:
	case XEN_DOMCTL_settimeoffset:
	case XEN_DOMCTL_unpausedomain:
	case XEN_DOMCTL_iomem_permission:
	case XEN_DOMCTL_memory_mapping:
	case XEN_DOMCTL_bind_pt_irq:
	case XEN_DOMCTL_unbind_pt_irq:
	case XEN_DOMCTL_ioport_permission:
	case XEN_DOMCTL_irq_permission:
	case XEN_DOMCTL_ioport_mapping:
	case XEN_DOMCTL_sendtrigger:
	case XEN_DOMCTL_set_paging_mempool_size:
	case XEN_DOMCTL_get_paging_mempool_size:
	case XEN_DOMCTL_soft_reset:
	case XEN_DOMCTL_pci_access:
	case XEN_DOMCTL_get_address_size:
		break;
	case XEN_DOMCTL_shadow_op:
		if (ptr_bad(op->u.shadow_op.dirty_bitmap.p,
			    (op->u.shadow_op.pages + 7) / 8, 1))
			goto err;
		break;
	case XEN_DOMCTL_setvcpuaffinity:
	case XEN_DOMCTL_getvcpuaffinity:
		if (ptr_bad(op->u.vcpuaffinity.cpumap_hard.bitmap.p, 1,
			    DIV_ROUND_UP(op->u.vcpuaffinity.cpumap_hard.nr_bits,
				         BITS_PER_BYTE)) ||
		    ptr_bad(op->u.vcpuaffinity.cpumap_soft.bitmap.p, 1,
			    DIV_ROUND_UP(op->u.vcpuaffinity.cpumap_soft.nr_bits,
				         BITS_PER_BYTE)))
			goto err;
		break;
	case XEN_DOMCTL_scheduler_op:
		if ((op->u.scheduler_op.cmd == XEN_DOMCTL_SCHEDOP_getvcpuinfo ||
		     op->u.scheduler_op.cmd == XEN_DOMCTL_SCHEDOP_putvcpuinfo) &&
		    ptr_bad(op->u.scheduler_op.u.v.vcpus.p,
			    op->u.scheduler_op.u.v.nr_vcpus,
			    sizeof(xen_domctl_schedparam_vcpu_t)))
			goto err;
		break;
	case XEN_DOMCTL_gethvmcontext:
	case XEN_DOMCTL_sethvmcontext:
		if (ptr_bad(op->u.hvmcontext.buffer.p, op->u.hvmcontext.size,
			    sizeof(uint8_t)))
			goto err;
		break;
	case XEN_DOMCTL_get_cpu_policy:
	case XEN_DOMCTL_set_cpu_policy:
		if (ptr_bad(op->u.cpu_policy.leaves.p, op->u.cpu_policy.nr_leaves,
			    sizeof(xen_cpuid_leaf_t)) ||
		    ptr_bad(op->u.cpu_policy.msrs.p, op->u.cpu_policy.nr_msrs,
			    sizeof(xen_msr_entry_t)))
			goto err;
		break;
	case XEN_DOMCTL_numa_op:
		switch (op->u.numa_op.op) {
		case XEN_DOMCTL_NUMA_OP_GET_NODE_PAGES:
			if (ptr_bad(op->u.numa_op.u.node_pages.node_tot_pages.p,
			            op->u.numa_op.u.node_pages.nr_nodes,
			            sizeof(uint64_t)))
				goto err;
			break;
		default: /* Unknown NUMA ops are not permitted */
			/* Unknown numa ops return -EOPNOTSUPP in Xen. */
			ret = -EOPNOTSUPP;
			goto err;
		}
		break;
	case XEN_DOMCTL_getpageframeinfo3:
		if (ptr_bad(op->u.getpageframeinfo3.array.p,
			    op->u.getpageframeinfo3.num, sizeof(xen_pfn_t)))
			goto err;
		break;
	case XEN_DOMCTL_assign_device:
	case XEN_DOMCTL_deassign_device:
	{
		struct pci_dev *pdev;
		uint32_t sbdf;

		if (unlikely(op->u.assign_device.dev != XEN_DOMCTL_DEV_PCI)) {
			pr_warn("filter-hypercall: Unimplemented DOMCTL_(de)assign_device dev: %u\n",
				op->u.assign_device.dev);
			/* Unknown device types return -ENODEV in Xen. */
			ret = -ENODEV;
			goto err;
		}

		/* reuse for keeping device */
		op->u.assign_device.u.dt.path.p = NULL;

		/*
		 * Avoid caller to cause dead locks using multicall, there's
		 * no much point in optimizing these calls.
		 */
		if (level > 1) {
			ret = -ELOOP;
			goto err;
		}

		sbdf = op->u.assign_device.u.pci.machine_sbdf;
		pdev = pci_get_domain_bus_and_slot(sbdf >> 16, PCI_BUS_NUM(sbdf), sbdf & 0xff);
		if (!pdev) {
			ret = -ENODEV;
			goto err;
		}
		if (op->cmd == XEN_DOMCTL_deassign_device) {
			ret = 0;
		} else if (pdev->unsafe) {
			ret = -EPERM;
		} else if (op->domain == DOMID_IO || op->domain == 0) {
			ret = 0;
		} else {
			ret = 0;
			pdev->unsafe = 1;
		}
		if (ret) {
			pci_dev_put(pdev);
			goto err;
		}
		device_lock(&pdev->dev);
		op->u.assign_device.u.dt.path.p = (void*) pdev;
		break;
	}
	case XEN_DOMCTL_setnodeaffinity:
	case XEN_DOMCTL_getnodeaffinity:
		if (ptr_bad(op->u.nodeaffinity.nodemap.bitmap.p, 1,
			    DIV_ROUND_UP(op->u.nodeaffinity.nodemap.nr_bits,
				         BITS_PER_BYTE)))
			goto err;
		break;
	case XEN_DOMCTL_createdomain:
		if (unlikely(op->u.createdomain.altp2m_opts != 0)) {
			pr_warn("filter-hypercall: Unexpected altp2m options: %u\n",
				op->u.createdomain.altp2m_opts);
			ret = -EPERM;
			goto err;
		}
		break;
	case XEN_DOMCTL_set_address_size:
	case XEN_DOMCTL_hypercall_init:
		if (op->domain == 0) {
			ret = -EPERM;
			goto err;
		}
		break;
	case XEN_DOMCTL_getvcpucontext:
	case XEN_DOMCTL_setvcpucontext:
		if (ptr_bad(op->u.vcpucontext.ctxt.p, 1,
			    sizeof(vcpu_guest_context_t)))
			goto err;
		break;
	case XEN_DOMCTL_set_llc_colors:
		if (ptr_bad(op->u.set_llc_colors.llc_colors.p,
			    op->u.set_llc_colors.num_llc_colors,
			    sizeof(uint32_t)))
			goto err;
		break;
	default:
		pr_warn("filter-hypercall: Unimplemented domctl op: %u\n",
			op->cmd);
		/* Unknown domctls return -ENOSYS in Xen. */
		ret = -ENOSYS;
		goto err;
	}

	return 0;

err:
	kvfree(*kptr);
	return ret;
}

static int post_domctl(void *uptr, void *kptr, int64_t rc)
{
	int ret = 0;
	struct xen_domctl *op = kptr;
	struct pci_dev *pdev;

	switch (op->cmd) {
	case XEN_DOMCTL_deassign_device:
	case XEN_DOMCTL_assign_device:
		pdev = (void *) op->u.assign_device.u.dt.path.p;
		/* avoids leaking pointers */
		op->u.assign_device.u.dt.path.p = NULL;
		if (!rc) {
			if (op->cmd == XEN_DOMCTL_deassign_device) {
				pdev->quarantined = 1;
			} else if (op->domain != DOMID_IO) {
				pdev->quarantined = 0;
			}
		}
		device_unlock(&pdev->dev);
		pci_dev_put(pdev);
		break;
	}

	if (copy_to_user(uptr, kptr, sizeof(struct xen_domctl)))
		ret = -EFAULT;

	kvfree(kptr);

	return ret;
}

static int pre_sysctl(void *uptr, void **kptr)
{
	struct xen_sysctl *op;
	int ret;

	ret = bounce(uptr, kptr, sizeof(*op));
	if (ret)
		return ret;

	op = *kptr;

	ret = -EFAULT;
	switch (op->cmd) {
	case XEN_SYSCTL_sched_id:
	case XEN_SYSCTL_physinfo:
	case XEN_SYSCTL_spec_ctrl:
	case XEN_SYSCTL_tbuf_op:
	case XEN_SYSCTL_cpu_hotplug:
		break;
	case XEN_SYSCTL_readconsole:
		if (ptr_bad(op->u.readconsole.buffer.p, op->u.readconsole.count, 1))
			goto err;
		break;
	case XEN_SYSCTL_getdomaininfolist:
		if (ptr_bad(op->u.getdomaininfolist.buffer.p,
			    op->u.getdomaininfolist.max_domains,
			    sizeof(xen_domctl_getdomaininfo_t)))
			goto err;
		break;
	case XEN_SYSCTL_getcpuinfo:
		if (ptr_bad(op->u.getcpuinfo.info.p, op->u.getcpuinfo.max_cpus,
			    sizeof(xen_sysctl_cpuinfo_t)))
			goto err;
		break;
	case XEN_SYSCTL_debug_keys:
		if (ptr_bad(op->u.debug_keys.keys.p, op->u.debug_keys.nr_keys,
			    sizeof(char)))
			goto err;
		break;
	case XEN_SYSCTL_pm_op:
		if (op->u.pm_op.cmd == GET_CPUFREQ_PARA &&
		    (ptr_bad(op->u.pm_op.u.get_para.affected_cpus.p,
			     op->u.pm_op.u.get_para.cpu_num,
			     sizeof(uint32_t)) ||
		     ptr_bad(op->u.pm_op.u.get_para.scaling_available_frequencies.p,
			     op->u.pm_op.u.get_para.freq_num,
			     sizeof(uint32_t)) ||
		     ptr_bad(op->u.pm_op.u.get_para.scaling_available_governors.p,
			     op->u.pm_op.u.get_para.gov_num, CPUFREQ_NAME_LEN)))
			goto err;
		break;
	case XEN_SYSCTL_get_pmstat:
		if (op->u.get_pmstat.type == PMSTAT_get_pxstat) {
			const uint8_t total = op->u.get_pmstat.u.getpx.total;
			if (ptr_bad(op->u.get_pmstat.u.getpx.pt.p,
				    total, sizeof(pm_px_val_t)) ||
			    ptr_bad(op->u.get_pmstat.u.getpx.trans_pt.p,
				    total * total, sizeof(uint64_t)))
				goto err;
		} else if (op->u.get_pmstat.type == PMSTAT_get_cxstat) {
			if (ptr_bad(op->u.get_pmstat.u.getcx.triggers.p,
				    op->u.get_pmstat.u.getcx.nr,
				    sizeof(uint64_t)) ||
			    ptr_bad(op->u.get_pmstat.u.getcx.residencies.p,
				    op->u.get_pmstat.u.getcx.nr,
				    sizeof(uint64_t)) ||
			    ptr_bad(op->u.get_pmstat.u.getcx.pc.p,
				    op->u.get_pmstat.u.getcx.nr_pc,
				    sizeof(uint64_t)) ||
			    ptr_bad(op->u.get_pmstat.u.getcx.cc.p,
				    op->u.get_pmstat.u.getcx.nr_cc,
				    sizeof(uint64_t)))
				goto err;
		}
		break;
	case XEN_SYSCTL_cpupool_op:
		if ((op->u.cpupool_op.op == XEN_SYSCTL_CPUPOOL_OP_INFO ||
		     op->u.cpupool_op.op == XEN_SYSCTL_CPUPOOL_OP_FREEINFO) &&
		    ptr_bad(op->u.cpupool_op.cpumap.bitmap.p, 1,
			    DIV_ROUND_UP(op->u.cpupool_op.cpumap.nr_bits, BITS_PER_BYTE)))
			goto err;
		break;
	case XEN_SYSCTL_numainfo:
		if (ptr_bad(op->u.numainfo.meminfo.p, op->u.numainfo.num_nodes,
			    sizeof(xen_sysctl_meminfo_t)) ||
		    ptr_bad(op->u.numainfo.distance.p,
			    op->u.numainfo.num_nodes * op->u.numainfo.num_nodes,
			    sizeof(uint32_t)))
			goto err;
		break;
	case XEN_SYSCTL_cputopoinfo:
		if (ptr_bad(op->u.cputopoinfo.cputopo.p,
			    op->u.cputopoinfo.num_cpus,
			    sizeof(xen_sysctl_cputopo_t)))
			goto err;
		break;
	case XEN_SYSCTL_get_cpu_featureset:
		if (ptr_bad(op->u.cpu_featureset.features.p,
			    op->u.cpu_featureset.nr_features,
			    sizeof(uint32_t)))
			goto err;
		break;
	case XEN_SYSCTL_get_cpu_policy:
		if (ptr_bad(op->u.cpu_policy.leaves.p,
			    op->u.cpu_policy.nr_leaves,
			    sizeof(xen_cpuid_leaf_t)) ||
		    ptr_bad(op->u.cpu_policy.msrs.p, op->u.cpu_policy.nr_msrs,
			    sizeof(xen_msr_entry_t)))
			goto err;
		break;
	case XEN_SYSCTL_livepatch_op:
		switch (op->u.livepatch.cmd) {
		case XEN_SYSCTL_LIVEPATCH_UPLOAD:
			if (ptr_bad(op->u.livepatch.u.upload.name.name.p,
				    op->u.livepatch.u.upload.name.size,
				    sizeof(char)) ||
			    ptr_bad(op->u.livepatch.u.upload.payload.p,
				    op->u.livepatch.u.upload.size,
				    sizeof(uint8_t)))
				goto err;
			break;
		case XEN_SYSCTL_LIVEPATCH_GET:
			if (ptr_bad(op->u.livepatch.u.get.name.name.p,
				    op->u.livepatch.u.get.name.size,
				    sizeof(char)))
				goto err;
			break;
		case XEN_SYSCTL_LIVEPATCH_ACTION:
			if (ptr_bad(op->u.livepatch.u.action.name.name.p,
				    op->u.livepatch.u.action.name.size,
				    sizeof(char)))
				goto err;
			break;
		case XEN_SYSCTL_LIVEPATCH_LIST:
			if (op->u.livepatch.u.list.nr) {
				if (ptr_bad(op->u.livepatch.u.list.status.p,
					    op->u.livepatch.u.list.nr,
					    sizeof(xen_livepatch_status_t)) ||
				    ptr_bad(op->u.livepatch.u.list.len.p,
					    op->u.livepatch.u.list.nr,
					    sizeof(uint32_t)) ||
				    ptr_bad(op->u.livepatch.u.list.metadata_len.p,
					    op->u.livepatch.u.list.nr,
					    sizeof(uint32_t)) ||
				    ptr_bad(op->u.livepatch.u.list.name.p,
					    op->u.livepatch.u.list.name_total_size,
					    sizeof(char)) ||
				    ptr_bad(op->u.livepatch.u.list.metadata.p,
					    op->u.livepatch.u.list.metadata_total_size,
					    sizeof(char)))
					goto err;
			}
			break;
		default:
			pr_warn("filter-hypercall: Unimplemented livepatch op: %u\n",
				op->u.livepatch.cmd);
			/* Unknown livepatch sysctls return -EOPNOTSUPP in Xen. */
			ret = -EOPNOTSUPP;
			goto err;
		}
		break;
	case XEN_SYSCTL_pcitopoinfo:
		if (ptr_bad(op->u.pcitopoinfo.devs.p, op->u.pcitopoinfo.num_devs,
			    sizeof(physdev_pci_device_t)) ||
		    ptr_bad(op->u.pcitopoinfo.nodes.p, op->u.pcitopoinfo.num_devs,
			    sizeof(uint32_t)))
			goto err;
		break;
	case XEN_SYSCTL_numa_meminfo:
		if (ptr_bad(op->u.numa_meminfo.meminfo.p,
		            op->u.numa_meminfo.num_nodes,
		            sizeof(xen_sysctl_node_meminfo_t)))
			goto err;
		break;
	default:
		pr_warn("filter-hypercall: Unimplemented sysctl op: %u\n", op->cmd);
		/* Unknown sysctls return -ENOSYS in Xen. */
		ret = -ENOSYS;
		goto err;
	}

	return 0;

err:
	kvfree(*kptr);
	return ret;
}

static int post_sysctl(void *uptr, void *kptr)
{
	int ret = 0;

	if (copy_to_user(uptr, kptr, sizeof(struct xen_sysctl)))
		ret = -EFAULT;

	kvfree(kptr);

	return ret;
}

static int pre_event_channel_op(int cmd, void *uptr)
{
	size_t size = 0;

	switch (cmd) {
		case EVTCHNOP_alloc_unbound:
			size = sizeof(struct evtchn_alloc_unbound);
			break;
		case EVTCHNOP_status:
			size = sizeof(struct evtchn_status);
			break;
		default:
			pr_warn("filter-hypercall: Unimplemented evtchn op: %u\n",
				cmd);
			/* Unknown event channel ops return -ENOSYS in Xen. */
			return -ENOSYS;
	}

	return !ptr_bad(uptr, 1, size) ? 0 : -EFAULT;
}

static int pre_mmuext_op(void *uptr, unsigned int count, unsigned int *pdone,
			 void **kptr)
{
	int ret;
	unsigned int n;
	const struct mmuext_op *op;

	if (ptr_bad(uptr, count, sizeof(struct mmuext_op))
	    || ptr_bad(pdone, count, sizeof(*pdone)))
		return -EFAULT;

	ret = bounce(uptr, kptr, sizeof(struct mmuext_op) * count);
	if (ret)
		return ret;

	for (n = 0, op = *kptr; n < count; ++n, ++op) {
		switch (op->cmd) {
		case MMUEXT_PIN_L1_TABLE:
		case MMUEXT_PIN_L2_TABLE:
		case MMUEXT_PIN_L3_TABLE:
		case MMUEXT_PIN_L4_TABLE:
			break;
		default:
			pr_warn("filter-hypercall: MMUext cmd: %u\n", op->cmd);
			kvfree(*kptr);
			*kptr = NULL;
			/* Unknown mmuext ops return -ENOSYS in Xen. */
			return -ENOSYS;
		}
	}
	return 0;
}

static int post_mmuext_op(struct mmuext_op *ops)
{
	kvfree(ops);
	return 0;
}

static int pre_multicall(struct filtercall *fc, void *uptr, uint32_t nr_calls,
			 void **kptr, unsigned int level)
{
	unsigned int i = 0;
	int ret;
	struct multicall_entry *mc;
	size_t size;

	/*
	 * Disallow recursive multicalls to avoid abuse (and Xen does too).
	 */
	if (level > 1)
		return -ELOOP;

	BUG_ON(!fc);

	/*
	 * nr_calls is limited to a sane number since the bounce buffer is
	 * limited to MAX_BOUNCE_LEN. No need to check it separately.
	 */
	size = sizeof(struct multicall_entry) * nr_calls;

	/*
	 * Copy the multicall array into kernel space. This will be modified to
	 * point at kernel buffers where necessary and then passed to Xen.
	 */
	ret = bounce(uptr, (void **)&mc, size);
	if (ret)
		return ret;

	/*
	 * Save a copy of the multicall array with userspace pointers,
	 * used for copying back relevant data to userspace.
	 */
	fc->umc_list = kmemdup(mc, size, GFP_KERNEL);
	if (!fc->umc_list) {
		ret = -ENOMEM;
		goto err;
	}

	for (; i < nr_calls; i++) {
		ret = __pre_hypercall(NULL, &mc[i], level);
		if (ret)
			goto err;
	}

	*kptr = mc;

	/*
	 * Save a copy of the multicall array since Xen modifies it but we need
	 * access to the kernel pointers to free them.
	 */
	fc->kmc_list = kmemdup(mc, size, GFP_KERNEL);
	if (fc->kmc_list)
		return 0;
	else
		ret = -ENOMEM;

err:
	/* unwind the for loop and cleanup */
	while (i--) {
		mc[i].result = -ENOMEM;
		__post_hypercall(NULL, &mc[i], &((struct multicall_entry *)uptr)[i]);
	}

	kvfree(mc);
	kvfree(fc->umc_list);

	return ret;
}

static int post_multicall(struct filtercall *fc,
			  struct multicall_entry *umc_list,
			  struct multicall_entry *mc_list, uint32_t nr_calls)
{
	int rc = 0, ret;
	int i;

	BUG_ON(!fc);

	for (i = 0; i < nr_calls; i++) {
		ret = __post_hypercall(NULL, &fc->kmc_list[i], &fc->umc_list[i]);
		if (ret)
			rc = ret;

		if (copy_to_user(&umc_list[i].result, &mc_list[i].result,
				 sizeof(umc_list[i].result)))
			rc = -EFAULT;
	}
	kvfree(mc_list);
	kvfree(fc->kmc_list);
	fc->kmc_list = NULL;
	kvfree(fc->umc_list);
	fc->umc_list = NULL;

	return rc;
}

static int __pre_hypercall(struct filtercall *fc, struct multicall_entry *mc,
			   unsigned int level)
{
	int ret;
	void *kptr = NULL;

	level++;

	switch (mc->op)
	{
		case __HYPERVISOR_xen_version:
			ret = pre_xen_version((int)mc->args[0],
					      (void *)mc->args[1],
					      &kptr);
			/* kptr is only set if we needed to bounce a buffer */
			if (kptr)
				mc->args[1] = (uint64_t)kptr;
			break;
		case __HYPERVISOR_event_channel_op:
			ret = pre_event_channel_op((int)mc->args[0],
						   (void *)mc->args[1]);
			break;
		case __HYPERVISOR_domctl:
			ret = pre_domctl((void *)mc->args[0], &kptr, level);
			mc->args[0] = (uint64_t)kptr;
			break;
		case __HYPERVISOR_sysctl:
			ret = pre_sysctl((void *)mc->args[0], &kptr);
			mc->args[0] = (uint64_t)kptr;
			break;
		case __HYPERVISOR_multicall:
			ret = pre_multicall(fc, (void *)mc->args[0],
					    mc->args[1], &kptr, level);
			mc->args[0] = (uint64_t)kptr;
			break;
		case __HYPERVISOR_memory_op:
			ret = pre_memory_op((unsigned long)mc->args[0],
					    (void *)mc->args[1], &kptr);
			mc->args[1] = (uint64_t)kptr;
			break;
		case __HYPERVISOR_hvm_op:
			ret = pre_hvm_op((unsigned long)mc->args[0],
					 (void *)mc->args[1]);
			break;
		case __HYPERVISOR_platform_op:
			ret = pre_platform_op((void *)mc->args[0], &kptr);
			mc->args[0] = (uint64_t)kptr;
			break;
		case __HYPERVISOR_physdev_op:
			ret = pre_physdev_op((int)mc->args[0],
					     (void *)mc->args[1]);
			break;
		case __HYPERVISOR_sched_op:
			ret = pre_sched_op((int)mc->args[0],
					   (void *)mc->args[1]);
			break;
		case __HYPERVISOR_iommu_op:
			ret = pre_iommu_op((void *)mc->args[0],
					   (unsigned int)mc->args[1], &kptr,
					   level);
			mc->args[0] = (uint64_t)kptr;
			break;
		case __HYPERVISOR_kexec_op:
			ret = pre_kexec_op((unsigned long)mc->args[0],
					   (void *)mc->args[1], &kptr);
			/* kptr is only set if we needed to bounce a buffer */
			if (kptr)
				mc->args[1] = (uint64_t)kptr;
			break;
		case __HYPERVISOR_mmuext_op:
			ret = pre_mmuext_op((void *)mc->args[0],
					    (unsigned int)mc->args[1],
					    (void *)mc->args[2], &kptr);
			mc->args[0] = (uint64_t)kptr;
			break;
		default:
			pr_warn("filter-hypercall: Unimplemented hypercall op: %lu\n",
				mc->op);
			/* Unknown hypercall. */
			return -ENOSYS;
	}

	return ret;
}

int pre_hypercall(struct filtercall *fc)
{
	return __pre_hypercall(fc, &fc->mc, 0);
}

static int __post_hypercall(struct filtercall *fc, struct multicall_entry *mc,
			    struct multicall_entry *mc_orig)
{
	void *uptr = NULL;
	int ret = 0;

	switch (mc->op)
	{
		case __HYPERVISOR_xen_version:
			uptr = (void *)mc_orig->args[1];
			ret = post_xen_version((unsigned long)mc->args[0],
					       uptr,
					       (void *)mc->args[1]);
			break;
		case __HYPERVISOR_domctl:
			uptr = (void *)mc_orig->args[0];
			ret = post_domctl(uptr, (void *)mc->args[0],
					  mc->result);
			break;
		case __HYPERVISOR_sysctl:
			uptr = (void *)mc_orig->args[0];
			ret = post_sysctl(uptr, (void *)mc->args[0]);
			break;
		case __HYPERVISOR_multicall:
			uptr = (void *)mc_orig->args[0];
			ret = post_multicall(fc, uptr,
					     (void *)mc->args[0], mc->args[1]);
			break;
		case __HYPERVISOR_memory_op:
			uptr = (void *)mc_orig->args[1];
			ret = post_memory_op((unsigned long)mc->args[0],
					     uptr,
					     (void *)mc->args[1]);
			break;
		case __HYPERVISOR_platform_op:
			uptr = (void *)mc_orig->args[0];
			ret = post_platform_op(uptr, (void *)mc->args[0]);
			break;
		case __HYPERVISOR_iommu_op:
			if (mc_orig)
				uptr = (void *)mc_orig->args[0];
			ret = post_iommu_op((void *)mc->args[0],
					    uptr,
					    (unsigned int)mc->args[1]);
			break;
		case __HYPERVISOR_kexec_op:
			uptr = (void *)mc_orig->args[1];
			ret = post_kexec_op((unsigned long)mc->args[0],
					    uptr,
					    (void *)mc->args[1]);
			break;
		case __HYPERVISOR_mmuext_op:
			ret = post_mmuext_op((void *)mc->args[0]);
			break;
	}

	return ret;
}

int post_hypercall(struct filtercall *fc)
{
	return __post_hypercall(fc, &fc->mc, &fc->mc_orig);
}
