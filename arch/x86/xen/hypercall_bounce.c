// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/irqflags.h>
#include <linux/types.h>

#include <asm/mem_encrypt.h>
#include <asm/page_types.h>
#include <asm/page.h>
#include <asm/set_memory.h>

#include <asm/xen/hypercall.h>

#include <xen/interface/xen.h>
#include <xen/interface/sched.h>
#include <xen/interface/xen-mca.h>
#include <xen/interface/hvm/hvm_op.h>
#include <xen/interface/vcpu.h>
#include <xen/interface/xenpmu.h>
#include <xen/interface/memory.h>
#include <xen/interface/grant_table.h>
#include <xen/interface/version.h>
#include <xen/interface/event_channel.h>

struct xen_hypercall_bounce_state {
  uint8_t *virt_base;
  phys_addr_t phys_base;
  size_t offset;
  unsigned long irq_flags; /* temporary irq flags during hypercall bounce logic */
};

DEFINE_PER_CPU(struct xen_hypercall_bounce_state, xen_bounce_states);
static uint8_t __meminitdata early_bounce_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

bool xen_physaddr_abi;

void __init xen_hypercall_bounce_init_early(void)
{
  /* Specific early initialization logic */
  struct xen_hypercall_bounce_state *state = this_cpu_ptr(&xen_bounce_states);

  state->phys_base = __pa(early_bounce_page);
  state->virt_base = early_memremap_decrypted(state->phys_base, PAGE_SIZE);
  state->irq_flags = 0;
  state->offset = 0;

  memset(state->virt_base, 0, PAGE_SIZE);
}

void __init xen_hypercall_bounce_teardown_early(void)
{
	struct xen_hypercall_bounce_state *state = this_cpu_ptr(&xen_bounce_states);

	early_memunmap(state->virt_base, PAGE_SIZE);
}

void xen_hypercall_bounce_init_smp(void)
{
  struct xen_hypercall_bounce_state *state = this_cpu_ptr(&xen_bounce_states);
  struct page *bounce_page = alloc_page(GFP_KERNEL);

  state->phys_base = page_to_phys(bounce_page);
  state->virt_base = page_to_virt(bounce_page);
  state->irq_flags = 0;
  state->offset = 0;
	
	set_memory_decrypted((unsigned long)state->virt_base, 1);
  memset(state->virt_base, 0, PAGE_SIZE);
}

static void xen_hypercall_bounce_begin(void)
{
  struct xen_hypercall_bounce_state *state = this_cpu_ptr(&xen_bounce_states);
  
  BUG_ON(!state->phys_base);
  BUG_ON(state->offset);
  local_irq_save(state->irq_flags);
}

static void xen_hypercall_bounce_end(void)
{
  struct xen_hypercall_bounce_state *state = this_cpu_ptr(&xen_bounce_states);
  
  state->offset = 0;
  local_irq_restore(state->irq_flags);
}

static phys_addr_t xen_hypercall_bounce_handle_prepare(void *buffer, size_t len)
{
  struct xen_hypercall_bounce_state *state = this_cpu_ptr(&xen_bounce_states);

  if ( state->offset + len >= PAGE_SIZE )
    return 0;

  void *hbuffer = state->virt_base + state->offset;
  phys_addr_t physaddr = state->phys_base + state->offset;

  memcpy(hbuffer, buffer, len);
  state->offset += len;

  return physaddr;
}

static void xen_hypercall_bounce_handle_writeback(void *buffer, phys_addr_t handle, size_t len)
{
  struct xen_hypercall_bounce_state *state = this_cpu_ptr(&xen_bounce_states);

  // Check bounds.
  BUG_ON(handle < state->phys_base);
  BUG_ON((handle + len) >= (state->phys_base + PAGE_SIZE));

  size_t handle_pos = handle - state->phys_base;
  void *hbuffer = state->virt_base + handle_pos;

  memcpy(buffer, hbuffer, len);
}

int xen_hypercall_bounce_sched_op(int cmd, void *arg)
{
	xen_hypercall_bounce_begin();
	size_t size = 0;
	phys_addr_t arg_handle = 0;

	switch (cmd) {
		case SCHEDOP_yield:
			break;
		case SCHEDOP_block:
			break;
		case SCHEDOP_shutdown:
			size = sizeof(struct sched_shutdown);
			break;
		case SCHEDOP_watchdog:
			size = sizeof(struct sched_watchdog);
			break;
		
		default:
			printk("Unhandled sched_op %u\n", cmd);
			BUG();
	}
	
	if (size)
		arg_handle = xen_hypercall_bounce_handle_prepare(arg, size);
	int ret = _hypercall2(int, sched_op | 0x40000000, cmd, arg_handle);
	xen_hypercall_bounce_end();
	return ret;
}

int xen_hypercall_bounce_mca(struct xen_mc *mc_op)
{
	mc_op->interface_version = XEN_MCA_INTERFACE_VERSION;
	return _hypercall1(int, mca | 0x40000000, mc_op);
}

int xen_hypercall_bounce_platform_op(struct xen_platform_op *op)
{
	op->interface_version = XENPF_INTERFACE_VERSION;

	xen_hypercall_bounce_begin();
	phys_addr_t op_handle = xen_hypercall_bounce_handle_prepare(op, sizeof(struct xen_platform_op));
	int ret = _hypercall1(int, platform_op | 0x40000000, op_handle);
	xen_hypercall_bounce_handle_writeback(op, op_handle, sizeof(struct xen_platform_op));
	xen_hypercall_bounce_end();

	return ret;
}

long xen_hypercall_bounce_memory_op(unsigned int cmd, void *arg)
{
	xen_hypercall_bounce_begin();
	size_t size = 0, subarg_size = 0;
	void *subarg_buffer = NULL;
	phys_addr_t subarg_handle = 0;

	switch (cmd) {
		case XENMEM_increase_reservation:
		case XENMEM_decrease_reservation:
		case XENMEM_populate_physmap:
		{
			size = sizeof(struct xen_memory_reservation);
			struct xen_memory_reservation *reservation = arg;
			subarg_buffer = reservation->extent_start;
			subarg_size = sizeof(xen_pfn_t) * reservation->nr_extents;
			subarg_handle = xen_hypercall_bounce_handle_prepare(subarg_buffer, subarg_size);
			reservation->extent_start = (void *)(unsigned long)subarg_handle;
			break;
		}

		case XENMEM_add_to_physmap:
			size = sizeof(struct xen_add_to_physmap);
			break;
		
		default:
			printk("Unhandled memory_op %u\n", cmd);
			BUG();
	}
	
	phys_addr_t arg_handle = xen_hypercall_bounce_handle_prepare(arg, size);
	long ret = _hypercall2(long, memory_op | 0x40000000, cmd, arg_handle);
	xen_hypercall_bounce_handle_writeback(arg, arg_handle, size);

	if (subarg_handle)
		xen_hypercall_bounce_handle_writeback(subarg_buffer, subarg_handle, subarg_size);

	xen_hypercall_bounce_end();

	return ret;
}

int xen_hypercall_bounce_multicall(void *call_list, uint32_t nr_calls)
{
	return _hypercall2(int, multicall | 0x40000000, call_list, nr_calls);
}

int xen_hypercall_bounce_event_channel_op(int cmd, void *arg)
{
	xen_hypercall_bounce_begin();
	size_t size = 0;
	phys_addr_t arg_handle = 0;

	switch (cmd) {
			case EVTCHNOP_bind_interdomain:
				size = sizeof(struct evtchn_bind_interdomain);
				break;
			case EVTCHNOP_bind_virq:
				size = sizeof(struct evtchn_bind_virq);
				break;
			case EVTCHNOP_bind_pirq:
				size = sizeof(struct evtchn_bind_pirq);
				break;
			case EVTCHNOP_bind_ipi:
				size = sizeof(struct evtchn_bind_ipi);
				break;
			case EVTCHNOP_close:
				size = sizeof(struct evtchn_close);
				break;
			case EVTCHNOP_send:
				size = sizeof(struct evtchn_send);
				break;
			case EVTCHNOP_status:
				size = sizeof(struct evtchn_status);
				break;
			case EVTCHNOP_alloc_unbound:
				size = sizeof(struct evtchn_alloc_unbound);
				break;
			case EVTCHNOP_bind_vcpu:
				size = sizeof(struct evtchn_bind_vcpu);
				break;
			case EVTCHNOP_unmask:
				size = sizeof(struct evtchn_unmask);
				break;
			case EVTCHNOP_reset:
				size = sizeof(struct evtchn_reset);
				break;
			case EVTCHNOP_init_control:
				size = sizeof(struct evtchn_init_control);
				break;
			case EVTCHNOP_expand_array:
				size = sizeof(struct evtchn_expand_array);
				break;
			case EVTCHNOP_set_priority:
				size = sizeof(struct evtchn_set_priority);
				break;
			default:
				BUG();
	}

	if (size)
		arg_handle = xen_hypercall_bounce_handle_prepare(arg, size);
	int ret = _hypercall2(int, event_channel_op | 0x40000000, cmd, arg_handle);
	if (size)
		xen_hypercall_bounce_handle_writeback(arg, arg_handle, size);
	xen_hypercall_bounce_end();

	return ret;
}

int xen_hypercall_bounce_xen_version(int cmd, void *arg)
{
	xen_hypercall_bounce_begin();
	size_t size = 0;
	phys_addr_t arg_handle = 0;

	switch (cmd) {
		case XENVER_extraversion:
			size = XEN_EXTRAVERSION_LEN;
			break;
		case XENVER_compile_info:
			size = sizeof(struct xen_compile_info);
			break;
		case XENVER_capabilities:
			size = XEN_CAPABILITIES_INFO_LEN;
			break;
		case XENVER_changeset:
			size = XEN_CHANGESET_INFO_LEN;
			break;
		case XENVER_platform_parameters:
			size = sizeof(struct xen_platform_parameters);
			break;
		case XENVER_get_features:
			size = sizeof(struct xen_feature_info);
			break;
		case XENVER_commandline:
			size = sizeof(struct xen_commandline);
			break;
		case XENVER_build_id:
			size = sizeof(struct xen_build_id);
			break;
	}

	if (size)
		arg_handle = xen_hypercall_bounce_handle_prepare(arg, size);
	long ret = _hypercall2(int, xen_version | 0x40000000, cmd, arg_handle);
	if (size)
		xen_hypercall_bounce_handle_writeback(arg, arg_handle, size);
	xen_hypercall_bounce_end();
	return ret;

	xen_hypercall_bounce_end();
}

int xen_hypercall_bounce_console_io(int cmd, int count, char *str)
{
	xen_hypercall_bounce_begin();
	phys_addr_t str_handle = xen_hypercall_bounce_handle_prepare(str, count);
	int ret = _hypercall3(int, console_io | 0x40000000, cmd, count, str_handle);
	xen_hypercall_bounce_end();

	return ret;

}

int xen_hypercall_bounce_physdev_op(int cmd, void *arg)
{
	return _hypercall2(int, physdev_op | 0x40000000, cmd, arg);
}

int xen_hypercall_bounce_grant_table_op(unsigned int cmd, void *uop, unsigned int count)
{
	xen_hypercall_bounce_begin();
	size_t size = 0, subarg_size = 0;
	void *subarg_buffer = NULL;
	phys_addr_t subarg_handle = 0;

	switch (cmd) {
		case GNTTABOP_map_grant_ref:
			size = sizeof(struct gnttab_map_grant_ref);
			break;
		case GNTTABOP_unmap_grant_ref:
			size = sizeof(struct gnttab_unmap_grant_ref);
			break;
		case GNTTABOP_copy:
			size = sizeof(struct gnttab_copy);
			break;
		case GNTTABOP_query_size:
			size = sizeof(struct gnttab_query_size);
			break;
		case GNTTABOP_set_version:
			size = sizeof(struct gnttab_set_version);
			break;
		case GNTTABOP_get_status_frames:
		{	
			size = sizeof(struct gnttab_get_status_frames);
			struct gnttab_get_status_frames *status = uop;
			subarg_buffer = status->frame_list;
			subarg_size = sizeof(uint64_t) * status->nr_frames;
			subarg_handle = xen_hypercall_bounce_handle_prepare(subarg_buffer, subarg_size);
			status->frame_list = (void *)(unsigned long)subarg_handle;
			break;
		}
		case GNTTABOP_setup_table:
		{
			size = sizeof(struct xen_memory_reservation);
			struct gnttab_setup_table *setup = uop;
			subarg_buffer = setup->frame_list;
			subarg_size = sizeof(xen_pfn_t) * setup->nr_frames;
			subarg_handle = xen_hypercall_bounce_handle_prepare(subarg_buffer, subarg_size);
			setup->frame_list = (void *)(unsigned long)subarg_handle;
			break;
		}

		default:
			printk("Unhandled grant_table_op %u\n", cmd);
			BUG();
	}
	
	phys_addr_t uop_handle = xen_hypercall_bounce_handle_prepare(uop, size);
	int ret = _hypercall3(int, grant_table_op | 0x40000000, cmd, uop_handle, count);
	xen_hypercall_bounce_handle_writeback(uop, uop_handle, size);

	if (subarg_handle)
		xen_hypercall_bounce_handle_writeback(subarg_buffer, subarg_handle, subarg_size);

	xen_hypercall_bounce_end();

	return ret;

}

int xen_hypercall_bounce_vcpu_op(int cmd, int vcpuid, void *extra_args)
{
	// TODO: We may be able to skip begin/end if there is no "extra_args".
	xen_hypercall_bounce_begin();
	phys_addr_t extra_args_handle = 0;
	size_t size = 0;

	switch (cmd) {
		case VCPUOP_get_runstate_info:
			size = sizeof(struct vcpu_runstate_info);
			break;
		case VCPUOP_register_runstate_memory_area:
		case VCPUOP_register_runstate_phys_area:
			// The caller needs to ensure that the runstate_info shared structure
			// actually points to shared memory, we don't need to do anything here.
			size = sizeof(struct vcpu_register_runstate_memory_area);
			break;
		case VCPUOP_set_periodic_timer:
			size = sizeof(struct vcpu_set_periodic_timer);
			break;
		case VCPUOP_set_singleshot_timer:
			size = sizeof(struct vcpu_set_singleshot_timer);
			break;
		case VCPUOP_register_vcpu_info:
			size = sizeof(struct vcpu_register_vcpu_info);
			break;
		case VCPUOP_get_physid:
			size = sizeof(struct vcpu_get_physid);
			break;
		case VCPUOP_register_vcpu_time_memory_area:
		case VCPUOP_register_vcpu_time_phys_area:
			// See VCPUOP_register_runstate_memory_area remark;
			size = sizeof(struct vcpu_register_time_memory_area);
			break;
	}

	if (size)
		extra_args_handle = xen_hypercall_bounce_handle_prepare(extra_args, size);
	
	int ret = _hypercall3(int, vcpu_op | 0x40000000, cmd, vcpuid, extra_args_handle);

	if (size)
		xen_hypercall_bounce_handle_writeback(extra_args, extra_args_handle, size);
	
	xen_hypercall_bounce_end();

	return ret;
}

int xen_hypercall_bounce_suspend(unsigned long start_info_mfn)
{
	xen_hypercall_bounce_begin();
	struct sched_shutdown r = { .reason = SHUTDOWN_suspend };
	phys_addr_t gpaddr = xen_hypercall_bounce_handle_prepare(&r, sizeof(r));

	int ret = _hypercall3(int, sched_op | 0x40000000, SCHEDOP_shutdown, gpaddr, start_info_mfn);
	xen_hypercall_bounce_end();

	return ret;
}

unsigned long xen_hypercall_bounce_hvm_op(int op, void *arg)
{
	xen_hypercall_bounce_begin();
	size_t size;

	switch (op) {
		case HVMOP_get_mem_type:
			size = sizeof(struct xen_hvm_get_mem_type);
			break;
		case HVMOP_get_param:
			size = sizeof(struct xen_hvm_param);
			break;
		case HVMOP_set_param:
			size = sizeof(struct xen_hvm_param);
			break;
		case HVMOP_pagetable_dying:
			size = sizeof(struct xen_hvm_pagetable_dying);
			break;
		case HVMOP_set_evtchn_upcall_vector:
			size = sizeof(struct xen_hvm_evtchn_upcall_vector);
			break;
		default:
			panic("Unexpected Xen hvm_op operation (%d)", op);
	}

	phys_addr_t arg_handle = xen_hypercall_bounce_handle_prepare(arg, size);
	int ret = _hypercall2(unsigned long, hvm_op | 0x40000000, op, arg_handle);
	xen_hypercall_bounce_handle_writeback(arg, arg_handle, size);
	xen_hypercall_bounce_end();

	return ret;
}

long xen_hypercall_bounce_xenpmu_op(unsigned int op, void *arg)
{
	xen_hypercall_bounce_begin();
	phys_addr_t arg_handle = xen_hypercall_bounce_handle_prepare(arg, sizeof(struct xen_pmu_params));

	long ret = _hypercall2(int, xenpmu_op | 0x40000000, op, arg);
	xen_hypercall_bounce_handle_writeback(arg, arg_handle, sizeof(struct xen_pmu_params));
	xen_hypercall_bounce_end();

	return ret;
}

long xen_hypercall_bounce_dm_op(
	domid_t dom, unsigned int nr_bufs, struct xen_dm_op_buf *bufs)
{
  printk("xen_hypercall_bounce_dm_op: TODO");
  BUG_ON(true);

	int ret;
	__xen_stac();
	ret = _hypercall3(int, dm_op | 0x40000000, dom, nr_bufs, bufs);
	__xen_clac();
	return ret;
}
