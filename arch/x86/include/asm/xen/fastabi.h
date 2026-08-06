/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_XEN_HYPERCALL_BOUNCE_H
#define _ASM_X86_XEN_HYPERCALL_BOUNCE_H

#include <linux/stddef.h>

#include <xen/xen.h>
#include <xen/interface/xen.h>
#include <xen/interface/memory.h>
#include <xen/interface/grant_table.h>
#include <xen/interface/event_channel.h>
#include <xen/interface/sched.h>
#include <xen/interface/version.h>
#include <xen/interface/vcpu.h>
#include <xen/interface/hvm/hvm_op.h>
#include <asm/xen/cpuid.h>

#include <xen/interface/fastabi.h>

#include <xen/interface/fastabi/sched.h>
#include <xen/interface/fastabi/event_channel.h>
#include <xen/interface/fastabi/hvm.h>
#include <xen/interface/fastabi/memory.h>
#include <xen/interface/fastabi/vcpu.h>
#include <xen/interface/fastabi/version.h>

extern bool xen_use_fastabi, xen_fastabi_force;
extern enum xen_hypercall_vendor xen_fastabi_hypercall_vendor;

static inline
int xen_fastabi_sched_op(int cmd, void *arg)
{
	switch (cmd) {
		case SCHEDOP_yield:
			return xen_hypercall_sched_yield(xen_fastabi_hypercall_vendor);
		case SCHEDOP_block:
			return xen_hypercall_sched_block(xen_fastabi_hypercall_vendor);
		case SCHEDOP_shutdown:
			return xen_hypercall_sched_shutdown(xen_fastabi_hypercall_vendor, arg);
		case SCHEDOP_watchdog:
			return xen_hypercall_sched_watchdog(xen_fastabi_hypercall_vendor, arg);
		case SCHEDOP_pin_override:
			return xen_hypercall_sched_pin_override(xen_fastabi_hypercall_vendor, arg);
		case SCHEDOP_poll:
		{
			struct sched_poll *_arg;

			if ( _arg->nr_ports == 0 )
				return -EINVAL;

			if ( _arg->nr_ports > 1 )
				return -EOPNOTSUPP;

			return xen_hypercall_sched_poll(xen_fastabi_hypercall_vendor, _arg->timeout, _arg->ports[0]);
		}

		default:
			printk("Unhandled sched_op %u\n", cmd);
			return -EOPNOTSUPP;
	}
}

static inline
long xen_fastabi_memory_op(unsigned int cmd, void *arg)
{
	switch (cmd) {
		default:
			WARN(1, "Unhandled memory_op %u\n", cmd);
			printk("Unhandled memory_op %u\n", cmd);
			return -EOPNOTSUPP;
	}
}

static inline
int xen_fastabi_event_channel_op(int cmd, void *arg)
{
	switch (cmd) {
			case EVTCHNOP_bind_interdomain:
				return xen_hypercall_event_channel_bind_interdomain(xen_fastabi_hypercall_vendor, arg);
			case EVTCHNOP_bind_virq:
				return xen_hypercall_event_channel_bind_virq(xen_fastabi_hypercall_vendor, arg);
			case EVTCHNOP_bind_pirq:
				return xen_hypercall_event_channel_bind_pirq(xen_fastabi_hypercall_vendor, arg);
			case EVTCHNOP_bind_ipi:
				return xen_hypercall_event_channel_bind_ipi(xen_fastabi_hypercall_vendor, arg);
			case EVTCHNOP_close:
				return xen_hypercall_event_channel_close(xen_fastabi_hypercall_vendor, arg);
			case EVTCHNOP_send:
				return xen_hypercall_event_channel_send(xen_fastabi_hypercall_vendor, arg);
			case EVTCHNOP_status:
				return xen_hypercall_event_channel_status(xen_fastabi_hypercall_vendor, arg);
			case EVTCHNOP_alloc_unbound:
				return xen_hypercall_event_channel_alloc_unbound(xen_fastabi_hypercall_vendor, arg);
			case EVTCHNOP_bind_vcpu:
				return xen_hypercall_event_channel_bind_vcpu(xen_fastabi_hypercall_vendor, arg);
			case EVTCHNOP_unmask:
				return xen_hypercall_event_channel_unmask(xen_fastabi_hypercall_vendor, arg);
			case EVTCHNOP_reset:
				return xen_hypercall_event_channel_reset(xen_fastabi_hypercall_vendor, arg);
			case EVTCHNOP_init_control:
				return xen_hypercall_event_channel_init_control(xen_fastabi_hypercall_vendor, arg);
			case EVTCHNOP_expand_array:
				return xen_hypercall_event_channel_expand_array(xen_fastabi_hypercall_vendor, arg);
			case EVTCHNOP_set_priority:
				return xen_hypercall_event_channel_set_priority(xen_fastabi_hypercall_vendor, arg);
			default:
				printk("Unhandled event_channel_op %u\n", cmd);
				return -EOPNOTSUPP;
	}
}

static inline
int xen_fastabi_xen_version(int cmd, void *arg)
{
	switch (cmd) {
		case XENVER_version:
			return xen_hypercall_version_version(xen_fastabi_hypercall_vendor);
		case XENVER_platform_parameters:
		{
			struct xen_platform_parameters *_arg = arg;
			_arg->virt_start = 0; // PV-only
			return 0;
		}
		case XENVER_get_features:
			return xen_hypercall_version_get_features(xen_fastabi_hypercall_vendor, arg);

		/* Dom0: TODO */
		case XENVER_extraversion:
		case XENVER_changeset:
		case XENVER_commandline:
		case XENVER_build_id:
		case XENVER_capabilities:
		case XENVER_compile_info:
			return -EPERM;

		default:
			printk("Unhandled xen_version op %u\n", cmd);
			return -EOPNOTSUPP;
	}
}

static inline
int xen_fastabi_grant_table_op(unsigned int cmd, void *uop, unsigned int count)
{
	WARN(count != 1, "TODO: Needs to deal with batched grant_table_op");
	
	switch (cmd) {
		default:
			printk("Unhandled grant_table_op %u\n", cmd);
			return -EOPNOTSUPP;
	}
}

static inline
int xen_fastabi_vcpu_op(int cmd, int vcpuid, void *extra_args)
{
	switch (cmd) {
		case VCPUOP_get_runstate_info:
			return xen_hypercall_vcpu_get_runstate_info(xen_fastabi_hypercall_vendor, extra_args, vcpuid);
		case VCPUOP_register_runstate_phys_area:
			return xen_hypercall_vcpu_register_runstate_phys_area(xen_fastabi_hypercall_vendor, extra_args, vcpuid);
		case VCPUOP_set_periodic_timer:
			return xen_hypercall_vcpu_set_periodic_timer(xen_fastabi_hypercall_vendor, extra_args, vcpuid);
		case VCPUOP_stop_periodic_timer:
			return xen_hypercall_vcpu_stop_periodic_timer(xen_fastabi_hypercall_vendor, vcpuid);
		case VCPUOP_set_singleshot_timer:
			return xen_hypercall_vcpu_set_singleshot_timer(xen_fastabi_hypercall_vendor, extra_args, vcpuid);
		case VCPUOP_stop_singleshot_timer:
			return xen_hypercall_vcpu_stop_singleshot_timer(xen_fastabi_hypercall_vendor, vcpuid);
		case VCPUOP_register_vcpu_info:
			return xen_hypercall_vcpu_register_vcpu_info(xen_fastabi_hypercall_vendor, extra_args, vcpuid);
		case VCPUOP_get_physid:
			return xen_hypercall_vcpu_get_physid(xen_fastabi_hypercall_vendor, extra_args, vcpuid);
		case VCPUOP_register_vcpu_time_phys_area:
			return xen_hypercall_vcpu_register_vcpu_time_phys_area(xen_fastabi_hypercall_vendor, extra_args, vcpuid);
		default:
			printk("Unhandled vcpu_op %u\n", cmd);
			return -EOPNOTSUPP;
	}
}

static inline
unsigned long xen_fastabi_hvm_op(int op, void *arg)
{
	switch (op) {
		case HVMOP_get_mem_type:
			return xen_hypercall_hvm_get_mem_type(xen_fastabi_hypercall_vendor, arg);
		case HVMOP_get_param:
			return xen_hypercall_hvm_get_param(xen_fastabi_hypercall_vendor, arg);
		case HVMOP_pagetable_dying:
			if ( xen_fastabi_force )
				return -ENOSYS;
			return -EOPNOTSUPP;
		case HVMOP_set_param:
			return xen_hypercall_hvm_set_param(xen_fastabi_hypercall_vendor, arg);
		case HVMOP_set_evtchn_upcall_vector:
			return xen_hypercall_hvm_set_evtchn_upcall_vector(xen_fastabi_hypercall_vendor, arg);
		default:
			printk("Unhandled hvm_op %u\n", op);
			return -EOPNOTSUPP;
	}
}

#endif /* _ASM_X86_XEN_HYPERCALL_BOUNCE_H */