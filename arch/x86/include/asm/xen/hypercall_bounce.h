/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_XEN_HYPERCALL_BOUNCE_H
#define _ASM_X86_XEN_HYPERCALL_BOUNCE_H

#include <linux/stddef.h>

#include <xen/xen.h>
#include <xen/interface/xen.h>
#include <xen/interface/xen-mca.h>
#include <xen/interface/platform.h>
#include <xen/interface/hvm/dm_op.h>

extern bool xen_physaddr_abi;

void __init xen_hypercall_bounce_init_early(void);
void __init xen_hypercall_bounce_teardown_early(void);
void xen_hypercall_bounce_init_smp(void);

int xen_hypercall_bounce_sched_op(int cmd, void *arg);
int xen_hypercall_bounce_mca(struct xen_mc *mc_op);
int xen_hypercall_bounce_platform_op(struct xen_platform_op *op);
long xen_hypercall_bounce_memory_op(unsigned int cmd, void *arg);
int xen_hypercall_bounce_multicall(void *call_list, uint32_t nr_calls);
int xen_hypercall_bounce_event_channel_op(int cmd, void *arg);
int xen_hypercall_bounce_xen_version(int cmd, void *arg);
int xen_hypercall_bounce_console_io(int cmd, int count, char *str);
int xen_hypercall_bounce_physdev_op(int cmd, void *arg);
int xen_hypercall_bounce_grant_table_op(unsigned int cmd, void *uop, unsigned int count);
int xen_hypercall_bounce_vcpu_op(int cmd, int vcpuid, void *extra_args);
unsigned long xen_hypercall_bounce_hvm_op(int op, void *arg);
long xen_hypercall_bounce_xenpmu_op(unsigned int op, void *arg);
long xen_hypercall_bounce_dm_op(domid_t dom, unsigned int nr_bufs, struct xen_dm_op_buf *bufs);
int xen_hypercall_bounce_suspend(unsigned long start_info_mfn);

#endif /* _ASM_X86_XEN_HYPERCALL_BOUNCE_H */