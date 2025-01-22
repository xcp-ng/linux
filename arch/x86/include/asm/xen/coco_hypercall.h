/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XEN_COCO_HYPERCALL_H
#define _XEN_COCO_HYPERCALL_H

#include <linux/stddef.h>
#include <linux/types.h>

int __init xen_coco_hypercall_init(void);

void xen_coco_hypercall_begin(void);
void xen_coco_hypercall_end(void);
phys_addr_t xen_coco_hypercall_handle_prepare(void *buffer, size_t size);
void xen_coco_hypercall_handle_copyback(void *buffer, phys_addr_t handle, size_t size);

#endif