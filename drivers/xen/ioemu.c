/*
 * Helpers for in-kernel device emulators.
 *
 * Copyright (C) 2014 Citrix Systems UK Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <linux/kernel.h>
#include <linux/string.h>

#include <xen/interface/xen.h>
#include <xen/interface/hvm/dm_op.h>
#include <xen/ioemu.h>

#include <asm/xen/hypercall.h>

/**
 * xen_ioemu_inject_msi - inject an MSI into a guest
 * @domid: domain to inject MSI into
 * @addr: address for MSI
 * @data: data for MSI
 *
 * This is a simple wrapper around the HVMOP_inject_msi hypercall.
 */
int xen_ioemu_inject_msi(domid_t domid, uint64_t addr, uint32_t data)
{
	struct xen_dm_op_buf op_buf;
	struct xen_dm_op op;
	struct xen_dm_op_inject_msi *msi_data;

	memset(&op, 0, sizeof(op));
	op.op = XEN_DMOP_inject_msi;
	msi_data = &op.u.inject_msi;

	msi_data->addr = addr;
	msi_data->data = data;

	set_xen_guest_handle(op_buf.h, &op);
	op_buf.size = sizeof(op);

	return HYPERVISOR_dm_op(domid, 1, &op_buf);
}

/**
 * xen_ioemu_map_foreign_gfn_to_bfn: Returns the BFN's corresponding to GFN's.
 * @pv_iommu_ops: pv_iommu_ops contains the struct_ map_foreign_page
 * that will be used for lookup for BFN.
 * @count: count of struct pv_iommu_ops.
 *
 * Its a wrapper function for getting BFN from GFN using IOMMU hypercall.
*/
int xen_ioemu_map_foreign_gfn_to_bfn(struct pv_iommu_op *ops, int count)
{
        int i;
        int rc = 0;
        for (i = 0; i < count; i++)
        {
                ops[i].subop_id = IOMMUOP_lookup_foreign_page;
                ops[i].flags |= IOMMU_OP_writeable;
        }
        rc = HYPERVISOR_iommu_op(ops, count);
        return rc;
}

/**
 * xen_ioemu_unmap_foreign_gfn_to_bfn: Unmap BFN's corresponding to GFN's.
 * @pv_iommu_ops: pv_iommu_ops contains the struct unmap_foreign_page
 * that will be used to unmap BFNs.
 * @count: count of struct pv_iommu_ops.
 *
 * Its a wrapper function to unmap foreign GFN's to BFN's .
*/
int xen_ioemu_unmap_foreign_gfn_to_bfn(struct pv_iommu_op *ops, int count)
{
        int i;
        int rc = 0;
        for (i = 0; i < count; i++)
        {
                ops[i].subop_id = IOMMUOP_unmap_foreign_page;
        }
        rc = HYPERVISOR_iommu_op(ops, count);
        return rc;


}
EXPORT_SYMBOL(xen_ioemu_inject_msi);
EXPORT_SYMBOL(xen_ioemu_map_foreign_gfn_to_bfn);
EXPORT_SYMBOL(xen_ioemu_unmap_foreign_gfn_to_bfn);
