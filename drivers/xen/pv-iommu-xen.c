/*
 *  Copyright 2014
 *  by Malcolm Crossley <malcolm.crossley@citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2.0 as published by
 * the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *
 */

#include <linux/bootmem.h>
#include <linux/dma-direct.h>
#include <linux/export.h>
#include <xen/swiotlb-xen.h>
#include <asm/swiotlb.h>
#include <xen/page.h>
#include <xen/xen-ops.h>
#include <xen/hvc-console.h>

#include <trace/events/swiotlb.h>

extern int xen_iommu_map_page(unsigned long pfn, unsigned long mfn);
extern bool pv_iommu_1_to_1_setup_complete;

extern phys_addr_t io_tlb_start, io_tlb_end;

dma_addr_t xen_pv_iommu_get_foreign_addr(unsigned long p2m_entry)
{
	dma_addr_t phys;
	unsigned long mfn = p2m_entry & ~FOREIGN_FRAME_BIT;
	/* If 1-1 has not completed being setup then map this page now */
	if (unlikely(!pv_iommu_1_to_1_setup_complete))
		xen_iommu_map_page(mfn + (pv_iommu_1_to_1_offset >> PAGE_SHIFT),
					mfn);

	phys = (mfn << PAGE_SHIFT) + pv_iommu_1_to_1_offset;
	return phys;
}

/*
 * Map a single buffer of the indicated size for DMA in streaming mode.  The
 * physical address to use is returned.
 *
 * PV IOMMU version detects Xen foreign pages and use's the original MFN offset
 * into previously setup IOMMU 1-to-1 offset mapping of host memory
 */
dma_addr_t xen_pv_iommu_map_page(struct device *dev, struct page *page,
				unsigned long offset, size_t size,
				enum dma_data_direction dir,
				unsigned long attrs)
{
	unsigned long p2m_entry = get_phys_to_machine(page_to_pfn(page));

	if (p2m_entry & FOREIGN_FRAME_BIT) {
		dma_addr_t phys = xen_pv_iommu_get_foreign_addr(p2m_entry) + offset;
		/* Check if device can DMA to 1-1 mapped foreign address */
		if (dma_capable(dev, phys, size)) {
			return phys;
		} else {
			phys_addr_t map = swiotlb_tbl_map_single(dev, io_tlb_start,
							page_to_phys(page) + offset,
							size, dir, attrs);
			trace_swiotlb_bounced(dev, phys, size, 0);
			return phys_to_dma(dev, map);
		}
	}

	return swiotlb_map_page(dev, page, offset, size, dir, attrs);
}
EXPORT_SYMBOL_GPL(xen_pv_iommu_map_page);

/*
 * Map a set of buffers described by scatterlist in streaming mode for DMA.
 * This is the scatter-gather version of the above xen_swiotlb_map_page
 * interface.  Here the scatter gather list elements are each tagged with the
 * appropriate dma address and length.  They are obtained via
 * sg_dma_{address,length}(SG).
 *
 * NOTE: An implementation may be able to use a smaller number of
 *       DMA address/length pairs than there are SG table elements.
 *       (for example via virtual mapping capabilities)
 *       The routine returns the number of addr/length pairs actually
 *       used, at most nents.
 *
 * PV IOMMU version detects Xen foreign pages and use's the original MFN offset
 * into previously setup IOMMU 1-to-1 offset mapping of host memory
 *
 */
int
xen_pv_iommu_map_sg_attrs(struct device *hwdev, struct scatterlist *sgl,
			 int nelems, enum dma_data_direction dir,
			 unsigned long attrs)
{
	struct scatterlist *sg;
	int i;

	for_each_sg(sgl, sg, nelems, i) {
		phys_addr_t paddr = sg_phys(sg);
		dma_addr_t dev_addr = phys_to_dma(hwdev, paddr);
		unsigned long p2m_entry = get_phys_to_machine(PFN_DOWN(paddr));
		if (p2m_entry & FOREIGN_FRAME_BIT)
			dev_addr = xen_pv_iommu_get_foreign_addr(p2m_entry) +
					(paddr & ~PAGE_MASK);

		/* Check if device can DMA to bus address */
		if (!dma_capable(hwdev, dev_addr, sg->length)){
			phys_addr_t map = swiotlb_tbl_map_single(hwdev, io_tlb_start,
						paddr, sg->length, dir, attrs);
			trace_swiotlb_bounced(hwdev, dev_addr, sg->length, 0);
			if (map == SWIOTLB_MAP_ERROR) {
				/* Don't panic here, we expect map_sg users
				   to do proper error handling. */
				swiotlb_unmap_sg_attrs(hwdev, sgl, i, dir,
						       attrs);
				sgl[0].dma_length = 0;
				return 0;
			}
			sg->dma_address = phys_to_dma(hwdev, map);

		} else {
			sg->dma_address = dev_addr;
		}
		sg->dma_length = sg->length;
	}
	return nelems;

}
EXPORT_SYMBOL_GPL(xen_pv_iommu_map_sg_attrs);
