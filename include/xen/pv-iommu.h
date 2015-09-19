/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __XEN_PVIOMMU_H
#define __XEN_PVIOMMU_H

#include <linux/swiotlb.h>
#include <xen/swiotlb-xen.h>

int xen_pv_iommu_map_sg_attrs(struct device *hwdev, struct scatterlist *sgl,
			int nelems, enum dma_data_direction dir,
			unsigned long attrs);

bool xen_pv_iommu_map_page(struct device *dev, struct page *page,
				unsigned long offset, size_t size,
				enum dma_data_direction dir,
				unsigned long attrs,
                                dma_addr_t *phys_addr);

#endif /* __XEN_PVIOUMMU_H */
