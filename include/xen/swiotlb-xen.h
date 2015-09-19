/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_SWIOTLB_XEN_H
#define __LINUX_SWIOTLB_XEN_H

#include <linux/swiotlb.h>
#include <asm/xen/swiotlb-xen.h>

void xen_dma_sync_for_cpu(struct device *dev, dma_addr_t handle,
			  size_t size, enum dma_data_direction dir);
void xen_dma_sync_for_device(struct device *dev, dma_addr_t handle,
			     size_t size, enum dma_data_direction dir);

extern int xen_iommu_map_page(unsigned long pfn, unsigned long mfn);
extern int xen_iommu_unmap_page(unsigned long pfn);

extern const struct dma_map_ops xen_swiotlb_dma_ops;

extern dma_addr_t pv_iommu_1_to_1_offset;
extern bool pv_iommu_1_to_1_setup_complete;

#endif /* __LINUX_SWIOTLB_XEN_H */
