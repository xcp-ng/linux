// SPDX-License-Identifier: GPL-2.0
#include <linux/bio.h>
#include <linux/io.h>
#include <linux/export.h>
#include <xen/page.h>
#include <xen/swiotlb-xen.h>

bool xen_biovec_phys_mergeable(const struct bio_vec *vec1,
			       const struct bio_vec *vec2)
{
#if XEN_PAGE_SIZE == PAGE_SIZE
	unsigned long pfn1 = page_to_pfn(vec1->bv_page);
	unsigned long pfn2 = page_to_pfn(vec2->bv_page);
	unsigned long bfn1, bfn2;

	if (!pv_iommu_1_to_1_offset) {
		bfn1 = pfn_to_bfn(pfn1);
		bfn2 = pfn_to_bfn(pfn2);
	} else {
		bfn1 = pfn1;
		bfn2 = pfn2;
	}

	return bfn1 + PFN_DOWN(vec1->bv_offset + vec1->bv_len) == bfn2;
#else
	/*
	 * XXX: Add support for merging bio_vec when using different page
	 * size in Xen and Linux.
	 */
	return false;
#endif
}
EXPORT_SYMBOL(xen_biovec_phys_mergeable);
