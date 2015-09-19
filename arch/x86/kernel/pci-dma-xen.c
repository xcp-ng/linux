#include <linux/types.h>
#include <linux/kthread.h>
#include <asm/xen/hypercall.h>
#include <xen/interface/memory.h>
#include <xen/hvc-console.h>
#include <asm/xen/page.h>

#include <xen/xen.h>

#define IOMMU_BATCH_SIZE 128

extern unsigned long max_pfn;
dma_addr_t pv_iommu_1_to_1_offset;
EXPORT_SYMBOL(pv_iommu_1_to_1_offset);

bool pv_iommu_1_to_1_setup_complete;
EXPORT_SYMBOL(pv_iommu_1_to_1_setup_complete);

static struct pv_iommu_op iommu_ops[IOMMU_BATCH_SIZE];

int xen_iommu_map_page(unsigned long bfn, unsigned long mfn)
{
	struct pv_iommu_op iommu_op;
	int rc;

	iommu_op.u.map_page.bfn = bfn;
	iommu_op.u.map_page.gfn = mfn;
	iommu_op.flags = IOMMU_OP_readable | IOMMU_OP_writeable | IOMMU_MAP_OP_no_ref_cnt;
	iommu_op.subop_id = IOMMUOP_map_page;
	rc = HYPERVISOR_iommu_op(&iommu_op, 1);
	if (rc < 0) {
		printk("Failed to setup IOMMU mapping for gpfn 0x%lx, mfn 0x%lx, err %d\n",
				bfn, mfn, rc);
		return rc;
	}
	return iommu_op.status;
}
EXPORT_SYMBOL_GPL(xen_iommu_map_page);

int xen_iommu_unmap_page(unsigned long bfn)
{
	struct pv_iommu_op iommu_op;
	int rc;

	iommu_op.u.unmap_page.bfn = bfn;
	iommu_op.flags = IOMMU_MAP_OP_no_ref_cnt;
	iommu_op.subop_id = IOMMUOP_unmap_page;
	rc = HYPERVISOR_iommu_op(&iommu_op, 1);
	if (rc < 0) {
		printk("Failed to remove IOMMU mapping for gpfn 0x%lx, err %d\n", bfn, rc);
		return rc;
	}
	return iommu_op.status;
}

int xen_iommu_batch(struct pv_iommu_op *iommu_ops, int count)
{
	int rc;

	rc = HYPERVISOR_iommu_op(iommu_ops, count);
	if (rc < 0) {
		printk("Failed to batch IOMMU map, err %d\n", rc);
	}
	return rc;
}
EXPORT_SYMBOL_GPL(xen_iommu_batch);

static int check_batch(int size)
{
	int op;
	int res=0;
	for (op = 1; op < size; op +=2)
	{
		if ( iommu_ops[op].status ) {
			printk("Iommu op %d went wrong, subop id %d, bfn 0x%llx, gfn 0x%llx\n, err %d, flags 0x%x\n",
			       op, iommu_ops[op].subop_id,
			       iommu_ops[op].u.map_page.bfn,
			       iommu_ops[op].u.map_page.gfn,
			       iommu_ops[op].status, iommu_ops[op].flags );
			res++;
		}
	}
	return res;
}


void __init pci_xen_pv_iommu_late_init(void)
{
	if (pv_iommu_1_to_1_offset) {
		/* Xen has already set up 1-1 mapping for us */
		pv_iommu_1_to_1_setup_complete = true;
		printk(KERN_INFO "XEN-PV-IOMMU - completed setting up 1-1 mapping\n");
	}
}

/*
 * Detect is we can use PV-IOMMU
 * If we can, caller needs to disable xen_swiotlb.
 * and additionally set up normal x86 swiotlb. (PV-IOMMU is layered on top)
 * Otherwise keep xen_swiotlb & don't setup x86 one.
 */

int pci_xen_swiotlb_pviommu_detect(void)
{
	int count = 0;
	u64 pfn, pfn_limit, max_host_mfn = 0;
	struct pv_iommu_op_ext iommu_op;
	int rc;

	if (!xen_initial_domain())
		return 0;

	iommu_op.u.query_caps.offset = 0;
	iommu_op.flags = 0;
	iommu_op.status = 0;
	iommu_op.subop_id = IOMMUOP_query_caps;
	rc = HYPERVISOR_iommu_op(&iommu_op, 1);

	if (rc || !(iommu_op.flags & IOMMU_QUERY_map_cap)) {
		printk(KERN_INFO "XEN-PV-IOMMU: No IOMMU cap.\n");
		return 0;
	}

	max_host_mfn = HYPERVISOR_memory_op(XENMEM_maximum_ram_page, NULL);
	printk("Max host RAM MFN is 0x%llx\n",max_host_mfn);
	printk("max_pfn is 0x%lx\n",max_pfn);

	/* Check and Setup 1-1 host RAM offset location */
	if (iommu_op.flags & IOMMU_QUERY_map_all_mfns)
		pv_iommu_1_to_1_offset = (dma_addr_t) iommu_op.u.query_caps.offset << PAGE_SHIFT;
	/* If offset is 0 or not set - disable PV IOMMU */
	if (!pv_iommu_1_to_1_offset) {
		printk(KERN_INFO "XEN-PV-IOMMU: Disabled.\n");
		return 0;
	}
	pfn_limit = pv_iommu_1_to_1_offset >> PAGE_SHIFT;
	if (max_pfn >= pfn_limit) {
		printk("XEN-PV-IOMMU: bfn_foreign_offset at %llu, is too small"
			" for Dom0.  Needs %lu\n", pfn_limit, max_pfn + 1);
		BUG();
	}

	pfn_limit = min(max_host_mfn, pfn_limit);

	/* Setup 1-1 mapping of GPFN to MFN */
	for (pfn=0; pfn < pfn_limit; pfn++)
	{
		unsigned long mfn = get_phys_to_machine(pfn);
		if (mfn != INVALID_P2M_ENTRY && mfn != IDENTITY_FRAME(pfn))
		{
			iommu_ops[count].u.unmap_page.bfn = pfn;
			iommu_ops[count].flags = IOMMU_MAP_OP_no_ref_cnt;
			iommu_ops[count].subop_id = IOMMUOP_unmap_page;
			count++;
			iommu_ops[count].u.map_page.bfn = pfn;
			iommu_ops[count].u.map_page.gfn = pfn_to_mfn(pfn);
			iommu_ops[count].flags = IOMMU_OP_readable |
						IOMMU_OP_writeable |
						IOMMU_MAP_OP_no_ref_cnt;
			iommu_ops[count].subop_id = IOMMUOP_map_page;
			count++;
		}
		if (count == IOMMU_BATCH_SIZE)
		{
			count = 0;
			if (xen_iommu_batch(iommu_ops, IOMMU_BATCH_SIZE)
			   || check_batch(IOMMU_BATCH_SIZE)) {
				printk("Failed to fully Setup 1-1 mapping of GPFN to MFN.\n");
				BUG();
			}
		}
	}
	if (count) {
		if (xen_iommu_batch(iommu_ops, count)
		   || check_batch(count)) {
			printk("Failed to fully Setup 1-1 mapping of GPFN to MFN.\n");
			BUG();
		}
	}

	printk("XEN-PV-IOMMU: Using GPFN IOMMU mode, 1-to-1 offset is 0x%llx\n",
		pv_iommu_1_to_1_offset);
	return 1;
}
