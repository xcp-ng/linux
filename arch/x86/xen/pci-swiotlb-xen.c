/* Glue code to lib/swiotlb-xen.c */

#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/kthread.h>
#include <xen/swiotlb-xen.h>

#include <asm/xen/hypervisor.h>
#include <xen/xen.h>
#include <asm/iommu_table.h>
#include <asm/xen/hypercall.h>
#include <xen/interface/memory.h>


#include <asm/xen/swiotlb-xen.h>
#include <asm/xen/page.h>
#ifdef CONFIG_X86_64
#include <asm/iommu.h>
#include <asm/dma.h>
#endif
#include <linux/export.h>

#define IOMMU_BATCH_SIZE 128

extern unsigned long max_pfn;
dma_addr_t pv_iommu_1_to_1_offset;
EXPORT_SYMBOL(pv_iommu_1_to_1_offset);


/* The bfn_foreign_offset is where the 1:1 BFN:MFN region starts.
 * This value must be after the Dom0 1:1 PFN:MFN range.
 * The default for bfn_foreign_offset is calculated as follows:
 * 1 TB (40 address bits on some GPUs) - 768 G (max host memory that we
 * want to support and have everything fit under 1 T) - 4 G (MMIO hole)
 * - 4 G ("wiggle room").
 */

static __initdata int bfn_foreign_offset = 248;

static int __init
xen_pviommu_foreign_offset_setup (char *str)
{
	if (!str)
		return 0;
	bfn_foreign_offset = simple_strtoul(str, NULL, 0);
	return 1;
}

__setup("xen_pviommu_foreign_offset=",  xen_pviommu_foreign_offset_setup);


bool pv_iommu_1_to_1_setup_complete;
EXPORT_SYMBOL(pv_iommu_1_to_1_setup_complete);

int xen_swiotlb __read_mostly;
static struct pv_iommu_op iommu_ops[IOMMU_BATCH_SIZE];
static struct task_struct *xen_pv_iommu_setup_task;

int xen_pv_iommu_map_sg_attrs(struct device *hwdev, struct scatterlist *sgl,
			 int nelems, enum dma_data_direction dir,
			 struct dma_attrs *attrs);

dma_addr_t xen_pv_iommu_map_page(struct device *dev, struct page *page,
				unsigned long offset, size_t size,
				enum dma_data_direction dir,
				struct dma_attrs *attrs);

void *xen_pv_iommu_alloc_coherent(struct device *hwdev, size_t size,
					dma_addr_t *dma_handle, gfp_t flags,
					struct dma_attrs *attrs);

void xen_pv_iommu_free_coherent(struct device *dev, size_t size,
				      void *vaddr, dma_addr_t dma_addr,
				      struct dma_attrs *attrs);


static struct dma_map_ops xen_swiotlb_dma_ops = {
	.mapping_error = xen_swiotlb_dma_mapping_error,
	.alloc = xen_swiotlb_alloc_coherent,
	.free = xen_swiotlb_free_coherent,
	.sync_single_for_cpu = xen_swiotlb_sync_single_for_cpu,
	.sync_single_for_device = xen_swiotlb_sync_single_for_device,
	.sync_sg_for_cpu = xen_swiotlb_sync_sg_for_cpu,
	.sync_sg_for_device = xen_swiotlb_sync_sg_for_device,
	.map_sg = xen_swiotlb_map_sg_attrs,
	.unmap_sg = xen_swiotlb_unmap_sg_attrs,
	.map_page = xen_swiotlb_map_page,
	.unmap_page = xen_swiotlb_unmap_page,
	.dma_supported = xen_swiotlb_dma_supported,
	.get_required_mask = xen_swiotlb_get_required_mask,
};

static struct dma_map_ops xen_pv_iommu_dma_ops = {
	.mapping_error = swiotlb_dma_mapping_error,
	.alloc = x86_swiotlb_alloc_coherent,
	.free = x86_swiotlb_free_coherent,
	.map_sg = xen_pv_iommu_map_sg_attrs,
	.map_page = xen_pv_iommu_map_page,
	.unmap_sg = swiotlb_unmap_sg_attrs,
	.unmap_page = swiotlb_unmap_page,
	.get_required_mask = xen_swiotlb_get_required_mask,
	.sync_single_for_cpu = swiotlb_sync_single_for_cpu,
	.sync_single_for_device = swiotlb_sync_single_for_device,
	.sync_sg_for_cpu = swiotlb_sync_sg_for_cpu,
	.sync_sg_for_device = swiotlb_sync_sg_for_device,
};

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
		if ( iommu_ops[op].status )
		{
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




static int pv_iommu_setup(void *data)
{
	int pfn, count = 0;
	u64 max_host_mfn = 0;
	u64 iommu_fn_offset = pv_iommu_1_to_1_offset >> PAGE_SHIFT;

	if (pv_iommu_1_to_1_setup_complete)
		return 0;

	max_host_mfn = HYPERVISOR_memory_op(XENMEM_maximum_ram_page, NULL);

	/* Remove Xen setup 1-1 mapping */
	for (pfn=0; pfn < max_host_mfn; pfn++)
	{
		if (get_phys_to_machine(pfn) == INVALID_P2M_ENTRY ||
		    (pfn >= iommu_fn_offset))
		{
			iommu_ops[count].u.unmap_page.bfn = pfn;
			iommu_ops[count].flags = IOMMU_MAP_OP_no_ref_cnt;
			iommu_ops[count].subop_id = IOMMUOP_unmap_page;
			count++;
		}
		if (count == IOMMU_BATCH_SIZE)
		{
			count = 0;
			if (xen_iommu_batch(iommu_ops,
						IOMMU_BATCH_SIZE))
				panic("Xen PV-IOMMU: failed to remove legacy"
						" mappings\n");
			cond_resched();
		}
	}
	if (count && xen_iommu_batch(iommu_ops, count))
		panic("Xen PV-IOMMU: failed to remove legacy mappings\n");

	count = 0;
	/* Create offset IOMMU mapping of all of host RAM, start from
	 * iommu_fn_offset (derived from pv_iommu_1_to_1_offset) 
	 */
	for (pfn=0; pfn < max_host_mfn; pfn++)
	{
		iommu_ops[count].u.map_page.bfn = iommu_fn_offset + pfn;
		iommu_ops[count].u.map_page.gfn = pfn;
		iommu_ops[count].flags = IOMMU_OP_readable | IOMMU_OP_writeable |
					IOMMU_MAP_OP_no_ref_cnt |
					IOMMU_MAP_OP_add_m2b;
		iommu_ops[count].subop_id = IOMMUOP_map_page;
		count++;
		if (count == IOMMU_BATCH_SIZE)
		{
			count = 0;
			if (xen_iommu_batch(iommu_ops,
						IOMMU_BATCH_SIZE))
				panic("Xen PV-IOMMU: failed to setup"
					" 1-1 mapping\n");
			if (check_batch(IOMMU_BATCH_SIZE))
				printk(KERN_ERR "Failed to fully create offset IOMMU mapping.");

			cond_resched();
		}
	}
	if (count)
	{
		if (xen_iommu_batch(iommu_ops, count))
			panic("Xen PV-IOMMU: failed to setup 1-1 mappings");
		if (check_batch(count))
			printk(KERN_ERR "Failed to fully create offset IOMMU mapping.");
	}

	printk(KERN_INFO "XEN-PV-IOMMU - completed setting up 1-1 mapping\n");
	pv_iommu_1_to_1_setup_complete = true;
	return 0;
}

/*
 * pci_xen_swiotlb_detect - set xen_swiotlb to 1 if necessary
 *
 * This returns non-zero if we are forced to use xen_swiotlb (by the boot
 * option).
 */
int __init pci_xen_swiotlb_detect(void)
{
	if (!xen_pv_domain())
		return 0;

	if (xen_initial_domain()){
		int count = 0;
		u64 pfn, pfn_limit, max_host_mfn = 0;
		struct pv_iommu_op iommu_op;
		int rc;

		iommu_op.flags = 0;
		iommu_op.status = 0;
		iommu_op.subop_id = IOMMUOP_query_caps;
		rc = HYPERVISOR_iommu_op(&iommu_op, 1);

		if (rc || !(iommu_op.flags & IOMMU_QUERY_map_cap))
			goto no_pv_iommu;

		max_host_mfn = HYPERVISOR_memory_op(XENMEM_maximum_ram_page, NULL);
		printk("Max host RAM MFN is 0x%llx\n",max_host_mfn);
		printk("max_pfn is 0x%lx\n",max_pfn);

		/* Check and Setup 1-1 host RAM offset location */
		pv_iommu_1_to_1_offset = (dma_addr_t) bfn_foreign_offset << 30;
		pfn_limit = pv_iommu_1_to_1_offset >> PAGE_SHIFT;
		if (max_pfn >= pfn_limit)
		{
			printk(KERN_INFO "XEN-PV-IOMMU: bfn_foreign_offset"
					 " at %d, is too small for Dom0."
					 "  Needs %lu", bfn_foreign_offset,
					 (max_pfn >> (30 - PAGE_SHIFT))+1);
			goto no_pv_iommu;
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
				if (xen_iommu_batch(iommu_ops,
							IOMMU_BATCH_SIZE))
					goto remove_iommu_mappings;

				if (check_batch(IOMMU_BATCH_SIZE))
				{
					printk(KERN_ERR "Failed to fully Setup 1-1 mapping of GPFN to MFN.");
					goto remove_iommu_mappings;
				}
			}

		}
		if (count) {
			if (xen_iommu_batch(iommu_ops, count))
				goto remove_iommu_mappings;
			if (check_batch(count))
			{
				printk(KERN_ERR "Failed to fully Setup 1-1 mapping of GPFN to MFN.");
				goto remove_iommu_mappings;
			}
		}

		/* hook the PV IOMMU DMA ops */
		xen_swiotlb = 0;

		printk("Using GPFN IOMMU mode, 1-to-1 offset is 0x%llx\n",
				pv_iommu_1_to_1_offset);
		return 1;

remove_iommu_mappings:
		BUG();
	}

no_pv_iommu:
	/* If running as PV guest, either iommu=soft, or swiotlb=force will
	 * activate this IOMMU. If running as PV privileged, activate it
	 * irregardless.
	 */
	if ((xen_initial_domain() || swiotlb || swiotlb_force))
		xen_swiotlb = 1;

	/* If we are running under Xen, we MUST disable the native SWIOTLB.
	 * Don't worry about swiotlb_force flag activating the native, as
	 * the 'swiotlb' flag is the only one turning it on. */
	swiotlb = 0;

#ifdef CONFIG_X86_64
	/* pci_swiotlb_detect_4gb turns on native SWIOTLB if no_iommu == 0
	 * (so no iommu=X command line over-writes).
	 * Considering that PV guests do not want the *native SWIOTLB* but
	 * only Xen SWIOTLB it is not useful to us so set no_iommu=1 here.
	 */
	if (max_pfn > MAX_DMA32_PFN)
		no_iommu = 1;
#endif
	return xen_swiotlb;
}

void __init pci_xen_pv_iommu_late_init(void)
{
	if (pv_iommu_1_to_1_offset){
		xen_pv_iommu_setup_task = kthread_create(pv_iommu_setup,
				NULL,"xen-pv-iommu-setup");
		wake_up_process(xen_pv_iommu_setup_task);
	}
}

void __init pci_xen_swiotlb_init(void)
{
	if (xen_swiotlb) {
		xen_swiotlb_init(1, true /* early */);
		dma_ops = &xen_swiotlb_dma_ops;

#ifdef CONFIG_PCI
		/* Make sure ACS will be enabled */
		pci_request_acs();
#endif
	}

	/* Start the native swiotlb */
	if (pv_iommu_1_to_1_offset) {
		dma_ops = &xen_pv_iommu_dma_ops;
		pci_request_acs();
		swiotlb_init(0);
		printk(KERN_INFO "XEN-PV-IOMMU: "
		       "Using software bounce buffering for IO on 32bit DMA devices (SWIOTLB)\n");
		swiotlb_print_info();
	}
}

int pci_xen_swiotlb_init_late(void)
{
	int rc;

	if (xen_swiotlb)
		return 0;

	rc = xen_swiotlb_init(1, false /* late */);
	if (rc)
		return rc;

	dma_ops = &xen_swiotlb_dma_ops;
#ifdef CONFIG_PCI
	/* Make sure ACS will be enabled */
	pci_request_acs();
#endif

	return 0;
}
EXPORT_SYMBOL_GPL(pci_xen_swiotlb_init_late);

IOMMU_INIT_FINISH(pci_xen_swiotlb_detect,
		  NULL,
		  pci_xen_swiotlb_init,
		  pci_xen_pv_iommu_late_init);
