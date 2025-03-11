// SPDX-License-Identifier: GPL-2.0 OR MIT
/******************************************************************************
 * grant_table.c
 * x86 specific part
 *
 * Granting foreign access to our memory reservation.
 *
 * Copyright (c) 2005-2006, Christopher Clark
 * Copyright (c) 2004-2005, K A Fraser
 * Copyright (c) 2008 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan. Split out x86 specific part.
 */

#define pr_fmt(fmt) "xen:" KBUILD_MODNAME ": " fmt

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include <xen/interface/xen.h>
#include <xen/page.h>
#include <xen/grant_table.h>
#include <xen/xen.h>

#include <asm/e820/api.h>

static struct gnttab_vm_area {
	struct vm_struct *area;
	pte_t **ptes;
	int idx;
} gnttab_shared_vm_area, gnttab_status_vm_area;

int arch_gnttab_map_shared(xen_pfn_t *frames, unsigned long nr_gframes,
				 unsigned long max_nr_gframes,
				 void **__shared)
{
	void *shared = *__shared;
	unsigned long addr;
	unsigned long i;

	if (shared == NULL)
		*__shared = shared = gnttab_shared_vm_area.area->addr;

	addr = (unsigned long)shared;

	for (i = 0; i < nr_gframes; i++) {
		set_pte_at(&init_mm, addr, gnttab_shared_vm_area.ptes[i],
			   mfn_pte(frames[i], PAGE_KERNEL_NOENC));
		addr += PAGE_SIZE;
	}

	return 0;
}

int arch_gnttab_map_status(uint64_t *frames, unsigned long nr_gframes,
				 unsigned long max_nr_gframes,
				 grant_status_t **__shared)
{
	grant_status_t *shared = *__shared;
	unsigned long addr;
	unsigned long i;

	if (shared == NULL)
		*__shared = shared = gnttab_status_vm_area.area->addr;

	addr = (unsigned long)shared;

	for (i = 0; i < nr_gframes; i++) {
		set_pte_at(&init_mm, addr, gnttab_status_vm_area.ptes[i],
				 mfn_pte(frames[i], PAGE_KERNEL_NOENC));
		addr += PAGE_SIZE;
	}

	return 0;
}

void arch_gnttab_unmap(void *shared, unsigned long nr_gframes)
{
	pte_t **ptes;
	unsigned long addr;
	unsigned long i;

	if (shared == gnttab_status_vm_area.area->addr)
		ptes = gnttab_status_vm_area.ptes;
	else
		ptes = gnttab_shared_vm_area.ptes;

	addr = (unsigned long)shared;

	for (i = 0; i < nr_gframes; i++) {
		set_pte_at(&init_mm, addr, ptes[i], __pte(0));
		addr += PAGE_SIZE;
	}
}

static int gnttab_apply(pte_t *pte, unsigned long addr, void *data)
{
	struct gnttab_vm_area *area = data;

	area->ptes[area->idx++] = pte;
	return 0;
}

static int arch_gnttab_valloc(struct gnttab_vm_area *area, unsigned nr_frames)
{
	area->ptes = kmalloc_objs(*area->ptes, nr_frames);
	if (area->ptes == NULL)
		return -ENOMEM;
	area->area = get_vm_area(PAGE_SIZE * nr_frames, VM_IOREMAP);
	if (!area->area)
		goto out_free_ptes;
	if (apply_to_page_range(&init_mm, (unsigned long)area->area->addr,
			PAGE_SIZE * nr_frames, gnttab_apply, area))
		goto out_free_vm_area;
	return 0;
out_free_vm_area:
	free_vm_area(area->area);
out_free_ptes:
	kfree(area->ptes);
	return -ENOMEM;
}

static void arch_gnttab_vfree(struct gnttab_vm_area *area)
{
	free_vm_area(area->area);
	kfree(area->ptes);
}

int arch_gnttab_init(unsigned long nr_shared, unsigned long nr_status)
{
	int ret;

	if (!xen_pv_domain())
		return 0;

	ret = arch_gnttab_valloc(&gnttab_shared_vm_area, nr_shared);
	if (ret < 0)
		return ret;

	/*
	 * Always allocate the space for the status frames in case
	 * we're migrated to a host with V2 support.
	 */
	ret = arch_gnttab_valloc(&gnttab_status_vm_area, nr_status);
	if (ret < 0)
		goto err;

	return 0;
err:
	arch_gnttab_vfree(&gnttab_shared_vm_area);
	return -ENOMEM;
}

static int arch_gnttab_setup_e820(void)
{
	int rc;
	unsigned long max_grant_frames = gnttab_max_grant_frames();
	bool found_gnttab = false, found_grant_status = false;

	for (unsigned int i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry entry = e820_table->entries[i];

		if (entry.type != E820_XEN_TYPE_GRANT_TABLE &&
				entry.type != E820_XEN_TYPE_GNTTAB_STATUS)
			continue;

		if ((entry.addr & 0xFFF) != 0 || (entry.size & 0xFFF) != 0) {
				pr_warn("Ignoring misaligned grant e820 entry (%u)\n", entry.type);
				break;
		}

		if (entry.type == E820_XEN_TYPE_GRANT_TABLE) {
			if (PFN_DOWN(entry.size) != max_grant_frames) {
				pr_warn("e820 grant table entry doesn't match grant table size\n");
				break;
			}
		}
		
		switch (entry.type) {
		case E820_XEN_TYPE_GRANT_TABLE:
			if (found_gnttab) {
				pr_warn("Duplicate E820 grant table entry\n");
				break;
			}

			found_gnttab = true;
			rc = gnttab_setup_auto_xlat_frames(entry.addr, PFN_DOWN(entry.size),
					 &xen_auto_xlat_grant_frames);
			break;
		case E820_XEN_TYPE_GNTTAB_STATUS:
			if (found_grant_status) {
				pr_warn("Duplicate E820 grant status entry\n");
				break;
			}
			found_grant_status = true;
			rc = gnttab_setup_auto_xlat_frames(entry.addr, PFN_DOWN(entry.size),
					 &xen_auto_xlat_status_frames);
			break;
		default:
			break;
		}

		if ( rc )
			return rc;
	}

	if ( found_gnttab ) {
		xen_gnttab_auto_mapped = true;
		pr_info("Using E820 provided grant table\n");
	}

	return found_gnttab ? 0 : -ENOENT;
}

#ifdef CONFIG_XEN_PVH
#include <xen/events.h>
#include <xen/xen-ops.h>
static int __init xen_pvh_gnttab_setup(void)
{
	if (!xen_pvh_domain())
		return -ENODEV;

	if (!arch_gnttab_setup_e820())
		return 0;

	xen_auto_xlat_grant_frames.count = gnttab_max_grant_frames();

	return xen_xlate_map_ballooned_pages(&xen_auto_xlat_grant_frames.pfn,
							 &xen_auto_xlat_grant_frames.vaddr,
							 xen_auto_xlat_grant_frames.count);
}
/* Call it _before_ __gnttab_init as we need to initialize the
 * xen_auto_xlat_grant_frames first. */
core_initcall(xen_pvh_gnttab_setup);
#endif
