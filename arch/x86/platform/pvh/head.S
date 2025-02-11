/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright C 2016, Oracle and/or its affiliates. All rights reserved.
 */

	.code32
	.text
#define _pa(x)          ((x) - __START_KERNEL_map)

#include <linux/elfnote.h>
#include <linux/init.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/asm.h>
#include <asm/boot.h>
#include <asm/processor-flags.h>
#include <asm/msr.h>
#include <asm/nospec-branch.h>
#include <xen/interface/elfnote.h>

	__HEAD

/*
 * Entry point for PVH guests.
 *
 * Xen ABI specifies the following register state when we come here:
 *
 * - `ebx`: contains the physical memory address where the loader has placed
 *          the boot start info structure.
 * - `cr0`: bit 0 (PE) must be set. All the other writeable bits are cleared.
 * - `cr4`: all bits are cleared.
 * - `cs `: must be a 32-bit read/execute code segment with a base of `0`
 *          and a limit of `0xFFFFFFFF`. The selector value is unspecified.
 * - `ds`, `es`: must be a 32-bit read/write data segment with a base of
 *               `0` and a limit of `0xFFFFFFFF`. The selector values are all
 *               unspecified.
 * - `tr`: must be a 32-bit TSS (active) with a base of '0' and a limit
 *         of '0x67'.
 * - `eflags`: bit 17 (VM) must be cleared. Bit 9 (IF) must be cleared.
 *             Bit 8 (TF) must be cleared. Other bits are all unspecified.
 *
 * All other processor registers and flag bits are unspecified. The OS is in
 * charge of setting up it's own stack, GDT and IDT.
 */

#define PVH_GDT_ENTRY_CS	1
#define PVH_GDT_ENTRY_DS	2
#define PVH_CS_SEL		(PVH_GDT_ENTRY_CS * 8)
#define PVH_DS_SEL		(PVH_GDT_ENTRY_DS * 8)

SYM_CODE_START_LOCAL(pvh_start_xen)
	UNWIND_HINT_END_OF_STACK
	cld

	lgdt (_pa(gdt))

	mov $PVH_DS_SEL,%eax
	mov %eax,%ds
	mov %eax,%es
	mov %eax,%ss

	/* Stash hvm_start_info. */
	mov $_pa(pvh_start_info), %edi
	mov %ebx, %esi
	mov _pa(pvh_start_info_sz), %ecx
	shr $2,%ecx
	rep
	movsl

	mov $_pa(early_stack_end), %esp

#ifdef CONFIG_AMD_MEM_ENCRYPT
	/* Check CPUID highest leaf */
	mov $0x80000000, %eax
	cpuid
	cmp $0x8000001f, %eax
	jb .skip_sev_prepare_pgt

	/* Check for SEV support */
	mov $0x8000001f, %eax
	cpuid
	bt $1, %eax
	jnc .skip_sev_prepare_pgt

	/* Check if SEV is enabled */
	mov $MSR_AMD64_SEV, %ecx
	rdmsr
	bt $MSR_AMD64_SEV_ENABLED_BIT, %eax
	jnc .skip_sev_prepare_pgt
	
	mov %ebx, %ecx
	and $0x3f, %ecx /* Get C-bit position */
	sub $0x20, %ecx
	mov $1, %eax
	shl %cl, %eax

	mov $_pa(init_top_pgt), %esi
	call set_pgtable_cbit

#ifdef CONFIG_X86_5LEVEL
	mov $_pa(level4_kernel_pgt), %esi
	call set_pgtable_cbit

	mov $_pa(level4_ident_pgt), %esi
	call set_pgtable_cbit
#endif

	mov $_pa(level3_ident_pgt), %esi
	call set_pgtable_cbit

	mov $_pa(level3_kernel_pgt), %esi
	call set_pgtable_cbit

	mov $_pa(level2_ident_pgt), %esi
	call set_pgtable_cbit

	mov $_pa(level2_kernel_pgt), %esi
	call set_pgtable_cbit

	mov $_pa(level2_fixmap_pgt), %esi
	call set_pgtable_cbit

	mov $_pa(level1_fixmap_pgt), %esi
	call set_pgtable_cbit

.skip_sev_prepare_pgt:
#endif

	/* Enable PAE mode. */
	mov %cr4, %eax
	orl $X86_CR4_PAE, %eax
	mov %eax, %cr4

#ifdef CONFIG_X86_64
	/* Enable Long mode. */
	mov $MSR_EFER, %ecx
	rdmsr
	btsl $_EFER_LME, %eax
	wrmsr

	/* Enable pre-constructed page tables. */
	mov $_pa(init_top_pgt), %eax
	mov %eax, %cr3
	mov $(X86_CR0_PG | X86_CR0_PE), %eax
	mov %eax, %cr0

	/* Jump to 64-bit mode. */
	ljmp $PVH_CS_SEL, $_pa(1f)

	/* 64-bit entry point. */
	.code64
1:
	/* Set base address in stack canary descriptor. */
	mov $MSR_GS_BASE,%ecx
	mov $_pa(canary), %eax
	xor %edx, %edx
	wrmsr

	call xen_prepare_pvh

	/* startup_64 expects boot_params in %rsi. */
	mov $_pa(pvh_bootparams), %rsi
	mov $_pa(startup_64), %rax
	ANNOTATE_RETPOLINE_SAFE
	jmp *%rax

#else /* CONFIG_X86_64 */

	call mk_early_pgtbl_32

	mov $_pa(initial_page_table), %eax
	mov %eax, %cr3

	mov %cr0, %eax
	or $(X86_CR0_PG | X86_CR0_PE), %eax
	mov %eax, %cr0

	ljmp $PVH_CS_SEL, $1f
1:
	call xen_prepare_pvh
	mov $_pa(pvh_bootparams), %esi

	/* startup_32 doesn't expect paging and PAE to be on. */
	ljmp $PVH_CS_SEL, $_pa(2f)
2:
	mov %cr0, %eax
	and $~X86_CR0_PG, %eax
	mov %eax, %cr0
	mov %cr4, %eax
	and $~X86_CR4_PAE, %eax
	mov %eax, %cr4

	ljmp $PVH_CS_SEL, $_pa(startup_32)
#endif
SYM_CODE_END(pvh_start_xen)

#ifdef CONFIG_AMD_MEM_ENCRYPT
SYM_FUNC_START_LOCAL(set_pgtable_cbit)
	.code32
	mov $512, %ecx
	xor %edx, %edx
.L2:
	testl $_PAGE_PRESENT, 0(%esi,%edx,8)
	jz .L3
	or %eax, 4(%esi,%edx,8)
.L3:
	inc %edx
	loop .L2
	RET
SYM_FUNC_END(set_pgtable_cbit)
#endif

	.section ".init.data","aw"
	.balign 8
SYM_DATA_START_LOCAL(gdt)
	.word gdt_end - gdt_start
	.long _pa(gdt_start)
	.word 0
SYM_DATA_END(gdt)
SYM_DATA_START_LOCAL(gdt_start)
	.quad 0x0000000000000000            /* NULL descriptor */
#ifdef CONFIG_X86_64
	.quad GDT_ENTRY(0xa09a, 0, 0xfffff) /* PVH_CS_SEL */
#else
	.quad GDT_ENTRY(0xc09a, 0, 0xfffff) /* PVH_CS_SEL */
#endif
	.quad GDT_ENTRY(0xc092, 0, 0xfffff) /* PVH_DS_SEL */
SYM_DATA_END_LABEL(gdt_start, SYM_L_LOCAL, gdt_end)

	.balign 16
SYM_DATA_LOCAL(canary, .fill 48, 1, 0)

SYM_DATA_START_LOCAL(early_stack)
	.fill BOOT_STACK_SIZE, 1, 0
SYM_DATA_END_LABEL(early_stack, SYM_L_LOCAL, early_stack_end)

	ELFNOTE(Xen, XEN_ELFNOTE_PHYS32_ENTRY,
	             _ASM_PTR (pvh_start_xen - __START_KERNEL_map))
