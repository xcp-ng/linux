// SPDX-License-Identifier: GPL-2.0-only

#ifndef XEN_FILTER_HYPERCALL_H
#define XEN_FILTER_HYPERCALL_H

#ifndef __ASSEMBLY__

struct filtercall {
	struct multicall_entry mc;
	struct multicall_entry mc_orig;

	/* Used for multicalls */
	struct multicall_entry *kmc_list;
	struct multicall_entry *umc_list;
};

int pre_hypercall(struct filtercall *fc);
int post_hypercall(struct filtercall *fc);

#endif /* !__ASSEMBLY__ */

/* Current filter code uses 9.0 XS ABI compatibility */

/* XCP-ng vendor ID */
#define FILTER_VENDOR_XCPNG   (1UL << 31)

#define PRIVCMD_FILTERING_ABI_VERSION \
    (FILTER_VENDOR_XCPNG | _AC(0x90001, UL))

#endif

