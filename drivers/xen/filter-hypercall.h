// SPDX-License-Identifier: GPL-2.0-only

#ifndef FILTER_HYPERCALL_H
#define FILTER_HYPERCALL_H

struct filtercall {
	struct multicall_entry mc;
	struct multicall_entry mc_orig;

	/* Used for multicalls */
	struct multicall_entry *kmc_list;
	struct multicall_entry *umc_list;
};

int pre_hypercall(struct filtercall *fc);
int post_hypercall(struct filtercall *fc);

#endif
