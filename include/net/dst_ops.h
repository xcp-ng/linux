/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_DST_OPS_H
#define _NET_DST_OPS_H
#include <linux/types.h>
#include <linux/percpu_counter.h>
#include <linux/cache.h>

struct dst_entry;
struct kmem_cachep;
struct net_device;
struct sk_buff;
struct sock;
struct net;

struct dst_ops {
	unsigned short		family;
	unsigned int		gc_thresh;

#ifdef __GENKSYMS__
	/* Kept for genksyms; real return type is void — see 95372b040ae6 */
	int			(*gc)(struct dst_ops *ops);
#else
	void			(*gc)(struct dst_ops *ops);
#endif
	struct dst_entry *	(*check)(struct dst_entry *, __u32 cookie);
	unsigned int		(*default_advmss)(const struct dst_entry *);
	unsigned int		(*mtu)(const struct dst_entry *);
	u32 *			(*cow_metrics)(struct dst_entry *, unsigned long);
	void			(*destroy)(struct dst_entry *);
	void			(*ifdown)(struct dst_entry *,
					  struct net_device *dev, int how);
#ifdef __GENKSYMS__
	/* Kept for genksyms; new signature takes struct sock * — see 051c0bde9f04 */
	struct dst_entry *	(*negative_advice)(struct dst_entry *);
#else
	void			(*negative_advice)(struct sock *sk, struct dst_entry *);
#endif
	void			(*link_failure)(struct sk_buff *);
#ifdef __GENKSYMS__
	/* Kept for genksyms; new signature adds bool confirm_neigh — see 8bf95f28be52 */
	void			(*update_pmtu)(struct dst_entry *dst, struct sock *sk,
					       struct sk_buff *skb, u32 mtu);
#else
	void			(*update_pmtu)(struct dst_entry *dst, struct sock *sk,
					       struct sk_buff *skb, u32 mtu,
					       bool confirm_neigh);
#endif
	void			(*redirect)(struct dst_entry *dst, struct sock *sk,
					    struct sk_buff *skb);
	int			(*local_out)(struct net *net, struct sock *sk, struct sk_buff *skb);
	struct neighbour *	(*neigh_lookup)(const struct dst_entry *dst,
						struct sk_buff *skb,
						const void *daddr);
	void			(*confirm_neigh)(const struct dst_entry *dst,
						 const void *daddr);

	struct kmem_cache	*kmem_cachep;

	struct percpu_counter	pcpuc_entries ____cacheline_aligned_in_smp;
};

#ifndef __GENKSYMS__
#include <linux/build_bug.h>
static inline void kabi_check_dst_ops(void)
{
	BUILD_BUG_ON(sizeof(struct dst_ops) != 192);
	BUILD_BUG_ON(offsetof(struct dst_ops, gc) != 8);
	BUILD_BUG_ON(offsetof(struct dst_ops, negative_advice) != 64);
	BUILD_BUG_ON(offsetof(struct dst_ops, update_pmtu) != 80);
}
#endif

static inline int dst_entries_get_fast(struct dst_ops *dst)
{
	return percpu_counter_read_positive(&dst->pcpuc_entries);
}

static inline int dst_entries_get_slow(struct dst_ops *dst)
{
	return percpu_counter_sum_positive(&dst->pcpuc_entries);
}

#define DST_PERCPU_COUNTER_BATCH 32
static inline void dst_entries_add(struct dst_ops *dst, int val)
{
	percpu_counter_add_batch(&dst->pcpuc_entries, val,
				 DST_PERCPU_COUNTER_BATCH);
}

static inline int dst_entries_init(struct dst_ops *dst)
{
	return percpu_counter_init(&dst->pcpuc_entries, 0, GFP_KERNEL);
}

static inline void dst_entries_destroy(struct dst_ops *dst)
{
	percpu_counter_destroy(&dst->pcpuc_entries);
}

#endif
