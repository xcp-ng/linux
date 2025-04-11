// SPDX-License-Identifier: GPL-2.0-only
/*
 * Xen grant page pool. Preallocated pool of memory pages with attached grant references
 * that can be used for bounce buffering and persistent grants.
 *
 * Copyright (c) 2025, Teddy Astie <teddy.astie@vates.tech>
 */

#ifndef _XEN_GRANT_POOL_H
#define _XEN_GRANT_POOL_H

#include <linux/stddef.h>

#include <xen/interface/grant_table.h>

struct grant_pool_chunk {
  size_t nr_pages; /* Number of pages in the pool */
  struct page *pages; /* pages */
  grant_ref_t first; /* first grant references */
  unsigned long *bitmap; /* bitmap of used pages */
};

struct grant_pool {
  size_t nr_chunks;
  struct grant_pool_chunk *chunks;
};

int xen_gntpool_create(struct grant_pool *pool, size_t order);

void xen_gntpool_destroy(struct grant_pool *pool);

struct page *xen_gntpool_alloc_page(struct grant_pool *pool);

grant_ref_t xen_gntpool_get_gref(struct grant_pool *pool, struct page *page);

void xen_gntpool_free_page(struct grant_pool *pool, struct page *page);


#endif /* _XEN_GRANT_POOL_H */