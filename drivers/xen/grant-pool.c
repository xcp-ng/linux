// SPDX-License-Identifier: GPL-2.0-only
/*
 * Xen grant page pool. Preallocated pool of memory pages with attached grant references
 * that can be used for bounce buffering and persistent grants.
 *
 * Copyright (c) 2025, Teddy Astie <teddy.astie@vates.tech>
 */
 
#include "linux/slab.h"
#include <linux/minmax.h>
#include <linux/gfp_types.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/bitops.h>
#include <linux/gfp.h>
#include <linux/bug.h>
#include <linux/atomic.h>
#include <asm/set_memory.h>

#include <xen/interface/grant_table.h>

#include <xen/grant_table.h>
#include <xen/grant_pool.h>

#define CHUNK_ORDER 10

static int gntpool_chunk_alloc(struct grant_pool_chunk *chunk, size_t order)
{
  BUG_ON(!chunk);

  int rc = 0;

  chunk->nr_pages = 1 << order;
  
  chunk->bitmap = kvcalloc(BITS_TO_LONGS(chunk->nr_pages), sizeof(long), GFP_KERNEL);
  if (!chunk->bitmap) {
    rc = -ENOMEM;
    goto out;
  }

  chunk->pages = alloc_pages(GFP_KERNEL, order);
  if (!chunk->pages)
    goto out;

  /* Make sure those pages are decrypted/shared */
  set_memory_decrypted((unsigned long)page_to_virt(chunk->pages), chunk->nr_pages);

  if ((rc = gnttab_alloc_grant_reference_seq(chunk->nr_pages, &chunk->first))) {
    set_memory_encrypted((unsigned long)page_to_virt(chunk->pages), chunk->nr_pages);
    goto out;
  }

  return rc;

  out:
  if (chunk->pages)
    __free_pages(chunk->pages, order);

  if (chunk->bitmap)
    kvfree(chunk->bitmap);

  return rc;
}

static void gntpool_chunk_destroy(struct grant_pool_chunk *chunk)
{
  BUG_ON(!chunk);

  gnttab_free_grant_reference_seq(chunk->first, chunk->nr_pages);

  if (chunk->pages)
  {
    __free_pages(chunk->pages, order_base_2(chunk->nr_pages));
    set_memory_encrypted((unsigned long)page_to_virt(chunk->pages), chunk->nr_pages);
  }

  if (chunk->bitmap)
    vfree(chunk->bitmap);
}

static struct page *gntpool_chunk_alloc_page(struct grant_pool_chunk *chunk)
{
  BUG_ON(!chunk);
  unsigned long pos;  

  do {
    pos = find_first_zero_bit(chunk->bitmap, chunk->nr_pages);

    if (pos == chunk->nr_pages)
      return NULL; /* no page left */
  } while (test_and_set_bit(pos, chunk->bitmap));

  return &chunk->pages[pos];
}

static grant_ref_t gntpool_chunk_get_gref(struct grant_pool_chunk *chunk, struct page *page)
{
  /* Sanity checks */
  BUG_ON(!chunk);

  if (page < chunk->pages || page >= (chunk->pages + chunk->nr_pages))
    return 0;

  ptrdiff_t pos = page - chunk->pages;

  /* Grant reference is first grant + page position */
  return chunk->first + pos;
}

static int gntpool_chunk_free_page(struct grant_pool_chunk *chunk, struct page *page)
{
  /* Sanity check */
  BUG_ON(!chunk);
  
  if (page < chunk->pages || page >= (chunk->pages + chunk->nr_pages))
    return -ENOENT;

  ptrdiff_t pos = page - chunk->pages;

  WARN_ON(!test_bit(pos, chunk->bitmap));

  printk("Freeing %lx\n", (unsigned long)page);
  clear_bit(pos, chunk->bitmap);

  return 0;
}

int xen_gntpool_create(struct grant_pool *chunk, size_t order)
{
  size_t count_order = order - CHUNK_ORDER;
  size_t size_order = min(order, CHUNK_ORDER);

  printk("xen_gntpool_create: count_order=%zu, size_order=%zu\n", count_order, size_order);

  chunk->nr_chunks = 1 << count_order;

  chunk->chunks = kvcalloc(chunk->nr_chunks, sizeof(struct grant_pool_chunk *), GFP_KERNEL);
  if (!chunk->chunks)
    return -ENOMEM;

  for (size_t i = 0; i < chunk->nr_chunks; i++)
    WARN_ON(gntpool_chunk_alloc(&chunk->chunks[i], size_order));

  return 0;
}

void xen_gntpool_destroy(struct grant_pool *pool)
{
  for (size_t i = 0; i < pool->nr_chunks; i++)
    gntpool_chunk_destroy(&pool->chunks[i]);
}

struct page *xen_gntpool_alloc_page(struct grant_pool *pool)
{
  for (size_t i = 0; i < pool->nr_chunks; i++) {
    struct page *page = gntpool_chunk_alloc_page(&pool->chunks[i]);

    if (page)
      return page;
  }

  return NULL;
}

void xen_gntpool_free_page(struct grant_pool *pool, struct page *page)
{
  for (size_t i = 0; i < pool->nr_chunks; i++) {
    if (gntpool_chunk_free_page(&pool->chunks[i], page) == 0)
      return;
  }

  WARN(1, "Attempting a free a non-allocated page");
}

grant_ref_t xen_gntpool_get_gref(struct grant_pool *pool, struct page *page)
{
  for (size_t i = 0; i < pool->nr_chunks; i++) {
    grant_ref_t ref = gntpool_chunk_get_gref(&pool->chunks[i], page);

    if (ref)
      return ref;
  }

  return 0;
}
