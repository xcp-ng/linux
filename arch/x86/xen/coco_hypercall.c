// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/spinlock.h>

#include <asm/mem_encrypt.h>
#include <asm/page_types.h>
#include <asm/page.h>

static uint8_t hypercall_buffer[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
static spinlock_t hypercall_lock;
static phys_addr_t base_addr;
static size_t offset;

int __init xen_coco_hypercall_init(void)
{
  memset(hypercall_buffer, 0, PAGE_SIZE);
  base_addr = __pa(hypercall_buffer);
  offset = 0;
	spin_lock_init(&hypercall_lock);

  return early_set_memory_decrypted((unsigned long)hypercall_buffer, PAGE_SIZE);
}

void xen_coco_hypercall_begin(void)
{
	spin_lock(&hypercall_lock);
  BUG_ON(offset);
}

void xen_coco_hypercall_end(void)
{
	spin_unlock(&hypercall_lock);
  offset = 0;
}

phys_addr_t xen_coco_hypercall_handle_prepare(void *buffer, size_t size)
{
  if ( offset + size >= PAGE_SIZE )
    return 0;

  void *hbuffer = hypercall_buffer + offset;
  memcpy(hbuffer, buffer, size);
  offset += size;

  return base_addr + offset;
}

void xen_coco_hypercall_handle_copyback(void *buffer, phys_addr_t handle, size_t size)
{
  // Check bounds.
  BUG_ON(handle < base_addr);
  BUG_ON((handle + size) >= (base_addr + PAGE_SIZE));

  size_t handle_pos = handle - base_addr;
  void *hbuffer = hypercall_buffer + handle_pos;

  memcpy(buffer, hbuffer, size);
}