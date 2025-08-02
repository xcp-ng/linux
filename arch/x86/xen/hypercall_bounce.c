// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/irqflags.h>
#include <linux/types.h>

#include <asm/mem_encrypt.h>
#include <asm/page_types.h>
#include <asm/page.h>
#include <asm/set_memory.h>

#include <asm/xen/hypercall.h>

#include <xen/interface/xen.h>
#include <xen/interface/sched.h>
#include <xen/interface/xen-mca.h>
#include <xen/interface/hvm/hvm_op.h>
#include <xen/interface/vcpu.h>
#include <xen/interface/xenpmu.h>
#include <xen/interface/memory.h>
#include <xen/interface/grant_table.h>
#include <xen/interface/version.h>
#include <xen/interface/event_channel.h>

#include <asm/xen/fastabi.h>

struct xen_hypercall_bounce_state {
  uint8_t *virt_base;
  phys_addr_t phys_base;
  size_t offset;
  unsigned long irq_flags; /* temporary irq flags during hypercall bounce logic */
};

DEFINE_PER_CPU(struct xen_hypercall_bounce_state, xen_bounce_states);
//static uint8_t __meminitdata early_bounce_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

enum xen_hypercall_vendor xen_fastabi_hypercall_vendor;
bool xen_use_fastabi = false, xen_fastabi_force = false;

void __init xen_hypercall_bounce_init_early(void)
{
  #if 0
  /* Specific early initialization logic */
  struct xen_hypercall_bounce_state *state = this_cpu_ptr(&xen_bounce_states);

  state->phys_base = __pa(early_bounce_page);
  state->virt_base = early_memremap_prot(state->phys_base, PAGE_SIZE, __PAGE_KERNEL_NOENC);
  state->irq_flags = 0;
  state->offset = 0;

  memset(state->virt_base, 0, PAGE_SIZE);
  #endif
}

void __init xen_hypercall_bounce_teardown_early(void)
{
  #if 0
	struct xen_hypercall_bounce_state *state = this_cpu_ptr(&xen_bounce_states);

	early_memunmap(state->virt_base, PAGE_SIZE);
  #endif
}

void xen_hypercall_bounce_init_smp(int cpu)
{
  #if 0
  struct xen_hypercall_bounce_state *state = per_cpu_ptr(&xen_bounce_states, cpu);
  struct page *bounce_page = alloc_page(GFP_KERNEL);

  state->phys_base = page_to_phys(bounce_page);
  state->virt_base = page_to_virt(bounce_page);
  state->irq_flags = 0;
  state->offset = 0;
	
	set_memory_decrypted((unsigned long)state->virt_base, 1);
  memset(state->virt_base, 0, PAGE_SIZE);
  #endif
}

#if 0
static void xen_hypercall_bounce_begin(void)
{
  struct xen_hypercall_bounce_state *state = this_cpu_ptr(&xen_bounce_states);
  
  BUG_ON(!state->phys_base);
  BUG_ON(state->offset);
  local_irq_save(state->irq_flags);
}

static void xen_hypercall_bounce_end(void)
{
  struct xen_hypercall_bounce_state *state = this_cpu_ptr(&xen_bounce_states);
  
  state->offset = 0;
  local_irq_restore(state->irq_flags);
}

static phys_addr_t xen_hypercall_bounce_handle_prepare(void *buffer, size_t len)
{
  struct xen_hypercall_bounce_state *state = this_cpu_ptr(&xen_bounce_states);

  if ( state->offset + len >= PAGE_SIZE )
    return 0;

  void *hbuffer = state->virt_base + state->offset;
  phys_addr_t physaddr = state->phys_base + state->offset;

  memcpy(hbuffer, buffer, len);
  state->offset += len;

  return physaddr;
}

static void xen_hypercall_bounce_handle_writeback(void *buffer, phys_addr_t handle, size_t len)
{
  struct xen_hypercall_bounce_state *state = this_cpu_ptr(&xen_bounce_states);

  // Check bounds.
  BUG_ON(handle < state->phys_base);
  BUG_ON((handle + len) >= (state->phys_base + PAGE_SIZE));

  size_t handle_pos = handle - state->phys_base;
  void *hbuffer = state->virt_base + handle_pos;

  memcpy(buffer, hbuffer, len);
}
#endif