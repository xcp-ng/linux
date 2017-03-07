/******************************************************************************
 * domctl.h
 * 
 * Domain management operations. For use by node control stack.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (c) 2002-2003, B Dragovic
 * Copyright (c) 2002-2006, K Fraser
 */

#ifndef __XEN_PUBLIC_DOMCTL_H__
#define __XEN_PUBLIC_DOMCTL_H__

#include "xen.h"
#include "grant_table.h"
//#include "hvm/save.h"

#define XEN_DOMCTL_INTERFACE_VERSION 0x00000010

#if 1
/*
 * NB. xen_domctl.domain is an IN/OUT parameter for this operation.
 * If it is specified as zero, an id is auto-allocated and returned.
 */
/* XEN_DOMCTL_createdomain */
struct xen_domctl_createdomain {
    /* IN parameters */
    uint32_t ssidref;
    xen_domain_handle_t handle;
 /* Is this an HVM guest (as opposed to a PVH or PV guest)? */
#define _XEN_DOMCTL_CDF_hvm_guest     0
#define XEN_DOMCTL_CDF_hvm_guest      (1U<<_XEN_DOMCTL_CDF_hvm_guest)
 /* Use hardware-assisted paging if available? */
#define _XEN_DOMCTL_CDF_hap           1
#define XEN_DOMCTL_CDF_hap            (1U<<_XEN_DOMCTL_CDF_hap)
 /* Should domain memory integrity be verifed by tboot during Sx? */
#define _XEN_DOMCTL_CDF_s3_integrity  2
#define XEN_DOMCTL_CDF_s3_integrity   (1U<<_XEN_DOMCTL_CDF_s3_integrity)
 /* Disable out-of-sync shadow page tables? */
#define _XEN_DOMCTL_CDF_oos_off       3
#define XEN_DOMCTL_CDF_oos_off        (1U<<_XEN_DOMCTL_CDF_oos_off)
 /* Is this a PVH guest (as opposed to an HVM or PV guest)? */
#define _XEN_DOMCTL_CDF_pvh_guest     4
#define XEN_DOMCTL_CDF_pvh_guest      (1U<<_XEN_DOMCTL_CDF_pvh_guest)
    uint32_t flags;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_createdomain);

/* XEN_DOMCTL_getdomaininfo */
struct xen_domctl_getdomaininfo {
    /* OUT variables. */
    domid_t  domain;              /* Also echoed in domctl.domain */
 /* Domain is scheduled to die. */
#define _XEN_DOMINF_dying     0
#define XEN_DOMINF_dying      (1U<<_XEN_DOMINF_dying)
 /* Domain is an HVM guest (as opposed to a PV guest). */
#define _XEN_DOMINF_hvm_guest 1
#define XEN_DOMINF_hvm_guest  (1U<<_XEN_DOMINF_hvm_guest)
 /* The guest OS has shut down. */
#define _XEN_DOMINF_shutdown  2
#define XEN_DOMINF_shutdown   (1U<<_XEN_DOMINF_shutdown)
 /* Currently paused by control software. */
#define _XEN_DOMINF_paused    3
#define XEN_DOMINF_paused     (1U<<_XEN_DOMINF_paused)
 /* Currently blocked pending an event.     */
#define _XEN_DOMINF_blocked   4
#define XEN_DOMINF_blocked    (1U<<_XEN_DOMINF_blocked)
 /* Domain is currently running.            */
#define _XEN_DOMINF_running   5
#define XEN_DOMINF_running    (1U<<_XEN_DOMINF_running)
 /* Being debugged.  */
#define _XEN_DOMINF_debugged  6
#define XEN_DOMINF_debugged   (1U<<_XEN_DOMINF_debugged)
/* domain is PVH */
#define _XEN_DOMINF_pvh_guest 7
#define XEN_DOMINF_pvh_guest  (1U<<_XEN_DOMINF_pvh_guest)
 /* XEN_DOMINF_shutdown guest-supplied code.  */
#define XEN_DOMINF_shutdownmask 255
#define XEN_DOMINF_shutdownshift 16
    uint32_t flags;              /* XEN_DOMINF_* */
    aligned_u64 tot_pages;
    aligned_u64 max_pages;
    aligned_u64 outstanding_pages;
    aligned_u64 shr_pages;
    aligned_u64 paged_pages;
    aligned_u64 shared_info_frame; /* GMFN of shared_info struct */
    aligned_u64 cpu_time;
    uint32_t nr_online_vcpus;    /* Number of VCPUs currently online. */
    uint32_t max_vcpu_id;        /* Maximum VCPUID in use by this domain. */
    uint32_t ssidref;
    xen_domain_handle_t handle;
    uint32_t cpupool;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_getdomaininfo);


/* XEN_DOMCTL_getmemlist */
struct xen_domctl_getmemlist {
    /* IN variables. */
    /* Max entries to write to output buffer. */
    aligned_u64 max_pfns;
    /* Start index in guest's page list. */
    aligned_u64 start_pfn;
    GUEST_HANDLE(uint64_t) buffer;
    /* OUT variables. */
    aligned_u64 num_pfns;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_getmemlist);


/* XEN_DOMCTL_getpageframeinfo */

#define XEN_DOMCTL_PFINFO_LTAB_SHIFT 28
#define XEN_DOMCTL_PFINFO_NOTAB   (0x0U<<28)
#define XEN_DOMCTL_PFINFO_L1TAB   (0x1U<<28)
#define XEN_DOMCTL_PFINFO_L2TAB   (0x2U<<28)
#define XEN_DOMCTL_PFINFO_L3TAB   (0x3U<<28)
#define XEN_DOMCTL_PFINFO_L4TAB   (0x4U<<28)
#define XEN_DOMCTL_PFINFO_LTABTYPE_MASK (0x7U<<28)
#define XEN_DOMCTL_PFINFO_LPINTAB (0x1U<<31)
#define XEN_DOMCTL_PFINFO_XTAB    (0xfU<<28) /* invalid page */
#define XEN_DOMCTL_PFINFO_XALLOC  (0xeU<<28) /* allocate-only page */
#define XEN_DOMCTL_PFINFO_BROKEN  (0xdU<<28) /* broken page */
#define XEN_DOMCTL_PFINFO_LTAB_MASK (0xfU<<28)

struct xen_domctl_getpageframeinfo {
    /* IN variables. */
    aligned_u64 gmfn; /* GMFN to query */
    /* OUT variables. */
    /* Is the page PINNED to a type? */
    uint32_t type;         /* see above type defs */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_getpageframeinfo);


/* XEN_DOMCTL_getpageframeinfo2 */
struct xen_domctl_getpageframeinfo2 {
    /* IN variables. */
    aligned_u64 num;
    /* IN/OUT variables. */
    GUEST_HANDLE(uint32_t) array;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_getpageframeinfo2);

/* XEN_DOMCTL_getpageframeinfo3 */
struct xen_domctl_getpageframeinfo3 {
    /* IN variables. */
    aligned_u64 num;
    /* IN/OUT variables. */
    GUEST_HANDLE(xen_pfn_t) array;
};


/*
 * Control shadow pagetables operation
 */
/* XEN_DOMCTL_shadow_op */

/* Disable shadow mode. */
#define XEN_DOMCTL_SHADOW_OP_OFF         0

/* Enable shadow mode (mode contains ORed XEN_DOMCTL_SHADOW_ENABLE_* flags). */
#define XEN_DOMCTL_SHADOW_OP_ENABLE      32

/* Log-dirty bitmap operations. */
 /* Return the bitmap and clean internal copy for next round. */
#define XEN_DOMCTL_SHADOW_OP_CLEAN       11
 /* Return the bitmap but do not modify internal copy. */
#define XEN_DOMCTL_SHADOW_OP_PEEK        12

/* Memory allocation accessors. */
#define XEN_DOMCTL_SHADOW_OP_GET_ALLOCATION   30
#define XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION   31

/* Legacy enable operations. */
 /* Equiv. to ENABLE with no mode flags. */
#define XEN_DOMCTL_SHADOW_OP_ENABLE_TEST       1
 /* Equiv. to ENABLE with mode flag ENABLE_LOG_DIRTY. */
#define XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY   2
 /* Equiv. to ENABLE with mode flags ENABLE_REFCOUNT and ENABLE_TRANSLATE. */
#define XEN_DOMCTL_SHADOW_OP_ENABLE_TRANSLATE  3

/* Mode flags for XEN_DOMCTL_SHADOW_OP_ENABLE. */
 /*
  * Shadow pagetables are refcounted: guest does not use explicit mmu
  * operations nor write-protect its pagetables.
  */
#define XEN_DOMCTL_SHADOW_ENABLE_REFCOUNT  (1 << 1)
 /*
  * Log pages in a bitmap as they are dirtied.
  * Used for live relocation to determine which pages must be re-sent.
  */
#define XEN_DOMCTL_SHADOW_ENABLE_LOG_DIRTY (1 << 2)
 /*
  * Automatically translate GPFNs into MFNs.
  */
#define XEN_DOMCTL_SHADOW_ENABLE_TRANSLATE (1 << 3)
 /*
  * Xen does not steal virtual address space from the guest.
  * Requires HVM support.
  */
#define XEN_DOMCTL_SHADOW_ENABLE_EXTERNAL  (1 << 4)

struct xen_domctl_shadow_op_stats {
    uint32_t fault_count;
    uint32_t dirty_count;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_shadow_op_stats);

struct xen_domctl_shadow_op {
    /* IN variables. */
    uint32_t       op;       /* XEN_DOMCTL_SHADOW_OP_* */

    /* OP_ENABLE */
    uint32_t       mode;     /* XEN_DOMCTL_SHADOW_ENABLE_* */

    /* OP_GET_ALLOCATION / OP_SET_ALLOCATION */
    uint32_t       mb;       /* Shadow memory allocation in MB */

    /* OP_PEEK / OP_CLEAN */
    GUEST_HANDLE(uchar) dirty_bitmap;
    aligned_u64 pages; /* Size of buffer. Updated with actual size. */
    struct xen_domctl_shadow_op_stats stats;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_shadow_op);


/* XEN_DOMCTL_max_mem */
struct xen_domctl_max_mem {
    /* IN variables. */
    aligned_u64 max_memkb;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_max_mem);


/* XEN_DOMCTL_setvcpucontext */
/* XEN_DOMCTL_getvcpucontext */
struct xen_domctl_vcpucontext {
    uint32_t              vcpu;                  /* IN */
    GUEST_HANDLE(vcpu_guest_context) ctxt; /* IN/OUT */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_vcpucontext);


/* XEN_DOMCTL_getvcpuinfo */
struct xen_domctl_getvcpuinfo {
    /* IN variables. */
    uint32_t vcpu;
    /* OUT variables. */
    uint8_t  online;                  /* currently online (not hotplugged)? */
    uint8_t  blocked;                 /* blocked waiting for an event? */
    uint8_t  running;                 /* currently scheduled on its CPU? */
    aligned_u64 cpu_time;        /* total cpu time consumed (ns) */
    uint32_t cpu;                     /* current mapping   */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_getvcpuinfo);

#if 0
/* Get/set the NUMA node(s) with which the guest has affinity with. */
/* XEN_DOMCTL_setnodeaffinity */
/* XEN_DOMCTL_getnodeaffinity */
struct xen_domctl_nodeaffinity {
    struct xenctl_bitmap nodemap;/* IN */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_nodeaffinity);


/* Get/set which physical cpus a vcpu can execute on. */
/* XEN_DOMCTL_setvcpuaffinity */
/* XEN_DOMCTL_getvcpuaffinity */
struct xen_domctl_vcpuaffinity {
    uint32_t  vcpu;              /* IN */
    struct xenctl_bitmap cpumap; /* IN/OUT */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_vcpuaffinity);
#endif


/* XEN_DOMCTL_max_vcpus */
struct xen_domctl_max_vcpus {
    uint32_t max;           /* maximum number of vcpus */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_max_vcpus);


/* XEN_DOMCTL_scheduler_op */
/* Scheduler types. */
#define XEN_SCHEDULER_SEDF     4
#define XEN_SCHEDULER_CREDIT   5
#define XEN_SCHEDULER_CREDIT2  6
#define XEN_SCHEDULER_ARINC653 7
/* Set or get info? */
#define XEN_DOMCTL_SCHEDOP_putinfo 0
#define XEN_DOMCTL_SCHEDOP_getinfo 1
struct xen_domctl_scheduler_op {
    uint32_t sched_id;  /* XEN_SCHEDULER_* */
    uint32_t cmd;       /* XEN_DOMCTL_SCHEDOP_* */
    union {
        struct xen_domctl_sched_sedf {
            aligned_u64 period;
            aligned_u64 slice;
            aligned_u64 latency;
            uint32_t extratime;
            uint32_t weight;
        } sedf;
        struct xen_domctl_sched_credit {
            uint16_t weight;
            uint16_t cap;
        } credit;
        struct xen_domctl_sched_credit2 {
            uint16_t weight;
        } credit2;
    } u;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_scheduler_op);


/* XEN_DOMCTL_setdomainhandle */
struct xen_domctl_setdomainhandle {
    xen_domain_handle_t handle;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_setdomainhandle);


/* XEN_DOMCTL_setdebugging */
struct xen_domctl_setdebugging {
    uint8_t enable;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_setdebugging);


/* XEN_DOMCTL_irq_permission */
struct xen_domctl_irq_permission {
    uint8_t pirq;
    uint8_t allow_access;    /* flag to specify enable/disable of IRQ access */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_irq_permission);


/* XEN_DOMCTL_iomem_permission */
struct xen_domctl_iomem_permission {
    aligned_u64 first_mfn;/* first page (physical page number) in range */
    aligned_u64 nr_mfns;  /* number of pages in range (>0) */
    uint8_t  allow_access;     /* allow (!0) or deny (0) access to range? */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_iomem_permission);


/* XEN_DOMCTL_ioport_permission */
struct xen_domctl_ioport_permission {
    uint32_t first_port;              /* first port int range */
    uint32_t nr_ports;                /* size of port range */
    uint8_t  allow_access;            /* allow or deny access to range? */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_ioport_permission);


/* XEN_DOMCTL_hypercall_init */
struct xen_domctl_hypercall_init {
    aligned_u64  gmfn;           /* GMFN to be initialised */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_hypercall_init);


/* XEN_DOMCTL_arch_setup */
#define _XEN_DOMAINSETUP_hvm_guest 0
#define XEN_DOMAINSETUP_hvm_guest  (1UL<<_XEN_DOMAINSETUP_hvm_guest)
#define _XEN_DOMAINSETUP_query 1 /* Get parameters (for save)  */
#define XEN_DOMAINSETUP_query  (1UL<<_XEN_DOMAINSETUP_query)
#define _XEN_DOMAINSETUP_sioemu_guest 2
#define XEN_DOMAINSETUP_sioemu_guest  (1UL<<_XEN_DOMAINSETUP_sioemu_guest)
struct xen_domctl_arch_setup {
    aligned_u64 flags;  /* XEN_DOMAINSETUP_* */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_arch_setup);


/* XEN_DOMCTL_settimeoffset */
struct xen_domctl_settimeoffset {
    int32_t  time_offset_seconds; /* applied to domain wallclock time */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_settimeoffset);

/* XEN_DOMCTL_gethvmcontext */
/* XEN_DOMCTL_sethvmcontext */
typedef struct xen_domctl_hvmcontext {
    uint32_t size; /* IN/OUT: size of buffer / bytes filled */
    GUEST_HANDLE(uchar) buffer; /* IN/OUT: data, or call
                                        * gethvmcontext with NULL
                                        * buffer to get size req'd */
} xen_domctl_hvmcontext_t;
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_hvmcontext);


/* XEN_DOMCTL_set_address_size */
/* XEN_DOMCTL_get_address_size */
typedef struct xen_domctl_address_size {
    uint32_t size;
} xen_domctl_address_size_t;
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_address_size);


/* XEN_DOMCTL_real_mode_area */
struct xen_domctl_real_mode_area {
    uint32_t log; /* log2 of Real Mode Area size */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_real_mode_area);


/* XEN_DOMCTL_sendtrigger */
#define XEN_DOMCTL_SENDTRIGGER_NMI    0
#define XEN_DOMCTL_SENDTRIGGER_RESET  1
#define XEN_DOMCTL_SENDTRIGGER_INIT   2
#define XEN_DOMCTL_SENDTRIGGER_POWER  3
#define XEN_DOMCTL_SENDTRIGGER_SLEEP  4
struct xen_domctl_sendtrigger {
    uint32_t  trigger;  /* IN */
    uint32_t  vcpu;     /* IN */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_sendtrigger);


/* Assign PCI device to HVM guest. Sets up IOMMU structures. */
/* XEN_DOMCTL_assign_device */
/* XEN_DOMCTL_test_assign_device */
/* XEN_DOMCTL_deassign_device */
struct xen_domctl_assign_device {
    uint32_t  machine_sbdf;   /* machine PCI ID of assigned device */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_assign_device);

/* Retrieve sibling devices infomation of machine_sbdf */
/* XEN_DOMCTL_get_device_group */
struct xen_domctl_get_device_group {
    uint32_t  machine_sbdf;     /* IN */
    uint32_t  max_sdevs;        /* IN */
    uint32_t  num_sdevs;        /* OUT */
    GUEST_HANDLE(uint32_t)  sdev_array;   /* OUT */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_get_device_group);

/* Pass-through interrupts: bind real irq -> hvm devfn. */
/* XEN_DOMCTL_bind_pt_irq */
/* XEN_DOMCTL_unbind_pt_irq */
typedef enum pt_irq_type_e {
    PT_IRQ_TYPE_PCI,
    PT_IRQ_TYPE_ISA,
    PT_IRQ_TYPE_MSI,
    PT_IRQ_TYPE_MSI_TRANSLATE,
} pt_irq_type_t;
struct xen_domctl_bind_pt_irq {
    uint32_t machine_irq;
    pt_irq_type_t irq_type;
    uint32_t hvm_domid;

    union {
        struct {
            uint8_t isa_irq;
        } isa;
        struct {
            uint8_t bus;
            uint8_t device;
            uint8_t intx;
        } pci;
        struct {
            uint8_t gvec;
            uint32_t gflags;
            aligned_u64 gtable;
        } msi;
    } u;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_bind_pt_irq);


/* Bind machine I/O address range -> HVM address range. */
/* XEN_DOMCTL_memory_mapping */
#define DPCI_ADD_MAPPING         1
#define DPCI_REMOVE_MAPPING      0
struct xen_domctl_memory_mapping {
    aligned_u64 first_gfn; /* first page (hvm guest phys page) in range */
    aligned_u64 first_mfn; /* first page (machine page) in range */
    aligned_u64 nr_mfns;   /* number of pages in range (>0) */
    uint32_t add_mapping;       /* add or remove mapping */
    uint32_t padding;           /* padding for 64-bit aligned structure */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_memory_mapping);


/* Bind machine I/O port range -> HVM I/O port range. */
/* XEN_DOMCTL_ioport_mapping */
struct xen_domctl_ioport_mapping {
    uint32_t first_gport;     /* first guest IO port*/
    uint32_t first_mport;     /* first machine IO port */
    uint32_t nr_ports;        /* size of port range */
    uint32_t add_mapping;     /* add or remove mapping */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_ioport_mapping);


/*
 * Pin caching type of RAM space for x86 HVM domU.
 */
/* XEN_DOMCTL_pin_mem_cacheattr */
/* Caching types: these happen to be the same as x86 MTRR/PAT type codes. */
#define XEN_DOMCTL_MEM_CACHEATTR_UC  0
#define XEN_DOMCTL_MEM_CACHEATTR_WC  1
#define XEN_DOMCTL_MEM_CACHEATTR_WT  4
#define XEN_DOMCTL_MEM_CACHEATTR_WP  5
#define XEN_DOMCTL_MEM_CACHEATTR_WB  6
#define XEN_DOMCTL_MEM_CACHEATTR_UCM 7
struct xen_domctl_pin_mem_cacheattr {
    aligned_u64 start, end;
    uint32_t type; /* XEN_DOMCTL_MEM_CACHEATTR_* */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_pin_mem_cacheattr);


#if 0
/* XEN_DOMCTL_set_ext_vcpucontext */
/* XEN_DOMCTL_get_ext_vcpucontext */
struct xen_domctl_ext_vcpucontext {
    /* IN: VCPU that this call applies to. */
    uint32_t         vcpu;
    /*
     * SET: Size of struct (IN)
     * GET: Size of struct (OUT, up to 128 bytes)
     */
    uint32_t         size;
#if defined(__i386__) || defined(__x86_64__)
    /* SYSCALL from 32-bit mode and SYSENTER callback information. */
    /* NB. SYSCALL from 64-bit mode is contained in vcpu_guest_context_t */
    aligned_u64 syscall32_callback_eip;
    aligned_u64 sysenter_callback_eip;
    uint16_t         syscall32_callback_cs;
    uint16_t         sysenter_callback_cs;
    uint8_t          syscall32_disables_events;
    uint8_t          sysenter_disables_events;
#if defined(__GNUC__)
    union {
        aligned_u64 mcg_cap;
        struct hvm_vmce_vcpu vmce;
    };
#else
    struct hvm_vmce_vcpu vmce;
#endif
#endif
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_ext_vcpucontext);
#endif

/*
 * Set the target domain for a domain
 */
/* XEN_DOMCTL_set_target */
struct xen_domctl_set_target {
    domid_t target;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_set_target);

#if defined(__i386__) || defined(__x86_64__)
# define XEN_CPUID_INPUT_UNUSED  0xFFFFFFFF
/* XEN_DOMCTL_set_cpuid */
struct xen_domctl_cpuid {
  uint32_t input[2];
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_cpuid);
#endif

/*
 * Arranges that if the domain suspends (specifically, if it shuts
 * down with code SHUTDOWN_suspend), this event channel will be
 * notified.
 *
 * This is _instead of_ the usual notification to the global
 * VIRQ_DOM_EXC.  (In most systems that pirq is owned by xenstored.)
 *
 * Only one subscription per domain is possible.  Last subscriber
 * wins; others are silently displaced.
 *
 * NB that contrary to the rather general name, it only applies to
 * domain shutdown with code suspend.  Shutdown for other reasons
 * (including crash), and domain death, are notified to VIRQ_DOM_EXC
 * regardless.
 */
/* XEN_DOMCTL_subscribe */
struct xen_domctl_subscribe {
    uint32_t port; /* IN */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_subscribe);

/*
 * Define the maximum machine address size which should be allocated
 * to a guest.
 */
/* XEN_DOMCTL_set_machine_address_size */
/* XEN_DOMCTL_get_machine_address_size */

/*
 * Do not inject spurious page faults into this domain.
 */
/* XEN_DOMCTL_suppress_spurious_page_faults */

/* XEN_DOMCTL_debug_op */
#define XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF         0
#define XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON          1
struct xen_domctl_debug_op {
    uint32_t op;   /* IN */
    uint32_t vcpu; /* IN */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_debug_op);

/*
 * Request a particular record from the HVM context
 */
/* XEN_DOMCTL_gethvmcontext_partial */
typedef struct xen_domctl_hvmcontext_partial {
    uint32_t type;                      /* IN: Type of record required */
    uint32_t instance;                  /* IN: Instance of that type */
    GUEST_HANDLE(uchar) buffer;  /* OUT: buffer to write record into */
} xen_domctl_hvmcontext_partial_t;
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_hvmcontext_partial);

/* XEN_DOMCTL_disable_migrate */
typedef struct xen_domctl_disable_migrate {
    uint32_t disable; /* IN: 1: disable migration and restore */
} xen_domctl_disable_migrate_t;


/* XEN_DOMCTL_gettscinfo */
/* XEN_DOMCTL_settscinfo */
struct xen_guest_tsc_info {
    uint32_t tsc_mode;
    uint32_t gtsc_khz;
    uint32_t incarnation;
    uint32_t pad;
    aligned_u64 elapsed_nsec;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_guest_tsc_info);
typedef struct xen_domctl_tsc_info {
    GUEST_HANDLE(xen_guest_tsc_info) out_info; /* OUT */
    struct xen_guest_tsc_info info; /* IN */
} xen_domctl_tsc_info_t;

/* XEN_DOMCTL_gdbsx_guestmemio      guest mem io */
struct xen_domctl_gdbsx_memio {
    /* IN */
    aligned_u64 pgd3val;/* optional: init_mm.pgd[3] value */
    aligned_u64 gva;    /* guest virtual address */
    aligned_u64 uva;    /* user buffer virtual address */
    uint32_t         len;    /* number of bytes to read/write */
    uint8_t          gwr;    /* 0 = read from guest. 1 = write to guest */
    /* OUT */
    uint32_t         remain; /* bytes remaining to be copied */
};

/* XEN_DOMCTL_gdbsx_pausevcpu */
/* XEN_DOMCTL_gdbsx_unpausevcpu */
struct xen_domctl_gdbsx_pauseunp_vcpu { /* pause/unpause a vcpu */
    uint32_t         vcpu;         /* which vcpu */
};

/* XEN_DOMCTL_gdbsx_domstatus */
struct xen_domctl_gdbsx_domstatus {
    /* OUT */
    uint8_t          paused;     /* is the domain paused */
    uint32_t         vcpu_id;    /* any vcpu in an event? */
    uint32_t         vcpu_ev;    /* if yes, what event? */
};

/*
 * Memory event operations
 */

/* XEN_DOMCTL_mem_event_op */

/*
 * Domain memory paging
 * Page memory in and out.
 * Domctl interface to set up and tear down the 
 * pager<->hypervisor interface. Use XENMEM_paging_op*
 * to perform per-page operations.
 *
 * The XEN_DOMCTL_MEM_EVENT_OP_PAGING_ENABLE domctl returns several
 * non-standard error codes to indicate why paging could not be enabled:
 * ENODEV - host lacks HAP support (EPT/NPT) or HAP is disabled in guest
 * EMLINK - guest has iommu passthrough enabled
 * EXDEV  - guest has PoD enabled
 * EBUSY  - guest has or had paging enabled, ring buffer still active
 */
#define XEN_DOMCTL_MEM_EVENT_OP_PAGING            1

#define XEN_DOMCTL_MEM_EVENT_OP_PAGING_ENABLE     0
#define XEN_DOMCTL_MEM_EVENT_OP_PAGING_DISABLE    1

/*
 * Access permissions.
 *
 * As with paging, use the domctl for teardown/setup of the
 * helper<->hypervisor interface.
 *
 * There are HVM hypercalls to set the per-page access permissions of every
 * page in a domain.  When one of these permissions--independent, read, 
 * write, and execute--is violated, the VCPU is paused and a memory event 
 * is sent with what happened.  (See public/mem_event.h) .
 *
 * The memory event handler can then resume the VCPU and redo the access 
 * with a XENMEM_access_op_resume hypercall.
 *
 * The XEN_DOMCTL_MEM_EVENT_OP_ACCESS_ENABLE domctl returns several
 * non-standard error codes to indicate why access could not be enabled:
 * ENODEV - host lacks HAP support (EPT/NPT) or HAP is disabled in guest
 * EBUSY  - guest has or had access enabled, ring buffer still active
 */
#define XEN_DOMCTL_MEM_EVENT_OP_ACCESS            2

#define XEN_DOMCTL_MEM_EVENT_OP_ACCESS_ENABLE     0
#define XEN_DOMCTL_MEM_EVENT_OP_ACCESS_DISABLE    1

/*
 * Sharing ENOMEM helper.
 *
 * As with paging, use the domctl for teardown/setup of the
 * helper<->hypervisor interface.
 *
 * If setup, this ring is used to communicate failed allocations
 * in the unshare path. XENMEM_sharing_op_resume is used to wake up
 * vcpus that could not unshare.
 *
 * Note that shring can be turned on (as per the domctl below)
 * *without* this ring being setup.
 */
#define XEN_DOMCTL_MEM_EVENT_OP_SHARING           3

#define XEN_DOMCTL_MEM_EVENT_OP_SHARING_ENABLE    0
#define XEN_DOMCTL_MEM_EVENT_OP_SHARING_DISABLE   1

/* Use for teardown/setup of helper<->hypervisor interface for paging, 
 * access and sharing.*/
struct xen_domctl_mem_event_op {
    uint32_t       op;           /* XEN_DOMCTL_MEM_EVENT_OP_*_* */
    uint32_t       mode;         /* XEN_DOMCTL_MEM_EVENT_OP_* */

    uint32_t port;              /* OUT: event channel for ring */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_mem_event_op);

/*
 * Memory sharing operations
 */
/* XEN_DOMCTL_mem_sharing_op.
 * The CONTROL sub-domctl is used for bringup/teardown. */
#define XEN_DOMCTL_MEM_SHARING_CONTROL          0

struct xen_domctl_mem_sharing_op {
    uint8_t op; /* XEN_DOMCTL_MEM_SHARING_* */

    union {
        uint8_t enable;                   /* CONTROL */
    } u;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_mem_sharing_op);

struct xen_domctl_audit_p2m {
    /* OUT error counts */
    uint64_t orphans;
    uint64_t m2p_bad;
    uint64_t p2m_bad;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_audit_p2m);

struct xen_domctl_set_virq_handler {
    uint32_t virq; /* IN */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_set_virq_handler);

#if defined(__i386__) || defined(__x86_64__)
/* XEN_DOMCTL_setvcpuextstate */
/* XEN_DOMCTL_getvcpuextstate */
struct xen_domctl_vcpuextstate {
    /* IN: VCPU that this call applies to. */
    uint32_t         vcpu;
    /*
     * SET: Ignored.
     * GET: xfeature support mask of struct (IN/OUT)
     * xfeature mask is served as identifications of the saving format
     * so that compatible CPUs can have a check on format to decide
     * whether it can restore.
     */
    aligned_u64         xfeature_mask;
    /*
     * SET: Size of struct (IN)
     * GET: Size of struct (IN/OUT)
     */
    aligned_u64         size;
    GUEST_HANDLE(uint64_t) buffer;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_vcpuextstate);
#endif

/* XEN_DOMCTL_set_access_required: sets whether a memory event listener
 * must be present to handle page access events: if false, the page
 * access will revert to full permissions if no one is listening;
 *  */
struct xen_domctl_set_access_required {
    uint8_t access_required;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_set_access_required);

struct xen_domctl_set_broken_page_p2m {
    aligned_u64 pfn;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_set_broken_page_p2m);

/*
 * XEN_DOMCTL_set_max_evtchn: sets the maximum event channel port
 * number the guest may use.  Use this limit the amount of resources
 * (global mapping space, xenheap) a guest may use for event channels.
 */
struct xen_domctl_set_max_evtchn {
    uint32_t max_port;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_set_max_evtchn);

/*
 * ARM: Clean and invalidate caches associated with given region of
 * guest memory.
 */
struct xen_domctl_cacheflush {
    /* IN: page range to flush. */
    xen_pfn_t start_pfn, nr_pfns;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_cacheflush);

#if defined(__i386__) || defined(__x86_64__)
struct xen_domctl_vcpu_msr {
    uint32_t         index;
    uint32_t         reserved;
    aligned_u64 value;
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_vcpu_msr);

/*
 * XEN_DOMCTL_set_vcpu_msrs / XEN_DOMCTL_get_vcpu_msrs.
 *
 * Input:
 * - A NULL 'msrs' guest handle is a request for the maximum 'msr_count'.
 * - Otherwise, 'msr_count' is the number of entries in 'msrs'.
 *
 * Output for get:
 * - If 'msr_count' is less than the number Xen needs to write, -ENOBUFS shall
 *   be returned and 'msr_count' updated to reflect the intended number.
 * - On success, 'msr_count' shall indicate the number of MSRs written, which
 *   may be less than the maximum if some are not currently used by the vcpu.
 *
 * Output for set:
 * - If Xen encounters an error with a specific MSR, -EINVAL shall be returned
 *   and 'msr_count' shall be set to the offending index, to aid debugging.
 */
struct xen_domctl_vcpu_msrs {
    uint32_t vcpu;                                   /* IN     */
    uint32_t msr_count;                              /* IN/OUT */
    GUEST_HANDLE(xen_domctl_vcpu_msr) msrs; /* IN/OUT */
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_vcpu_msrs);
#endif

/*
 * Return information about the state and running time of a domain.
 * The "domain runstate" is based on the runstates of all the vcpus of the
 * domain (see below).
 * @extra_arg == pointer to domain_runstate_info structure.
 */
struct xen_domctl_runstate_info {
    /* VCPU's current state (RUNSTATE_*). */
    uint32_t      state;
    uint32_t missed_changes;
    /* Number of times we missed an update due to contention */
    /* When was current state entered (system time, ns)? */
    uint64_t state_entry_time;
    /*
     * Time spent in each RUNSTATE_* (ns). The sum of these times is
     * NOT guaranteed not to drift from system time.
     */
    uint64_t time[6];
};
DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_runstate_info);

/* All vcpus are running */
#define DOMAIN_RUNSTATE_full_run           0

/* All vcpus are runnable (i.e., waiting for cpu) */
#define DOMAIN_RUNSTATE_full_contention    1

/* Some vcpus are running, some are runnable */
#define DOMAIN_RUNSTATE_concurrency_hazard 2

/* All vcpus are blocked / offline */
#define DOMAIN_RUNSTATE_blocked            3

/* Some vpcus are running, some are blocked */
#define DOMAIN_RUNSTATE_partial_run        4

/* Some vcpus are runnable, some are blocked */
#define DOMAIN_RUNSTATE_partial_contention 5

struct xen_domctl_corespersocket {
    uint32_t cores_per_socket;
};

DEFINE_GUEST_HANDLE_STRUCT(xen_domctl_corespersocket);
#endif

struct xen_domctl {
    uint32_t cmd;
#define XEN_DOMCTL_createdomain                   1
#define XEN_DOMCTL_destroydomain                  2
#define XEN_DOMCTL_pausedomain                    3
#define XEN_DOMCTL_unpausedomain                  4
#define XEN_DOMCTL_getdomaininfo                  5
#define XEN_DOMCTL_getmemlist                     6
#define XEN_DOMCTL_getpageframeinfo               7
#define XEN_DOMCTL_getpageframeinfo2              8
#define XEN_DOMCTL_setvcpuaffinity                9
#define XEN_DOMCTL_shadow_op                     10
#define XEN_DOMCTL_max_mem                       11
#define XEN_DOMCTL_setvcpucontext                12
#define XEN_DOMCTL_getvcpucontext                13
#define XEN_DOMCTL_getvcpuinfo                   14
#define XEN_DOMCTL_max_vcpus                     15
#define XEN_DOMCTL_scheduler_op                  16
#define XEN_DOMCTL_setdomainhandle               17
#define XEN_DOMCTL_setdebugging                  18
#define XEN_DOMCTL_irq_permission                19
#define XEN_DOMCTL_iomem_permission              20
#define XEN_DOMCTL_ioport_permission             21
#define XEN_DOMCTL_hypercall_init                22
#define XEN_DOMCTL_arch_setup                    23
#define XEN_DOMCTL_settimeoffset                 24
#define XEN_DOMCTL_getvcpuaffinity               25
#define XEN_DOMCTL_real_mode_area                26
#define XEN_DOMCTL_resumedomain                  27
#define XEN_DOMCTL_sendtrigger                   28
#define XEN_DOMCTL_subscribe                     29
#define XEN_DOMCTL_gethvmcontext                 33
#define XEN_DOMCTL_sethvmcontext                 34
#define XEN_DOMCTL_set_address_size              35
#define XEN_DOMCTL_get_address_size              36
#define XEN_DOMCTL_assign_device                 37
#define XEN_DOMCTL_bind_pt_irq                   38
#define XEN_DOMCTL_memory_mapping                39
#define XEN_DOMCTL_ioport_mapping                40
#define XEN_DOMCTL_pin_mem_cacheattr             41
#define XEN_DOMCTL_set_ext_vcpucontext           42
#define XEN_DOMCTL_get_ext_vcpucontext           43
#define XEN_DOMCTL_set_opt_feature               44 /* Obsolete IA64 only */
#define XEN_DOMCTL_test_assign_device            45
#define XEN_DOMCTL_set_target                    46
#define XEN_DOMCTL_deassign_device               47
#define XEN_DOMCTL_unbind_pt_irq                 48
#define XEN_DOMCTL_set_cpuid                     49
#define XEN_DOMCTL_get_device_group              50
#define XEN_DOMCTL_set_machine_address_size      51
#define XEN_DOMCTL_get_machine_address_size      52
#define XEN_DOMCTL_suppress_spurious_page_faults 53
#define XEN_DOMCTL_debug_op                      54
#define XEN_DOMCTL_gethvmcontext_partial         55
#define XEN_DOMCTL_mem_event_op                  56
#define XEN_DOMCTL_mem_sharing_op                57
#define XEN_DOMCTL_disable_migrate               58
#define XEN_DOMCTL_gettscinfo                    59
#define XEN_DOMCTL_settscinfo                    60
#define XEN_DOMCTL_getpageframeinfo3             61
#define XEN_DOMCTL_setvcpuextstate               62
#define XEN_DOMCTL_getvcpuextstate               63
#define XEN_DOMCTL_set_access_required           64
#define XEN_DOMCTL_audit_p2m                     65
#define XEN_DOMCTL_set_virq_handler              66
#define XEN_DOMCTL_set_broken_page_p2m           67
#define XEN_DOMCTL_setnodeaffinity               68
#define XEN_DOMCTL_getnodeaffinity               69
#define XEN_DOMCTL_set_max_evtchn                70
#define XEN_DOMCTL_cacheflush                    71
#define XEN_DOMCTL_get_vcpu_msrs                 72
#define XEN_DOMCTL_set_vcpu_msrs                 73
#define XEN_DOMCTL_get_runstate_info             98
#define XEN_DOMCTL_gdbsx_guestmemio            1000
#define XEN_DOMCTL_gdbsx_pausevcpu             1001
#define XEN_DOMCTL_gdbsx_unpausevcpu           1002
#define XEN_DOMCTL_gdbsx_domstatus             1003
#define XEN_DOMCTL_setcorespersocket           4001
    uint32_t interface_version; /* XEN_DOMCTL_INTERFACE_VERSION */
    domid_t  domain;
    union {
        struct xen_domctl_createdomain      createdomain;
        struct xen_domctl_getdomaininfo     getdomaininfo;
        struct xen_domctl_getmemlist        getmemlist;
        struct xen_domctl_getpageframeinfo  getpageframeinfo;
        struct xen_domctl_getpageframeinfo2 getpageframeinfo2;
        struct xen_domctl_getpageframeinfo3 getpageframeinfo3;
#if 0
        struct xen_domctl_nodeaffinity      nodeaffinity;
        struct xen_domctl_vcpuaffinity      vcpuaffinity;
#endif
        struct xen_domctl_shadow_op         shadow_op;
        struct xen_domctl_max_mem           max_mem;
        struct xen_domctl_vcpucontext       vcpucontext;
        struct xen_domctl_getvcpuinfo       getvcpuinfo;
        struct xen_domctl_max_vcpus         max_vcpus;
        struct xen_domctl_scheduler_op      scheduler_op;
        struct xen_domctl_setdomainhandle   setdomainhandle;
        struct xen_domctl_setdebugging      setdebugging;
        struct xen_domctl_irq_permission    irq_permission;
        struct xen_domctl_iomem_permission  iomem_permission;
        struct xen_domctl_ioport_permission ioport_permission;
        struct xen_domctl_hypercall_init    hypercall_init;
        struct xen_domctl_arch_setup        arch_setup;
        struct xen_domctl_settimeoffset     settimeoffset;
        struct xen_domctl_disable_migrate   disable_migrate;
        struct xen_domctl_tsc_info          tsc_info;
        struct xen_domctl_real_mode_area    real_mode_area;
        struct xen_domctl_hvmcontext        hvmcontext;
        struct xen_domctl_hvmcontext_partial hvmcontext_partial;
        struct xen_domctl_address_size      address_size;
        struct xen_domctl_sendtrigger       sendtrigger;
        struct xen_domctl_get_device_group  get_device_group;
        struct xen_domctl_assign_device     assign_device;
        struct xen_domctl_bind_pt_irq       bind_pt_irq;
        struct xen_domctl_memory_mapping    memory_mapping;
        struct xen_domctl_ioport_mapping    ioport_mapping;
        struct xen_domctl_pin_mem_cacheattr pin_mem_cacheattr;
#if 0
        struct xen_domctl_ext_vcpucontext   ext_vcpucontext;
#endif
        struct xen_domctl_set_target        set_target;
        struct xen_domctl_subscribe         subscribe;
        struct xen_domctl_debug_op          debug_op;
        struct xen_domctl_mem_event_op      mem_event_op;
        struct xen_domctl_mem_sharing_op    mem_sharing_op;
#if defined(__i386__) || defined(__x86_64__)
        struct xen_domctl_cpuid             cpuid;
        struct xen_domctl_vcpuextstate      vcpuextstate;
        struct xen_domctl_vcpu_msrs         vcpu_msrs;
#endif
        struct xen_domctl_set_access_required access_required;
        struct xen_domctl_audit_p2m         audit_p2m;
        struct xen_domctl_set_virq_handler  set_virq_handler;
        struct xen_domctl_set_max_evtchn    set_max_evtchn;
        struct xen_domctl_runstate_info     domain_runstate;
        struct xen_domctl_corespersocket    corespersocket;
        struct xen_domctl_gdbsx_memio       gdbsx_guest_memio;
        struct xen_domctl_set_broken_page_p2m set_broken_page_p2m;
        struct xen_domctl_cacheflush        cacheflush;
        struct xen_domctl_gdbsx_pauseunp_vcpu gdbsx_pauseunp_vcpu;
        struct xen_domctl_gdbsx_domstatus   gdbsx_domstatus;
        uint8_t                             pad[128];
    } u __attribute__((aligned(8)));
};

#endif /* __XEN_PUBLIC_DOMCTL_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
