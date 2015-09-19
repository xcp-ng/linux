#ifndef _XEN_KEXEC_H
#define _XEN_KEXEC_H

#define KEXEC_CMD_kexec                    0
#define KEXEC_CMD_kexec_get_range          3
typedef struct xen_kexec_exec {
	int type;
} xen_kexec_exec_t;

#define KEXEC_RANGE_MA_CRASH      0 /* machine address and size of crash area */

typedef struct xen_kexec_range {
	int range;
	int nr;
	unsigned long size;
	unsigned long start;
} xen_kexec_range_t;

#endif

