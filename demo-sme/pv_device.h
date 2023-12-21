#ifndef __MYDEVICE_H__
#define __MYDEVICE_H__

#include <xen/interface/io/ring.h>

struct smepv_request {
	char not_used_now;
};

struct smepv_response {
	char msg[32];
};

DEFINE_RING_TYPES(smepv, struct smepv_request,
		  struct smepv_response);
#endif
