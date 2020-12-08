#ifndef _LINUX_SHADOW_VAR_H
#define _LINUX_SHADOW_VAR_H

#include <linux/hashtable.h>
#include <linux/slab.h>

void *shadow_var_alloc(void *obj, char *var, size_t size, gfp_t gfp);
void *shadow_var_get(void *obj, char *var);
void shadow_var_free(void *obj, char *var);

#endif /*_LINUX_SHADOW_VAR_H */
