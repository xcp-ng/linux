/* SPDX-License-Identifier: GPL-2.0 */
/* Values for NULL algorithms */

#ifndef _CRYPTO_NULL_H
#define _CRYPTO_NULL_H

#define NULL_KEY_SIZE		0
#define NULL_BLOCK_SIZE		1
#define NULL_DIGEST_SIZE	0
#define NULL_IV_SIZE		0

#ifndef __GENKSYMS__
/**
 * Backport of 8d6053984258 ("crypto: null - Remove VLA usage of skcipher")
 * changed the return type from crypto_skcipher to crypto_sync_skcipher,
 * but the later is pretty much an alias to the former, used to know which
 * sub-system are still using Variable Length Arrays stack allocations.
 */
struct crypto_sync_skcipher *crypto_get_default_null_skcipher(void);
#else
struct crypto_skcipher *crypto_get_default_null_skcipher(void);
#endif

void crypto_put_default_null_skcipher(void);

#endif
