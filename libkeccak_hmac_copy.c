/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Make a copy of an HMAC hashing-state
 * 
 * @param   dest  The slot for the duplicate, must not be initialised (memory leak otherwise)
 * @param   src   The state to duplicate
 * @return        Zero on success, -1 on error
 */
int
libkeccak_hmac_copy(struct libkeccak_hmac_state *restrict dest, const struct libkeccak_hmac_state *restrict src)
{
	size_t size;

	dest->key_opad = NULL;
	dest->key_ipad = NULL;

	if (libkeccak_state_copy(&dest->sponge, &src->sponge) < 0)
		return -1;

	dest->key_length = src->key_length;
	dest->leftover = src->leftover;

	size = (src->key_length + 7) >> 3;
	dest->key_opad = malloc(2 * size);
	if (!dest->key_opad) {
		libkeccak_state_destroy(&dest->sponge);
		return -1;
	}
	dest->key_ipad = dest->key_opad + size;

	memcpy(dest->key_opad, src->key_opad, size);
	memcpy(dest->key_ipad, src->key_ipad, size);

	return 0;
}
