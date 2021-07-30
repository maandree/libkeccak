/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Change the HMAC-hashing key on the state
 * 
 * @param   state       The state that should be reset
 * @param   key         The new key
 * @param   key_length  The length of key, in bits
 * @return              Zero on success, -1 on error
 */
int
libkeccak_hmac_set_key(struct libkeccak_hmac_state *restrict state, const void *restrict key, size_t key_length)
{
	size_t i, size, new_key_length, key_bytes;
	unsigned char *old;

	size = (size_t)(state->sponge.r) > key_length ? (size_t)(state->sponge.r) : key_length;
	new_key_length = size;
	size = (size + 7) >> 3;
	key_bytes = (key_length + 7) >> 3;

	if (size != key_bytes) {
		state->key_opad = realloc(old = state->key_opad, 2 * size);
		if (!state->key_opad) {
			state->key_opad = old;
			return -1;
		}
		state->key_ipad = state->key_opad + size;
	}

	memcpy(state->key_opad, key, key_bytes);
	if (key_length & 7)
		state->key_opad[(key_bytes >> 3) - 1] &= (unsigned char)((1 << (key_length & 7)) - 1);

	if ((size_t)(state->sponge.r) > key_length)
		__builtin_memset(state->key_opad + key_bytes, 0, size - key_bytes);

	for (i = 0; i < size; i++) {
		state->key_ipad[i] = state->key_opad[i] ^ HMAC_INNER_PAD;
		state->key_opad[i] ^= HMAC_OUTER_PAD;
	}

	state->key_length = new_key_length;

	return 0;
}
