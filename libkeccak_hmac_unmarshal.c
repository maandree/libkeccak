/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Unmarshal a `struct libkeccak_hmac_state` from a buffer
 * 
 * @param   state  The slot for the unmarshalled state, must not be initialised (memory leak otherwise)
 * @param   data   The input buffer
 * @return         The number of bytes read from `data`, 0 on error
 */
size_t
libkeccak_hmac_unmarshal(struct libkeccak_hmac_state *restrict state, const void *restrict data_)
{
	const unsigned char *restrict data = data_;
	size_t parsed, size, i;

	state->key_opad = NULL;
	state->key_ipad = NULL;

	parsed = libkeccak_state_unmarshal(&state->sponge, data);
	if (parsed == 0)
		return 0;

	data += parsed / sizeof(char);
	state->key_length = *(const size_t *)data;
	data += sizeof(size_t) / sizeof(char);
	size = (state->key_length + 7) >> 3;

	state->key_opad = malloc(2 * size);
	if (!state->key_opad) {
		libkeccak_state_destroy(&state->sponge);
		return 0;
	}
	memcpy(state->key_opad, data, size);
	data += size / sizeof(char);

	if (data[0]) {
		state->key_ipad = state->key_opad + size / sizeof(char);
		memcpy(state->key_ipad, state->key_opad, size);
		for (i = 0; i < size / sizeof(char); i++)
			state->key_ipad[i] ^= (char)(HMAC_OUTER_PAD ^ HMAC_INNER_PAD);
	}

	state->leftover = data[1];
	state->buffer = NULL;
	state->buffer_size = 0;

	return parsed + sizeof(size_t) + size + 2 * sizeof(char);
}
