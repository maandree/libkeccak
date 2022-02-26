/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Wipe sensitive data wihout freeing any data
 * 
 * @param  state  The state that should be wipe
 */
void
libkeccak_hmac_wipe(volatile struct libkeccak_hmac_state *state)
{
	volatile unsigned char *restrict key_pads;
	size_t i, size;

	key_pads = state->key_opad;
	size = 2 * ((state->key_length + 7) >> 3);

	libkeccak_state_wipe(&state->sponge);
	for (i = 0; i < size; i++)
		key_pads[i] = 0;
	state->leftover = 0;
	__builtin_memset(state->buffer, 0, state->buffer_size);
}
