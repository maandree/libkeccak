/* See LICENSE file for copyright and license details. */
#define NEED_EXPLICIT_BZERO 1
#include "common.h"


/**
 * Absorb more, or the first part, of the message
 * and wipe sensitive data when possible
 * 
 * @param   state   The hashing state
 * @param   msg_    The partial message
 * @param   msglen  The length of the partial message, in bytes
 * @return          Zero on success, -1 on error
 */
int
libkeccak_hmac_update(struct libkeccak_hmac_state *restrict state, const void *restrict msg_, size_t msglen)
{
	const unsigned char *restrict msg = msg_;
	size_t i;
	int n, cn, r;

	if (state->key_ipad) {
		if (libkeccak_update(&state->sponge, state->key_ipad, state->key_length >> 3) < 0)
			return -1;
		if (state->key_length & 7)
			state->leftover = state->key_ipad[state->key_length >> 3];
		state->key_ipad = NULL;
	}

	if (!msg || !msglen)
		return 0;

	if (!(state->key_length & 7))
		return libkeccak_update(&state->sponge, msg, msglen);

	if (msglen != state->buffer_size) {
		free(state->buffer);
		state->buffer = malloc(state->buffer_size = msglen);
		if (!state->buffer)
			return -1;
	}

	n = (int)(state->key_length & 7);
	cn = 8 - n;
	for (i = 1; i < msglen; i++)
		state->buffer[i] = (unsigned char)((msg[i - 1] >> cn) | (msg[i] << n));
	state->buffer[0] = (unsigned char)((state->leftover & ((1 << n) - 1)) | (msg[0] << n));
	state->leftover = (unsigned char)(msg[msglen - 1] >> cn);

	r = libkeccak_update(&state->sponge, state->buffer, msglen);
	my_explicit_bzero(state->buffer, msglen);
	return r;
}
