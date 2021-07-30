/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Absorb the last part of the message and fetch the hash
 * without wiping sensitive data when possible
 * 
 * You may use `&state->sponge` for continued squeezing
 * 
 * @param   state    The hashing state
 * @param   msg_     The rest of the message, may be `NULL`, may be modified
 * @param   msglen   The length of the partial message
 * @param   bits     The number of bits at the end of the message not covered by `msglen`
 * @param   suffix   The suffix concatenate to the message, only '1':s and '0':s, and NUL-termination
 * @param   hashsum  Output parameter for the hashsum, may be `NULL`
 * @return           Zero on success, -1 on error
 */
int
libkeccak_hmac_fast_digest(struct libkeccak_hmac_state *restrict state, const void *restrict msg_, size_t msglen,
                           size_t bits, const char *restrict suffix, void *restrict hashsum)
{
	const unsigned char *restrict msg = msg_;
	size_t hashsize = (size_t)state->sponge.n >> 3;
	unsigned char *tmp = malloc((size_t)((state->sponge.n + 7) >> 3) * sizeof(char));
	unsigned char leftover[2];
	size_t newlen;

	if (!tmp)
		return -1;

	if (!(state->key_length & 7)) {
		if (libkeccak_fast_digest(&state->sponge, msg, msglen, bits, suffix, tmp) < 0)
			goto fail;
		goto stage_2;
	}

	if (libkeccak_hmac_fast_update(state, msg, msglen) < 0)
		goto fail;
	leftover[0] = state->leftover;
	if (bits) {
		leftover[0] |= (unsigned char)(msg[msglen] >> (state->key_length & 7));
		leftover[1] = (unsigned char)(msg[msglen] << (8 - (state->key_length & 7)));
	}
	newlen = (state->key_length & 7) + bits;
	if (libkeccak_fast_digest(&state->sponge, leftover, newlen >> 3, newlen & 7, suffix, tmp) < 0)
		goto fail;

stage_2:
	bits = state->sponge.n & 7;
	state->key_ipad = state->key_opad;
	if (libkeccak_hmac_fast_update(state, NULL, 0) < 0)
		goto fail;

	if (!(state->key_length & 7)) {
		if (libkeccak_fast_digest(&state->sponge, tmp, hashsize, bits, suffix, hashsum) < 0)
			goto fail;
		goto stage_3;
	}

	if (libkeccak_hmac_fast_update(state, tmp, hashsize) < 0)
		goto fail;
	leftover[0] = state->leftover;
	if (bits) {
		leftover[0] |= (unsigned char)(tmp[hashsize] >> (state->key_length & 7));
		leftover[1] = (unsigned char)(tmp[hashsize] << (8 - (state->key_length & 7)));
	}
	newlen = (state->key_length & 7) + bits;
	if (libkeccak_fast_digest(&state->sponge, leftover, newlen >> 3, newlen & 7, suffix, tmp) < 0)
		goto fail;

stage_3:
	free(tmp);
	return 0;
fail:
	free(tmp);
	return -1;
}
