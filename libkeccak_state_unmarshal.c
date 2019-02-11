/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Unmarshal a `struct libkeccak_state` from a buffer
 * 
 * @param   state  The slot for the unmarshalled state, must not be initialised (memory leak otherwise)
 * @param   data   The input buffer
 * @return         The number of bytes read from `data`, 0 on error
 */
size_t
libkeccak_state_unmarshal(struct libkeccak_state *restrict state, const void *restrict data_)
{
#define get(type, var) state->var = *((const type *)data), data += sizeof(type) / sizeof(char)
	const unsigned char *restrict data = data_;
	get(long int, r);
	get(long int, c);
	get(long int, n);
	get(long int, b);
	get(long int, w);
	get(int64_t, wmod);
	get(long int, l);
	get(long int, nr);
	memcpy(state->S, data, sizeof(state->S));
	data += sizeof(state->S) / sizeof(char);
	get(size_t, mptr);
	get(size_t, mlen);
	state->M = malloc(state->mptr * sizeof(char));
	if (!state->M)
		return 0;
	memcpy(state->M, data, state->mptr * sizeof(char));
	data += state->mptr;
	return sizeof(struct libkeccak_state) - sizeof(char *) + state->mptr * sizeof(char);
#undef get
}
