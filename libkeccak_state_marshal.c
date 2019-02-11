/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Marshal a `struct libkeccak_state` into a buffer
 * 
 * @param   state  The state to marshal
 * @param   data   The output buffer
 * @return         The number of bytes stored to `data`
 */
size_t
libkeccak_state_marshal(const struct libkeccak_state *restrict state, void *restrict data_)
{
#define set(type, var) *((type *)data) = state->var, data += sizeof(type) / sizeof(char)
	unsigned char *restrict data = data_;
	set(long int, r);
	set(long int, c);
	set(long int, n);
	set(long int, b);
	set(long int, w);
	set(int64_t, wmod);
	set(long int, l);
	set(long int, nr);
	memcpy(data, state->S, sizeof(state->S));
	data += sizeof(state->S) / sizeof(char);
	set(size_t, mptr);
	set(size_t, mlen);
	memcpy(data, state->M, state->mptr * sizeof(char));
	data += state->mptr;
	return sizeof(struct libkeccak_state) - sizeof(char *) + state->mptr * sizeof(char);
#undef set
}
