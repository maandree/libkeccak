/* See LICENSE file for copyright and license details. */
#include "common.h"


#if defined(__clang__)
# pragma clang diagnostic ignored "-Wcast-align"
#endif


/**
 * Marshal a `struct libkeccak_state` into a buffer
 * 
 * @param   state  The state to marshal
 * @param   data_  The output buffer, can be `NULL`
 * @return         The number of bytes stored to `data`
 */
size_t
libkeccak_state_marshal(const struct libkeccak_state *restrict state, void *restrict data_)
{
#define set(type, var) *(type *)data = state->var, data += sizeof(type)
	unsigned char *restrict start = data_;
	unsigned char *restrict data = start;
	if (!data) {
		return 7 * sizeof(long int) +
		       1 * sizeof(int64_t) +
		       sizeof(state->S) +
		       2 * sizeof(size_t) +
		       state->mptr;
	}
	set(long int, r);
	set(long int, c);
	set(long int, n);
	set(long int, b);
	set(long int, w);
	set(int64_t, wmod);
	set(long int, l);
	set(long int, nr);
	memcpy(data, state->S, sizeof(state->S));
	data += sizeof(state->S);
	set(size_t, mptr);
	set(size_t, mlen);
	memcpy(data, state->M, state->mptr * sizeof(char));
	data += state->mptr;
	return (size_t)(data - start);
#undef set
}
