/* See LICENSE file for copyright and license details. */
#include "common.h"


#if defined(__clang__)
# pragma clang diagnostic ignored "-Wcast-align"
#endif


/**
 * Unmarshal a `struct libkeccak_state` from a buffer
 * 
 * @param   state  The slot for the unmarshalled state, must not be
 *                 initialised (memory leak otherwise), can be `NULL`
 * @param   data_  The input buffer
 * @return         The number of bytes read from `data`, 0 on error
 */
size_t
libkeccak_state_unmarshal(struct libkeccak_state *restrict state, const void *restrict data_)
{
#define get(type, var) state->var = *(const type *)data, data += sizeof(type)
	const unsigned char *restrict start = data_;
	const unsigned char *restrict data = start;
	size_t mptr;
	if (!state) {
		data += 7 * sizeof(long int);
		data += 1 * sizeof(int64_t);
		data += sizeof(state->S);
		mptr = *(const size_t *)data;
		data += 2 * sizeof(size_t);
		data += mptr;
		return (size_t)(data - start);
	}
	get(long int, r);
	get(long int, c);
	get(long int, n);
	get(long int, b);
	get(long int, w);
	get(int64_t, wmod);
	get(long int, l);
	get(long int, nr);
	memcpy(state->S, data, sizeof(state->S));
	data += sizeof(state->S);
	get(size_t, mptr);
	get(size_t, mlen);
	if (state->mptr) {
		state->M = malloc(state->mptr * sizeof(char));
		if (!state->M)
			return 0;
		memcpy(state->M, data, state->mptr * sizeof(char));
		data += state->mptr;
	} else {
		state->M = NULL;
	}
	return (size_t)(data - start);
#undef get
}
