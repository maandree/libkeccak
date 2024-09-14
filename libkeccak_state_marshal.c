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
#define set(VAR)\
	do {\
		__builtin_memcpy(data, &state->VAR, sizeof(state->VAR));\
		data += sizeof(state->VAR);\
	} while (0)

	unsigned char *restrict start = data_;
	unsigned char *restrict data = start;

	if (!data) {
		return 7 * sizeof(long int) +
		       1 * sizeof(int64_t) +
		       sizeof(state->S) +
		       2 * sizeof(size_t) +
		       state->mptr;
	}

	set(r);
	set(c);
	set(n);
	set(b);
	set(w);
	set(wmod);
	set(l);
	set(nr);
	__builtin_memcpy(data, state->S, sizeof(state->S));
	data += sizeof(state->S);
	set(mptr);
	set(mlen);
	memcpy(data, state->M, state->mptr * sizeof(char));
	data += state->mptr;

	return (size_t)(data - start);

#undef set
}
