/* See LICENSE file for copyright and license details. */
#ifndef LIBKECCAK_H
#define LIBKECCAK_H 1


#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


#if defined(__clang__)
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wdocumentation"
# pragma clang diagnostic ignored "-Wunknown-attributes"
#endif
#if defined(__GNUC__)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Winline"
#endif


/**
 * Only include some C code if compiling with GCC.
 * 
 * For internal use.
 */
#ifdef __GNUC__
# define LIBKECCAK_GCC_ONLY(x) x
#else
# define LIBKECCAK_GCC_ONLY(x)
#endif


/**
 * Data structure that describes the parameters
 * that should be used when hashing
 */
struct libkeccak_spec {
	/**
	 * The bitrate
	 */
	long int bitrate;

	/**
	 * The capacity
	 */
	long int capacity;

	/**
	 * The output size
	 */
	long int output;
};


/**
 * Data structure that describes the state of a hashing process
 * 
 * The `char`-size of the output hashsum is calculated by `(.n + 7) / 8`
 */
struct libkeccak_state {
	/**
	 * The lanes (state/sponge)
	 */
	union {
		uint64_t w64[25];
		uint32_t w32[25];
		uint16_t w16[25];
		uint_fast8_t w8[25];
	} S;

	/**
	 * The bitrate
	 */
	long int r;

	/**
	 * The capacity
	 */
	long int c;

	/**
	 * The output size
	 */
	long int n;

	/**
	 * The state size
	 */
	long int b;

	/**
	 * The word size
	 */
	long int w;

	/**
	 * The word mask
	 */
	uint64_t wmod;

	/**
	 * ℓ, the binary logarithm of the word size
	 */
	long int l;

	/**
	 * 12 + 2ℓ, the number of rounds
	 */
	long int nr;

	/**
	 * Pointer for `M`
	 */
	size_t mptr;

	/**
	 * Size of `M`
	 */
	size_t mlen;

	/**
	 * Left over water to fill the sponge with at next update
	 */
	unsigned char *M;
};


/**
 * Initialise a state according to hashing specifications
 * 
 * @param   state  The state that should be initialised
 * @param   spec   The specifications for the state
 * @return         Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__)))
int libkeccak_state_initialise(struct libkeccak_state *, const struct libkeccak_spec *);

/**
 * Get the number of bytes that are absorbed during
 * one pass of the absorption phase
 * 
 * @param   state  The hashing state
 * @return         The number of bytes absorbed during one pass
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __warn_unused_result__, __pure__)))
inline size_t
libkeccak_zerocopy_chunksize(struct libkeccak_state *state)
{
	return (size_t)state->r >> 3;
}

/**
 * Absorb more of the message to the Keccak sponge
 * without copying the data to an internal buffer
 * 
 * It is safe run zero-copy functions before non-zero-copy
 * functions for the same state, running zero-copy functions
 * after non-zero-copy functions on the other hand can
 * cause the message to be misread
 * 
 * @param  state   The hashing state
 * @param  msg     The partial message
 * @param  msglen  The length of the partial message; must be a
 *                 multiple of `libkeccak_zerocopy_chunksize(state)`
 *                 (undefined behaviour otherwise)
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
void libkeccak_zerocopy_update(struct libkeccak_state *restrict, const void *restrict, size_t);

/**
 * Absorb more of the message to the Keccak sponge
 * without wiping sensitive data when possible
 * 
 * @param   state   The hashing state
 * @param   msg     The partial message
 * @param   msglen  The length of the partial message
 * @return          Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__)))
int libkeccak_fast_update(struct libkeccak_state *restrict, const void *restrict, size_t);

/**
 * Absorb more of the message to the Keccak sponge
 * and wipe sensitive data when possible
 * 
 * @param   state   The hashing state
 * @param   msg     The partial message
 * @param   msglen  The length of the partial message
 * @return          Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__)))
int libkeccak_update(struct libkeccak_state *restrict, const void *restrict, size_t);

/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * without copying the data to an internal buffer
 * 
 * It is safe run zero-copy functions before non-zero-copy
 * functions for the same state, running zero-copy functions
 * after non-zero-copy functions on the other hand can
 * cause the message to be misread
 * 
 * @param  state    The hashing state
 * @param  msg      The rest of the message; will be edited; extra memory
 *                  shall be allocated such that `suffix` and a 10*1 pad (which
 *                  is at least 2 bits long) can be added in a why the makes it's
 *                  length a multiple of `libkeccak_zerocopy_chunksize(state)`
 * @param  msglen   The length of the partial message
 * @param  bits     The number of bits at the end of the message not covered by `msglen`
 * @param  suffix   The suffix concatenate to the message, only '1':s and '0':s, and NUL-termination
 * @param  hashsum  Output parameter for the hashsum, may be `NULL`
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1, 2))))
void libkeccak_zerocopy_digest(struct libkeccak_state *restrict, void *restrict, size_t,
                               size_t, const char *restrict, void *restrict);

/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * without wiping sensitive data when possible
 * 
 * @param   state    The hashing state
 * @param   msg      The rest of the message, may be `NULL`
 * @param   msglen   The length of the partial message
 * @param   bits     The number of bits at the end of the message not covered by `msglen`
 * @param   suffix   The suffix concatenate to the message, only '1':s and '0':s, and NUL-termination
 * @param   hashsum  Output parameter for the hashsum, may be `NULL`
 * @return           Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1))))
int libkeccak_fast_digest(struct libkeccak_state *restrict, const void *restrict, size_t,
                          size_t, const char *restrict, void *restrict);

/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * and wipe sensitive data when possible
 * 
 * @param   state    The hashing state
 * @param   msg      The rest of the message, may be `NULL`
 * @param   msglen   The length of the partial message
 * @param   bits     The number of bits at the end of the message not covered by `msglen`
 * @param   suffix   The suffix concatenate to the message, only '1':s and '0':s, and NUL-termination
 * @param   hashsum  Output parameter for the hashsum, may be `NULL`
 * @return           Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1))))
int libkeccak_digest(struct libkeccak_state *restrict, const void *restrict, size_t,
                     size_t, const char *restrict, void *restrict);

/**
 * Force some rounds of Keccak-f
 * 
 * @param  state  The hashing state
 * @param  times  The number of rounds
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
void libkeccak_simple_squeeze(register struct libkeccak_state *, register long int);

/**
 * Squeeze as much as is needed to get a digest a number of times
 * 
 * @param  state  The hashing state
 * @param  times  The number of digests
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
inline void
libkeccak_fast_squeeze(register struct libkeccak_state *state, register long int times)
{
	times *= (state->n - 1) / state->r + 1;
	libkeccak_simple_squeeze(state, times);
}

/**
 * Squeeze out another digest
 * 
 * @param  state    The hashing state
 * @param  hashsum  Output parameter for the hashsum
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
void libkeccak_squeeze(register struct libkeccak_state *restrict, register void *restrict);

#include "libkeccak/extra.h"

/**
 * Release resources allocation for a state without wiping sensitive data
 * 
 * @param  state  The state that should be destroyed
 */
inline void
libkeccak_state_fast_destroy(struct libkeccak_state *state)
{
	if (state) {
		free(state->M);
		state->M = NULL;
	}
}

/**
 * Release resources allocation for a state and wipe sensitive data
 * 
 * @param  state  The state that should be destroyed
 */
LIBKECCAK_GCC_ONLY(__attribute__((__optimize__("-O0"))))
inline void
libkeccak_state_destroy(volatile struct libkeccak_state *state)
{
	if (state) {
		libkeccak_state_wipe(state);
		free(state->M);
		state->M = NULL;
	}
}

#include "libkeccak/util.h"
#include "libkeccak/hmac.h"

#include "libkeccak/keccak.h"
#include "libkeccak/sha3.h"
#include "libkeccak/rawshake.h"
#include "libkeccak/shake.h"
#include "libkeccak/cshake.h"

#include "libkeccak/legacy.h"



#if defined(__GNUC__)
# pragma GCC diagnostic pop
#endif
#if defined(__clang__)
# pragma clang diagnostic pop
#endif

#endif
