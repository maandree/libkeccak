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
 * Message suffix for SHA3 hashing
 */
#define LIBKECCAK_SHA3_SUFFIX "01"

/**
 * Message suffix for RawSHAKE hashing
 */
#define LIBKECCAK_RAWSHAKE_SUFFIX "11"

/**
 * Message suffix for SHAKE hashing
 */
#define LIBKECCAK_SHAKE_SUFFIX "1111"


/**
 * Invalid `struct libkeccak_spec.bitrate`: non-positive
 */
#define LIBKECCAK_SPEC_ERROR_BITRATE_NONPOSITIVE 1

/**
 * Invalid `struct libkeccak_spec.bitrate`: not a multiple of 8
 */
#define LIBKECCAK_SPEC_ERROR_BITRATE_MOD_8 2

/**
 * Invalid `struct libkeccak_spec.capacity`: non-positive
 */
#define LIBKECCAK_SPEC_ERROR_CAPACITY_NONPOSITIVE 3

/**
 * Invalid `struct libkeccak_spec.capacity`: not a multiple of 8
 */
#define LIBKECCAK_SPEC_ERROR_CAPACITY_MOD_8 4

/**
 * Invalid `struct libkeccak_spec.output`: non-positive
 */
#define LIBKECCAK_SPEC_ERROR_OUTPUT_NONPOSITIVE 5

/**
 * Invalid `struct libkeccak_spec` values: `.bitrate + `.capacity`
 * is greater 1600 which is the largest supported state size
 */
#define LIBKECCAK_SPEC_ERROR_STATE_TOO_LARGE 6

/**
 * Invalid `struct libkeccak_spec` values:
 * `.bitrate + `.capacity` is not a multiple of 25
 */
#define LIBKECCAK_SPEC_ERROR_STATE_MOD_25 7

/**
 * Invalid `struct libkeccak_spec` values: `.bitrate + `.capacity`
 * is a not a 2-potent multiple of 25
 */
#define LIBKECCAK_SPEC_ERROR_WORD_NON_2_POTENT 8

/**
 * Invalid `struct libkeccak_spec` values: `.bitrate + `.capacity`
 * is a not multiple of 100, and thus the word size is not
 * a multiple of 8
 */
#define LIBKECCAK_SPEC_ERROR_WORD_MOD_8 9


/**
 * Value for `struct libkeccak_generalised_spec` member that
 * is used to automatically select the value
 */
#define LIBKECCAK_GENERALISED_SPEC_AUTOMATIC (-65536L)


/**
 * Invalid `struct libkeccak_generalised_spec.state_size`: non-positive
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_NONPOSITIVE 1

/**
 * Invalid `struct libkeccak_generalised_spec.state_size`: larger than 1600
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_TOO_LARGE 2

/**
 * Invalid `struct libkeccak_generalised_spec.state_size`: not a multiple of 25
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_MOD_25 3

/**
 * Invalid `struct libkeccak_generalised_spec.word_size`: non-positive
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_WORD_NONPOSITIVE 4

/**
 * Invalid `struct libkeccak_generalised_spec.word_size`: larger than 1600 / 25
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_WORD_TOO_LARGE 5

/**
 * Invalid `struct libkeccak_generalised_spec.word_size` and
 * `struct libkeccak_generalised_spec.state_size`: `.word_size * 25 != .state_size`
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_WORD_INCOHERENCY 6

/**
 * Invalid `struct libkeccak_generalised_spec.capacity`: non-positive
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_CAPACITY_NONPOSITIVE 7

/**
 * Invalid `struct libkeccak_generalised_spec.capacity`: not a multiple of 8
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_CAPACITY_MOD_8 8

/**
 * Invalid `struct libkeccak_generalised_spec.bitrate`: non-positive
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_BITRATE_NONPOSITIVE 9

/**
 * Invalid `struct libkeccak_generalised_spec.bitrate`: not a multiple of 8
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_BITRATE_MOD_8 10

/**
 * Invalid `struct libkeccak_generalised_spec.output`: non-positive
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_OUTPUT_NONPOSITIVE 11

/**
 * Invalid `struct libkeccak_generalised_spec.state_size`,
 * `struct libkeccak_generalised_spec.bitrate`, and
 * `struct libkeccak_generalised_spec.capacity`:
 * `.bitrate + .capacity != .state_size`
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_BITRATE_CAPACITY_INCONSISTENCY 12


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
 * Generalised datastructure that describes the
 * parameters that should be used when hashing
 */
struct libkeccak_generalised_spec {
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

	/**
	 * The state size
	 */
	long int state_size;

	/**
	 * The word size
	 */
	long int word_size;
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
	int64_t S[25];

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
	int64_t wmod;

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
 * Fill in a `struct libkeccak_spec` for a SHA3-x hashing
 * 
 * @param  spec  The specifications datastructure to fill in
 * @param  x     The value of x in `SHA3-x`, the output size
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
inline void
libkeccak_spec_sha3(struct libkeccak_spec *spec, long int x)
{
	spec->bitrate = 1600 - 2 * x;
	spec->capacity = 2 * x;
	spec->output = x;
}

/**
 * Fill in a `struct libkeccak_spec` for a RawSHAKEx hashing
 * 
 * @param  spec  The specifications datastructure to fill in
 * @param  x     The value of x in `RawSHAKEx`, half the capacity
 * @param  d     The output size
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
inline void
libkeccak_spec_rawshake(struct libkeccak_spec *spec, long int x, long int d)
{
	spec->bitrate = 1600 - 2 * x;
	spec->capacity = 2 * x;
	spec->output = d;
}

/**
 * Fill in a `struct libkeccak_spec` for a SHAKEx hashing
 * 
 * @param  spec:struct libkeccak_spec *  The specifications datastructure to fill in
 * @param  x:long                        The value of x in `SHAKEx`, half the capacity
 * @param  d:long                        The output size
 */
#define libkeccak_spec_shake libkeccak_spec_rawshake

/**
 * Fill in a `struct libkeccak_spec` for a cSHAKEx hashing
 * 
 * @param  spec:struct libkeccak_spec *  The specifications datastructure to fill in
 * @param  x:long                        The value of x in `cSHAKEx`, half the capacity
 * @param  d:long                        The output size
 */
#define libkeccak_spec_cshake libkeccak_spec_rawshake

/**
 * Check for errors in a `struct libkeccak_spec`
 * 
 * @param   spec  The specifications datastructure to check
 * @return        Zero if error free, a `LIBKECCAK_SPEC_ERROR_*` if an error was found
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __warn_unused_result__, __pure__)))
inline int
libkeccak_spec_check(const struct libkeccak_spec *spec)
{
	long int state_size = spec->capacity + spec->bitrate;
	int32_t word_size = (int32_t)(state_size / 25);

	if (spec->bitrate <= 0)  return LIBKECCAK_SPEC_ERROR_BITRATE_NONPOSITIVE;
	if (spec->bitrate % 8)   return LIBKECCAK_SPEC_ERROR_BITRATE_MOD_8;
	if (spec->capacity <= 0) return LIBKECCAK_SPEC_ERROR_CAPACITY_NONPOSITIVE;
	if (spec->capacity % 8)  return LIBKECCAK_SPEC_ERROR_CAPACITY_MOD_8;
	if (spec->output <= 0)   return LIBKECCAK_SPEC_ERROR_OUTPUT_NONPOSITIVE;
	if (state_size > 1600)   return LIBKECCAK_SPEC_ERROR_STATE_TOO_LARGE;
	if (state_size % 25)     return LIBKECCAK_SPEC_ERROR_STATE_MOD_25;
	if (word_size % 8)       return LIBKECCAK_SPEC_ERROR_WORD_MOD_8;

	/* `(x & -x) != x` assumes two's complement, which of course is always
	 * satisfied by GCC, however C99 guarantees that `int32_t` exists,
	 * and it is basically the same thing as `long int`; with one important
	 * difference: it is guaranteed to use two's complement. */
	if ((word_size & -word_size) != word_size)
		return LIBKECCAK_SPEC_ERROR_WORD_NON_2_POTENT;

	return 0;
}

/**
 * Set all specification parameters to automatic
 * 
 * @param  spec  The specification datastructure to fill in
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
inline void
libkeccak_generalised_spec_initialise(struct libkeccak_generalised_spec *spec)
{
	spec->bitrate    = LIBKECCAK_GENERALISED_SPEC_AUTOMATIC;
	spec->capacity   = LIBKECCAK_GENERALISED_SPEC_AUTOMATIC;
	spec->output     = LIBKECCAK_GENERALISED_SPEC_AUTOMATIC;
	spec->state_size = LIBKECCAK_GENERALISED_SPEC_AUTOMATIC;
	spec->word_size  = LIBKECCAK_GENERALISED_SPEC_AUTOMATIC;
}

/**
 * Convert a `struct libkeccak_generalised_spec` to a `struct libkeccak_spec`
 * 
 * @param   spec         The generalised input specifications, will be update with resolved automatic values
 * @param   output_spec  The specification datastructure to fill in
 * @return               Zero if `spec` is valid, a `LIBKECCAK_GENERALISED_SPEC_ERROR_*` if an error was found
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__, __nothrow__)))
int libkeccak_degeneralise_spec(struct libkeccak_generalised_spec *, struct libkeccak_spec *);

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
 * Reset a state according to hashing specifications
 * 
 * @param  state  The state that should be reset
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
inline void
libkeccak_state_reset(struct libkeccak_state *state)
{
	state->mptr = 0;
	memset(state->S, 0, sizeof(state->S));
}

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
 * Wipe data in the state's message wihout freeing any data
 * 
 * @param  state  The state that should be wipe
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__, __nothrow__, __optimize__("-O0"))))
void libkeccak_state_wipe_message(volatile struct libkeccak_state *);

/**
 * Wipe data in the state's sponge wihout freeing any data
 * 
 * @param  state  The state that should be wipe
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__, __nothrow__, __optimize__("-O0"))))
void libkeccak_state_wipe_sponge(volatile struct libkeccak_state *);

/**
 * Wipe sensitive data wihout freeing any data
 * 
 * @param  state  The state that should be wipe
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __optimize__("-O0"))))
void libkeccak_state_wipe(volatile struct libkeccak_state *);

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

/**
 * Wrapper for `libkeccak_state_initialise` that also allocates the states
 * 
 * @param   spec  The specifications for the state
 * @return        The state, `NULL` on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __warn_unused_result__, __malloc__)))
struct libkeccak_state *libkeccak_state_create(const struct libkeccak_spec *);

/**
 * Wrapper for `libkeccak_state_fast_destroy` that also frees the allocation of the state
 * 
 * @param  state  The state that should be freed
 */
inline void
libkeccak_state_fast_free(struct libkeccak_state *state)
{
	libkeccak_state_fast_destroy(state);
	free(state);
}

/**
 * Wrapper for `libkeccak_state_destroy` that also frees the allocation of the state
 * 
 * @param  state  The state that should be freed
 */
LIBKECCAK_GCC_ONLY(__attribute__((__optimize__("-O0"))))
inline void
libkeccak_state_free(volatile struct libkeccak_state *state)
{
#ifdef __GNUC__
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wcast-qual"
#endif
	libkeccak_state_destroy(state);
	free((struct libkeccak_state *)state);
#ifdef __GNUC__
# pragma GCC diagnostic pop
#endif
}

/**
 * Make a copy of a state
 * 
 * @param   dest  The slot for the duplicate, must not be initialised (memory leak otherwise)
 * @param   src   The state to duplicate
 * @return        Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__)))
int libkeccak_state_copy(struct libkeccak_state *restrict, const struct libkeccak_state *restrict);

/**
 * A wrapper for `libkeccak_state_copy` that also allocates the duplicate
 * 
 * @param   src  The state to duplicate
 * @return       The duplicate, `NULL` on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __warn_unused_result__, __malloc__)))
struct libkeccak_state *libkeccak_state_duplicate(const struct libkeccak_state *);

/**
 * Marshal a `struct libkeccak_state` into a buffer
 * 
 * @param   state  The state to marshal
 * @param   data   The output buffer, can be `NULL`
 * @return         The number of bytes stored to `data`
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__(1), __nothrow__)))
size_t libkeccak_state_marshal(const struct libkeccak_state *restrict, void *restrict);

/**
 * Unmarshal a `struct libkeccak_state` from a buffer
 * 
 * @param   state  The slot for the unmarshalled state, must not be
 *                 initialised (memory leak otherwise), can be `NULL`
 * @param   data   The input buffer
 * @return         The number of bytes read from `data`, 0 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__(2))))
size_t libkeccak_state_unmarshal(struct libkeccak_state *restrict, const void *restrict);

/**
 * Create and absorb the initialisation blocks for cSHAKE hashing
 * 
 * @param  state       The hashing state
 * @param  n_text      Function name-string
 * @param  n_len       Byte-length of `n_text` (only whole byte)
 * @param  n_bits      Bit-length of `n_text`, minus `n_len * 8`
 * @param  n_suffix    Bit-string, represented by a NUL-terminated
 *                     string of '1':s and '0's:, making up the part
 *                     after `n_text` of the function-name bit-string;
 *                     `NULL` is treated as the empty string
 * @param  s_text      Customisation-string
 * @param  s_len       Byte-length of `s_text` (only whole byte)
 * @param  s_bits      Bit-length of `s_text`, minus `s_len * 8`
 * @param  s_suffix    Bit-string, represented by a NUL-terminated
 *                     string of '1':s and '0's:, making up the part
 *                     after `s_text` of the customisation bit-string;
 *                     `NULL` is treated as the empty string
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1), __nothrow__)))
void libkeccak_cshake_initialise(struct libkeccak_state *restrict,
                                 const void *, size_t, size_t, const char *,
                                 const void *, size_t, size_t, const char *);

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
 * Get message suffix for cSHAKE hashing
 * 
 * @param   nlen  Whether the function-name bit string is non-empty
 * @param   slen  Whether the customisation bit string is non-empty
 * @return        The message suffix to use
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nothrow__, __warn_unused_result__, __const__, __returns_nonnull__)))
inline const char *
libkeccak_cshake_suffix(size_t nlen, size_t slen)
{
	return (nlen || slen) ? "00" : LIBKECCAK_SHAKE_SUFFIX;
}

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
void libkeccak_fast_squeeze(register struct libkeccak_state *, register long int);

/**
 * Squeeze out another digest
 * 
 * @param  state    The hashing state
 * @param  hashsum  Output parameter for the hashsum
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
void libkeccak_squeeze(register struct libkeccak_state *restrict, register void *restrict);

/**
 * Convert a binary hashsum to lower case hexadecimal representation
 * 
 * @param  output   Output array, should have an allocation size of at least `2 * n + 1`
 * @param  hashsum  The hashsum to convert
 * @param  n        The size of `hashsum`
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__, __nothrow__)))
void libkeccak_behex_lower(char *restrict, const void *restrict, size_t);

/**
 * Convert a binary hashsum to upper case hexadecimal representation
 * 
 * @param  output   Output array, should have an allocation size of at least `2 * n + 1`
 * @param  hashsum  The hashsum to convert
 * @param  n        The size of `hashsum`
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__, __nothrow__)))
void libkeccak_behex_upper(char *restrict, const void *restrict, size_t);

/**
 * Convert a hexadecimal hashsum (both lower case, upper
 * case and mixed is supported) to binary representation
 * 
 * @param  output   Output array, should have an allocation size of at least `strlen(hashsum) / 2`
 * @param  hashsum  The hashsum to convert
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__, __nothrow__)))
void libkeccak_unhex(void *restrict, const char *restrict);

/**
 * Calculate a Keccak-family hashsum of a file,
 * the content of the file is assumed non-sensitive
 * 
 * @param   fd       The file descriptor of the file to hash
 * @param   state    The hashing state, should not be initialised unless
 *                   `spec` is `NULL` (memory leak otherwise)
 * @param   spec     Specifications for the hashing algorithm; or `NULL`
 *                   if `spec` is already initialised
 * @param   spec     Specifications for the hashing algorithm
 * @param   suffix   The data suffix, see `libkeccak_digest`
 * @param   hashsum  Output array for the hashsum, have an allocation size of
 *                   at least `((spec->output + 7) / 8) * sizeof(char)`, may be `NULL`
 * @return           Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(2))))
int libkeccak_generalised_sum_fd(int, struct libkeccak_state *restrict, const struct libkeccak_spec *restrict,
                                 const char *restrict, void *restrict);

/**
 * Calculate the Keccak hashsum of a file,
 * the content of the file is assumed non-sensitive
 * 
 * @param   fd       The file descriptor of the file to hash
 * @param   state    The hashing state, should not be initialised (memory leak otherwise)
 * @param   spec     Specifications for the hashing algorithm
 * @param   hashsum  Output array for the hashsum, have an allocation size of
 *                   at least `((spec->output + 7) / 8) * sizeof(char)`, may be `NULL`
 * @return           Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(2, 3), __artificial__)))
inline int
libkeccak_keccaksum_fd(int fd, struct libkeccak_state *restrict state,
                       const struct libkeccak_spec *restrict spec, void *restrict hashsum)
{
	return libkeccak_generalised_sum_fd(fd, state, spec, NULL, hashsum);
}

/**
 * Calculate the SHA3 hashsum of a file,
 * the content of the file is assumed non-sensitive
 * 
 * @param   fd       The file descriptor of the file to hash
 * @param   state    The hashing state, should not be initialised (memory leak otherwise)
 * @param   output   The output size parameter for the hashing algorithm
 * @param   hashsum  Output array for the hashsum, have an allocation size of
 *                   at least `((output + 7) / 8) * sizeof(char)`, may be `NULL`
 * @return           Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(2), __artificial__)))
inline int
libkeccak_sha3sum_fd(int fd, struct libkeccak_state *restrict state, long output, void *restrict hashsum)
{
	struct libkeccak_spec spec;
	libkeccak_spec_sha3(&spec, output);
	return libkeccak_generalised_sum_fd(fd, state, &spec, LIBKECCAK_SHA3_SUFFIX, hashsum);
}

/**
 * Calculate the RawSHAKE hashsum of a file,
 * the content of the file is assumed non-sensitive
 * 
 * @param   fd            The file descriptor of the file to hash
 * @param   state         The hashing state, should not be initialised (memory leak otherwise)
 * @param   semicapacity  The semicapacity parameter for the hashing algorithm
 * @param   output        The output size parameter for the hashing algorithm
 * @param   hashsum       Output array for the hashsum, have an allocation size of
 *                        at least `((output + 7) / 8) * sizeof(char)`, may be `NULL`
 * @return                Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(2), __artificial__)))
inline int
libkeccak_rawshakesum_fd(int fd, struct libkeccak_state *restrict state, long semicapacity, long output, void *restrict hashsum)
{
	struct libkeccak_spec spec;
	libkeccak_spec_rawshake(&spec, semicapacity, output);
	return libkeccak_generalised_sum_fd(fd, state, &spec, LIBKECCAK_RAWSHAKE_SUFFIX, hashsum);
}

/**
 * Calculate the SHAKE hashsum of a file,
 * the content of the file is assumed non-sensitive
 * 
 * @param   fd            The file descriptor of the file to hash
 * @param   state         The hashing state, should not be initialised (memory leak otherwise)
 * @param   semicapacity  The semicapacity parameter for the hashing algorithm
 * @param   output        The output size parameter for the hashing algorithm
 * @param   hashsum       Output array for the hashsum, have an allocation size of
 *                        at least `((output + 7) / 8) * sizeof(char)`, may be `NULL`
 * @return                Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(2), __artificial__)))
inline int
libkeccak_shakesum_fd(int fd, struct libkeccak_state *restrict state, long semicapacity, long output, void *restrict hashsum)
{
	struct libkeccak_spec spec;
	libkeccak_spec_shake(&spec, semicapacity, output);
	return libkeccak_generalised_sum_fd(fd, state, &spec, LIBKECCAK_SHAKE_SUFFIX, hashsum);
}

/* TODO add libkeccak_cshakesum_fd */


/*
 * The Keccak hash-function, that was selected by NIST as the SHA-3 competition winner,
 * doesn't need this nested approach and can be used to generate a MAC by simply prepending
 * the key to the message. [http://keccak.noekeon.org] HMAC-SHA3-224, HMAC-SHA3-256,
 * HMAC-SHA3-384, and HMAC-SHA3-512 are however approved by NIST.
 */


/**
 * Data structure that describes the state of an HMAC-hashing process
 */
struct libkeccak_hmac_state {
	/**
	 * The key right-padded and XOR:ed with the outer pad
	 */
	unsigned char *restrict key_opad;

	/**
	 * The key right-padded and XOR:ed with the inner pad
	 */
	unsigned char *restrict key_ipad;
	/* Not marshalled, implicitly unmarshalled using `key_opad`. */
	/* Shares allocation with `key_opad`, do not `free`. */

	/**
	 * The length of key, but at least the input block size, in bits
	 */
	size_t key_length;

	/**
	 * The state of the underlaying hash-algorithm
	 */
	struct libkeccak_state sponge;

	/**
	 * Buffer used to temporarily store bit shift message if
	 * `.key_length` is not zero modulus 8
	 */
	unsigned char *restrict buffer;

	/**
	 * The allocation size of `.buffer`
	 */
	size_t buffer_size;

	/**
	 * Part of feed key, message or digest that have not been passed yet
	 */
	unsigned char leftover;

	char _pad[sizeof(void *) - 1];
};


/**
 * Change the HMAC-hashing key on the state
 * 
 * @param   state       The state that should be reset
 * @param   key         The new key
 * @param   key_length  The length of key, in bits
 * @return              Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1))))
int libkeccak_hmac_set_key(struct libkeccak_hmac_state *restrict, const void *restrict, size_t);

/**
 * Initialise an HMAC hashing-state according to hashing specifications
 * 
 * @param   state       The state that should be initialised
 * @param   spec        The specifications for the state
 * @param   key         The key
 * @param   key_length  The length of key, in bits
 * @return              Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__)))
inline int
libkeccak_hmac_initialise(struct libkeccak_hmac_state *restrict state, const struct libkeccak_spec *restrict spec,
                          const void *restrict key, size_t key_length)
{
	if (libkeccak_state_initialise(&state->sponge, spec) < 0)
		return -1;
	if (libkeccak_hmac_set_key(state, key, key_length) < 0) {
		libkeccak_state_destroy(&state->sponge);
		return -1;
	}
	state->leftover = 0;
	state->buffer = NULL;
	state->buffer_size = 0;
	return 0;
}

/**
 * Wrapper for `libkeccak_hmac_initialise` that also allocates the states
 * 
 * @param   spec        The specifications for the state
 * @param   key         The key
 * @param   key_length  The length of key, in bits
 * @return              The state, `NULL` on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __warn_unused_result__, __malloc__)))
inline struct libkeccak_hmac_state *
libkeccak_hmac_create(const struct libkeccak_spec *restrict spec, const void *restrict key, size_t key_length)
{
	struct libkeccak_hmac_state *state = malloc(sizeof(struct libkeccak_hmac_state));
	if (!state || libkeccak_hmac_initialise(state, spec, key, key_length)) {
		free(state);
		return NULL;
	}
	return state;
}

/**
 * Reset an HMAC-hashing state according to hashing specifications,
 * you can choose whether to change the key
 * 
 * @param   state       The state that should be reset
 * @param   key         The new key, `NULL` to keep the old key
 * @param   key_length  The length of key, in bits, ignored if `key == NULL`
 * @return              Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1))))
inline int
libkeccak_hmac_reset(struct libkeccak_hmac_state *restrict state, const void *restrict key, size_t key_length)
{
	libkeccak_state_reset(&state->sponge);
	return key ? libkeccak_hmac_set_key(state, key, key_length) : 0;
}

/**
 * Wipe sensitive data wihout freeing any data
 * 
 * @param  state  The state that should be wipe
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __optimize__("-O0"))))
void libkeccak_hmac_wipe(volatile struct libkeccak_hmac_state *);

/**
 * Release resources allocation for an HMAC hashing-state without wiping sensitive data
 * 
 * @param  state  The state that should be destroyed
 */
inline void
libkeccak_hmac_fast_destroy(struct libkeccak_hmac_state *state)
{
	if (!state)
		return;
	free(state->key_opad);
	state->key_opad = NULL;
	state->key_ipad = NULL;
	state->key_length = 0;
	free(state->buffer);
	state->buffer = NULL;
	state->buffer_size = 0;
}

/**
 * Release resources allocation for an HMAC hasing-state and wipe sensitive data
 * 
 * @param  state  The state that should be destroyed
 */
LIBKECCAK_GCC_ONLY(__attribute__((__optimize__("-O0"))))
inline void
libkeccak_hmac_destroy(volatile struct libkeccak_hmac_state *state)
{
	if (!state)
		return;
	libkeccak_hmac_wipe(state);
	free(state->key_opad);
	state->key_opad = NULL;
	state->key_ipad = NULL;
	state->key_length = 0;
	state->leftover = 0;
	free(state->buffer);
	state->buffer = NULL;
	state->buffer_size = 0;
}

/**
 * Wrapper for `libkeccak_fast_destroy` that also frees the allocation of the state
 * 
 * @param  state  The state that should be freed
 */
inline void
libkeccak_hmac_fast_free(struct libkeccak_hmac_state *state)
{
	libkeccak_hmac_fast_destroy(state);
	free(state);
}

/**
 * Wrapper for `libkeccak_hmac_destroy` that also frees the allocation of the state
 * 
 * @param  state  The state that should be freed
 */
LIBKECCAK_GCC_ONLY(__attribute__((__optimize__("-O0"))))
inline void
libkeccak_hmac_free(volatile struct libkeccak_hmac_state *state)
{
#ifdef __GNUC__
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wcast-qual"
#endif
	libkeccak_hmac_destroy(state);
	free((struct libkeccak_hmac_state *)state);
#ifdef __GNUC__
# pragma GCC diagnostic pop
#endif
}

/**
 * Make a copy of an HMAC hashing-state
 * 
 * @param   dest  The slot for the duplicate, must not be initialised (memory leak otherwise)
 * @param   src   The state to duplicate
 * @return        Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__)))
int libkeccak_hmac_copy(struct libkeccak_hmac_state *restrict, const struct libkeccak_hmac_state *restrict);

/**
 * A wrapper for `libkeccak_hmac_copy` that also allocates the duplicate
 * 
 * @param   src  The state to duplicate
 * @return       The duplicate, `NULL` on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __warn_unused_result__, __malloc__)))
inline struct libkeccak_hmac_state *
libkeccak_hmac_duplicate(const struct libkeccak_hmac_state *src)
{
	struct libkeccak_hmac_state *dest = malloc(sizeof(struct libkeccak_hmac_state));
	if (!dest || libkeccak_hmac_copy(dest, src)) {
		libkeccak_hmac_free(dest);
		return NULL;
	}
	return dest;
}

/**
 * Marshal a `struct libkeccak_hmac_state` into a buffer
 * 
 * @param   state  The state to marshal
 * @param   data   The output buffer, can be `NULL`
 * @return         The number of bytes stored to `data`
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1), __nothrow__)))
inline size_t
libkeccak_hmac_marshal(const struct libkeccak_hmac_state *restrict state, void *restrict data_)
{
	unsigned char *restrict data = data_;
	size_t written = libkeccak_state_marshal(&state->sponge, data);
	if (data) {
		data += written;
#if defined(__clang__)
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wcast-align"
#endif
		*(size_t *)data = state->key_length;
#if defined(__clang__)
# pragma clang diagnostic pop
#endif
		data += sizeof(size_t);
		memcpy(data, state->key_opad, (state->key_length + 7) >> 3);
		data += (state->key_length + 7) >> 3;
		data[0] = (unsigned char)!!state->key_ipad;
		data[1] = state->leftover;
	}
	return written + sizeof(size_t) + ((state->key_length + 7) >> 3) + 2 * sizeof(char);
}

/**
 * Unmarshal a `struct libkeccak_hmac_state` from a buffer
 * 
 * @param   state  The slot for the unmarshalled state, must not be
 *                 initialised (memory leak otherwise), can be `NULL`
 * @param   data   The input buffer
 * @return         The number of bytes read from `data`, 0 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(2))))
size_t libkeccak_hmac_unmarshal(struct libkeccak_hmac_state *restrict, const void *restrict);

/**
 * Absorb more, or the first part, of the message
 * without wiping sensitive data when possible
 * 
 * @param   state   The hashing state
 * @param   msg     The partial message
 * @param   msglen  The length of the partial message, in bytes
 * @return          Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1))))
int libkeccak_hmac_fast_update(struct libkeccak_hmac_state *restrict state, const void *restrict msg, size_t msglen);

/**
 * Absorb more, or the first part, of the message
 * and wipe sensitive data when possible
 * 
 * @param   state   The hashing state
 * @param   msg     The partial message
 * @param   msglen  The length of the partial message, in bytes
 * @return          Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1))))
int libkeccak_hmac_update(struct libkeccak_hmac_state *restrict state, const void *restrict msg, size_t msglen);

/**
 * Absorb the last part of the message and fetch the hash
 * without wiping sensitive data when possible
 * 
 * You may use `&state->sponge` for continued squeezing
 * 
 * @param   state    The hashing state
 * @param   msg      The rest of the message, may be `NULL`, may be modified
 * @param   msglen   The length of the partial message
 * @param   bits     The number of bits at the end of the message not covered by `msglen`
 * @param   suffix   The suffix concatenate to the message, only '1':s and '0':s, and NUL-termination
 * @param   hashsum  Output parameter for the hashsum, may be `NULL`
 * @return           Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1))))
int libkeccak_hmac_fast_digest(struct libkeccak_hmac_state *restrict state, const void *restrict msg, size_t msglen,
                               size_t bits, const char *restrict suffix, void *restrict hashsum);

/**
 * Absorb the last part of the message and fetch the hash
 * and wipe sensitive data when possible
 * 
 * You may use `&state->sponge` for continued squeezing
 * 
 * @param   state    The hashing state
 * @param   msg      The rest of the message, may be `NULL`, may be modified
 * @param   msglen   The length of the partial message
 * @param   bits     The number of bits at the end of the message not covered by `msglen`
 * @param   suffix   The suffix concatenate to the message, only '1':s and '0':s, and NUL-termination
 * @param   hashsum  Output parameter for the hashsum, may be `NULL`
 * @return           Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1))))
int libkeccak_hmac_digest(struct libkeccak_hmac_state *restrict state, const void *restrict msg, size_t msglen,
                          size_t bits, const char *restrict suffix, void *restrict hashsum);


#include "libkeccak-legacy.h"


#if defined(__clang__)
# pragma clang diagnostic pop
#endif

#endif
