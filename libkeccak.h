/* See LICENSE file for copyright and license details. */
#ifndef LIBKECCAK_H
#define LIBKECCAK_H 1


#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


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
 * Invalid `libkeccak_spec_t.bitrate`: non-positive
 */
#define LIBKECCAK_SPEC_ERROR_BITRATE_NONPOSITIVE 1

/**
 * Invalid `libkeccak_spec_t.bitrate`: not a multiple of 8
 */
#define LIBKECCAK_SPEC_ERROR_BITRATE_MOD_8 2

/**
 * Invalid `libkeccak_spec_t.capacity`: non-positive
 */
#define LIBKECCAK_SPEC_ERROR_CAPACITY_NONPOSITIVE 3

/**
 * Invalid `libkeccak_spec_t.capacity`: not a multiple of 8
 */
#define LIBKECCAK_SPEC_ERROR_CAPACITY_MOD_8 4

/**
 * Invalid `libkeccak_spec_t.output`: non-positive
 */
#define LIBKECCAK_SPEC_ERROR_OUTPUT_NONPOSITIVE 5

/**
 * Invalid `libkeccak_spec_t` values: `.bitrate + `.capacity`
 * is greater 1600 which is the largest supported state size
 */
#define LIBKECCAK_SPEC_ERROR_STATE_TOO_LARGE 6

/**
 * Invalid `libkeccak_spec_t` values:
 * `.bitrate + `.capacity` is not a multiple of 25
 */
#define LIBKECCAK_SPEC_ERROR_STATE_MOD_25 7

/**
 * Invalid `libkeccak_spec_t` values: `.bitrate + `.capacity`
 * is a not a 2-potent multiple of 25
 */
#define LIBKECCAK_SPEC_ERROR_WORD_NON_2_POTENT 8

/**
 * Invalid `libkeccak_spec_t` values: `.bitrate + `.capacity`
 * is a not multiple of 100, and thus the word size is not
 * a multiple of 8
 */
#define LIBKECCAK_SPEC_ERROR_WORD_MOD_8 9


/**
 * Value for `libkeccak_generalised_spec_t` member that
 * is used to automatically select the value
 */
#define LIBKECCAK_GENERALISED_SPEC_AUTOMATIC (-65536L)


/**
 * Invalid `libkeccak_generalised_spec_t.state_size`: non-positive
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_NONPOSITIVE 1

/**
 * Invalid `libkeccak_generalised_spec_t.state_size`: larger than 1600
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_TOO_LARGE 2

/**
 * Invalid `libkeccak_generalised_spec_t.state_size`: not a multiple of 25
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_MOD_25 3

/**
 * Invalid `libkeccak_generalised_spec_t.word_size`: non-positive
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_WORD_NONPOSITIVE 4

/**
 * Invalid `libkeccak_generalised_spec_t.word_size`: larger than 1600 / 25
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_WORD_TOO_LARGE 5

/**
 * Invalid `libkeccak_generalised_spec_t.word_size` and
 * `libkeccak_generalised_spec_t.state_size`: `.word_size * 25 != .state_size`
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_WORD_INCOHERENCY 6

/**
 * Invalid `libkeccak_generalised_spec_t.capacity`: non-positive
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_CAPACITY_NONPOSITIVE 7

/**
 * Invalid `libkeccak_generalised_spec_t.capacity`: not a multiple of 8
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_CAPACITY_MOD_8 8

/**
 * Invalid `libkeccak_generalised_spec_t.bitrate`: non-positive
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_BITRATE_NONPOSITIVE 9

/**
 * Invalid `libkeccak_generalised_spec_t.bitrate`: not a multiple of 8
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_BITRATE_MOD_8 10

/**
 * Invalid `libkeccak_generalised_spec_t.output`: non-positive
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_OUTPUT_NONPOSITIVE 11


/**
 * Data structure that describes the parameters
 * that should be used when hashing
 */
typedef struct libkeccak_spec {
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

} libkeccak_spec_t;

/**
 * Generalised datastructure that describes the
 * parameters that should be used when hashing
 */
typedef struct libkeccak_generalised_spec
{
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

} libkeccak_generalised_spec_t;

/**
 * Data structure that describes the state of a hashing process
 * 
 * The `char`-size of the output hashsum is calculated by `(.n + 7) / 8`
 */
typedef struct libkeccak_state {
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
	char *M;

} libkeccak_state_t;


/**
 * Fill in a `libkeccak_spec_t` for a SHA3-x hashing
 * 
 * @param  spec  The specifications datastructure to fill in
 * @param  x     The value of x in `SHA3-x`, the output size
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull, nothrow)))
static inline void
libkeccak_spec_sha3(libkeccak_spec_t *restrict spec, long int x)
{
	spec->bitrate = 1600 - 2 * x;
	spec->capacity = 2 * x;
	spec->output = x;
}

/**
 * Fill in a `libkeccak_spec_t` for a RawSHAKEx hashing
 * 
 * @param  spec  The specifications datastructure to fill in
 * @param  x     The value of x in `RawSHAKEx`, half the capacity
 * @param  d     The output size
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull, nothrow)))
static inline void
libkeccak_spec_rawshake(libkeccak_spec_t *restrict spec, long int x, long int d)
{
	spec->bitrate = 1600 - 2 * x;
	spec->capacity = 2 * x;
	spec->output = d;
}

/**
 * Fill in a `libkeccak_spec_t` for a SHAKEx hashing
 * 
 * @param  spec:libkeccak_spec_t*  The specifications datastructure to fill in
 * @param  x:long                  The value of x in `SHAKEx`, half the capacity
 * @param  d:long                  The output size
 */
#define libkeccak_spec_shake libkeccak_spec_rawshake

/**
 * Check for errors in a `libkeccak_spec_t`
 * 
 * @param   spec  The specifications datastructure to check
 * @return        Zero if error free, a `LIBKECCAK_SPEC_ERROR_*` if an error was found
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull, nothrow, unused, warn_unused_result, pure)))
static inline int
libkeccak_spec_check(const libkeccak_spec_t *restrict spec)
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
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __unused__)))
static inline void
libkeccak_generalised_spec_initialise(libkeccak_generalised_spec_t *restrict spec)
{
	spec->bitrate    = LIBKECCAK_GENERALISED_SPEC_AUTOMATIC;
	spec->capacity   = LIBKECCAK_GENERALISED_SPEC_AUTOMATIC;
	spec->output     = LIBKECCAK_GENERALISED_SPEC_AUTOMATIC;
	spec->state_size = LIBKECCAK_GENERALISED_SPEC_AUTOMATIC;
	spec->word_size  = LIBKECCAK_GENERALISED_SPEC_AUTOMATIC;
}

/**
 * Convert a `libkeccak_generalised_spec_t` to a `libkeccak_spec_t`
 * 
 * @param   spec         The generalised input specifications, will be update with resolved automatic values
 * @param   output_spec  The specification datastructure to fill in
 * @return               Zero if `spec` is valid, a `LIBKECCAK_GENERALISED_SPEC_ERROR_*` if an error was found
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__, __nothrow__)))
int libkeccak_degeneralise_spec(libkeccak_generalised_spec_t *restrict, libkeccak_spec_t *restrict);

/**
 * Initialise a state according to hashing specifications
 * 
 * @param   state  The state that should be initialised
 * @param   spec   The specifications for the state
 * @return         Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__)))
int libkeccak_state_initialise(libkeccak_state_t *restrict, const libkeccak_spec_t *restrict);

/**
 * Reset a state according to hashing specifications
 * 
 * @param  state  The state that should be reset
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __unused__)))
static inline void
libkeccak_state_reset(libkeccak_state_t *restrict state)
{
	state->mptr = 0;
	memset(state->S, 0, sizeof(state->S));
}

/**
 * Release resources allocation for a state without wiping sensitive data
 * 
 * @param  state  The state that should be destroyed
 */
static inline void
libkeccak_state_fast_destroy(libkeccak_state_t *restrict state)
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
void libkeccak_state_wipe_message(volatile libkeccak_state_t *restrict);

/**
 * Wipe data in the state's sponge wihout freeing any data
 * 
 * @param  state  The state that should be wipe
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__, __nothrow__, __optimize__("-O0"))))
void libkeccak_state_wipe_sponge(volatile libkeccak_state_t *restrict);

/**
 * Wipe sensitive data wihout freeing any data
 * 
 * @param  state  The state that should be wipe
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __optimize__("-O0"))))
void libkeccak_state_wipe(volatile libkeccak_state_t *restrict);

/**
 * Release resources allocation for a state and wipe sensitive data
 * 
 * @param  state  The state that should be destroyed
 */
LIBKECCAK_GCC_ONLY(__attribute__((__unused__, __optimize__("-O0"))))
static inline void
libkeccak_state_destroy(volatile libkeccak_state_t *restrict state)
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
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __unused__, __warn_unused_result__, __malloc__)))
static inline libkeccak_state_t *
libkeccak_state_create(const libkeccak_spec_t *restrict spec)
{
	libkeccak_state_t *restrict state = malloc(sizeof(libkeccak_state_t));
	if (!state || libkeccak_state_initialise(state, spec)) {
		free(state);
		return NULL;
	}
	return state;
}

/**
 * Wrapper for `libkeccak_state_fast_destroy` that also frees the allocation of the state
 * 
 * @param  state  The state that should be freed
 */
LIBKECCAK_GCC_ONLY(__attribute__((__unused__)))
static inline void
libkeccak_state_fast_free(libkeccak_state_t *restrict state)
{
	libkeccak_state_fast_destroy(state);
	free(state);
}

/**
 * Wrapper for `libkeccak_state_destroy` that also frees the allocation of the state
 * 
 * @param  state  The state that should be freed
 */
LIBKECCAK_GCC_ONLY(__attribute__((__unused__, __optimize__("-O0"))))
static inline void
libkeccak_state_free(volatile libkeccak_state_t *restrict state)
{
#ifdef __GNUC__
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wcast-qual"
#endif
	libkeccak_state_destroy(state);
	free((libkeccak_state_t *)state);
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
int libkeccak_state_copy(libkeccak_state_t *restrict, const libkeccak_state_t *restrict);

/**
 * A wrapper for `libkeccak_state_copy` that also allocates the duplicate
 * 
 * @param   src  The state to duplicate
 * @return       The duplicate, `NULL` on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __unused__, __warn_unused_result__, __malloc__)))
static inline libkeccak_state_t *
libkeccak_state_duplicate(const libkeccak_state_t *restrict src)
{
	libkeccak_state_t *restrict dest = malloc(sizeof(libkeccak_state_t));
	if (!dest || libkeccak_state_copy(dest, src)) {
		libkeccak_state_free(dest);
		return NULL;
	}
	return dest;
}

/**
 * Calculates the allocation size required for the second argument
 * of `libkeccak_state_marshal` (`char* restrict data)`)
 * 
 * @param   state  The state as it will be marshalled by a subsequent call to `libkeccak_state_marshal`
 * @return         The allocation size needed for the buffer to which the state will be marshalled
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __unused__, __warn_unused_result__, __pure__)))
static inline size_t
libkeccak_state_marshal_size(const libkeccak_state_t *restrict state)
{
	return sizeof(libkeccak_state_t) - sizeof(char *) + state->mptr * sizeof(char);
}

/**
 * Marshal a `libkeccak_state_t` into a buffer
 * 
 * @param   state  The state to marshal
 * @param   data   The output buffer
 * @return         The number of bytes stored to `data`
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__, __nothrow__)))
size_t libkeccak_state_marshal(const libkeccak_state_t *restrict, void *restrict);

/**
 * Unmarshal a `libkeccak_state_t` from a buffer
 * 
 * @param   state  The slot for the unmarshalled state, must not be initialised (memory leak otherwise)
 * @param   data   The input buffer
 * @return         The number of bytes read from `data`, 0 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__)))
size_t libkeccak_state_unmarshal(libkeccak_state_t *restrict, const void *restrict);

/**
 * Gets the number of bytes the `libkeccak_state_t` stored
 * at the beginning of `data` occupies
 * 
 * @param   data  The data buffer
 * @return        The byte size of the stored state
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__, __nothrow__, __warn_unused_result__, __pure__)))
size_t libkeccak_state_unmarshal_skip(const void *restrict);

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
int libkeccak_fast_update(libkeccak_state_t *restrict, const void *restrict, size_t);

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
int libkeccak_update(libkeccak_state_t *restrict, const void *restrict, size_t);

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
int libkeccak_fast_digest(libkeccak_state_t *restrict, const void *restrict, size_t,
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
int libkeccak_digest(libkeccak_state_t *restrict, const void *restrict, size_t,
                     size_t, const char *restrict, void *restrict);

/**
 * Force some rounds of Keccak-f
 * 
 * @param  state  The hashing state
 * @param  times  The number of rounds
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
void libkeccak_simple_squeeze(register libkeccak_state_t *restrict, register long int);

/**
 * Squeeze as much as is needed to get a digest a number of times
 * 
 * @param  state  The hashing state
 * @param  times  The number of digests
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
void libkeccak_fast_squeeze(register libkeccak_state_t *restrict, register long int);

/**
 * Squeeze out another digest
 * 
 * @param  state    The hashing state
 * @param  hashsum  Output parameter for the hashsum
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
void libkeccak_squeeze(register libkeccak_state_t *restrict, register void *restrict);

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
 * @param   state    The hashing state, should not be initialised (memory leak otherwise)
 * @param   spec     Specifications for the hashing algorithm
 * @param   suffix   The data suffix, see `libkeccak_digest`
 * @param   hashsum  Output array for the hashsum, have an allocation size of
 *                   at least `((spec->output + 7) / 8) * sizeof(char)`, may be `NULL`
 * @return           Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(2, 3))))
int libkeccak_generalised_sum_fd(int, libkeccak_state_t *restrict, const libkeccak_spec_t *restrict,
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
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(2, 3), __artificial__, __gnu_inline__)))
static inline int
libkeccak_keccaksum_fd(int fd, libkeccak_state_t *restrict state, const libkeccak_spec_t *restrict spec, void *restrict hashsum)
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
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(2), __artificial__, __gnu_inline__)))
static inline int
libkeccak_sha3sum_fd(int fd, libkeccak_state_t *restrict state, long output, void *restrict hashsum)
{
	libkeccak_spec_t spec;
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
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(2), __artificial__, __gnu_inline__)))
static inline int
libkeccak_rawshakesum_fd(int fd, libkeccak_state_t *restrict state, long semicapacity, long output, void *restrict hashsum)
{
	libkeccak_spec_t spec;
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
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(2), __artificial__, __gnu_inline__)))
static inline int
libkeccak_shakesum_fd(int fd, libkeccak_state_t *restrict state, long semicapacity, long output, void *restrict hashsum)
{
	libkeccak_spec_t spec;
	libkeccak_spec_shake(&spec, semicapacity, output);
	return libkeccak_generalised_sum_fd(fd, state, &spec, LIBKECCAK_SHAKE_SUFFIX, hashsum);
}


/*
 * The Keccak hash-function, that was selected by NIST as the SHA-3 competition winner,
 * doesn't need this nested approach and can be used to generate a MAC by simply prepending
 * the key to the message. [http://keccak.noekeon.org]
 */


/**
 * Datastructure that describes the state of an HMAC-hashing process
 */
typedef struct libkeccak_hmac_state
{
	/**
	 * The key right-padded and XOR:ed with the outer pad
	 */
	char *restrict key_opad;

	/**
	 * The key right-padded and XOR:ed with the inner pad
	 */
	char *restrict key_ipad;
	/* Not marshalled, implicitly unmarshalled using `key_opad`. */
	/* Shares allocation with `key_opad`, do not `free`. */

	/**
	 * The length of key, but at least the input block size, in bits
	 */
	size_t key_length;

	/**
	 * The state of the underlaying hash-algorithm
	 */
	libkeccak_state_t sponge;

	/**
	 * Buffer used to temporarily store bit shift message if
	 * `.key_length` is not zero modulus 8
	 */
	char *restrict buffer;

	/**
	 * The allocation size of `.buffer`
	 */
	size_t buffer_size;

	/**
	 * Part of feed key, message or digest that have not been passed yet
	 */
	char leftover;

	char __pad[sizeof(void *) / sizeof(char) - 1];

} libkeccak_hmac_state_t;


/**
 * Change the HMAC-hashing key on the state
 * 
 * @param   state       The state that should be reset
 * @param   key         The new key
 * @param   key_length  The length of key, in bits
 * @return              Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1))))
int libkeccak_hmac_set_key(libkeccak_hmac_state_t *restrict, const void *restrict, size_t);

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
static inline int
libkeccak_hmac_initialise(libkeccak_hmac_state_t *restrict state, const libkeccak_spec_t *restrict spec,
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
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __unused__, __warn_unused_result__, __malloc__)))
static inline libkeccak_hmac_state_t *
libkeccak_hmac_create(const libkeccak_spec_t *restrict spec, const void *restrict key, size_t key_length)
{
	libkeccak_hmac_state_t *restrict state = malloc(sizeof(libkeccak_hmac_state_t));
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
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1), __unused__)))
static inline int
libkeccak_hmac_reset(libkeccak_hmac_state_t *restrict state, const void *restrict key, size_t key_length)
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
void libkeccak_hmac_wipe(volatile libkeccak_hmac_state_t *restrict);

/**
 * Release resources allocation for an HMAC hashing-state without wiping sensitive data
 * 
 * @param  state  The state that should be destroyed
 */
static inline void
libkeccak_hmac_fast_destroy(libkeccak_hmac_state_t *restrict state)
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
LIBKECCAK_GCC_ONLY(__attribute__((__unused__, __optimize__("-O0"))))
static inline void
libkeccak_hmac_destroy(volatile libkeccak_hmac_state_t *restrict state)
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
LIBKECCAK_GCC_ONLY(__attribute__((__unused__)))
static inline void
libkeccak_hmac_fast_free(libkeccak_hmac_state_t *restrict state)
{
	libkeccak_hmac_fast_destroy(state);
	free(state);
}

/**
 * Wrapper for `libkeccak_hmac_destroy` that also frees the allocation of the state
 * 
 * @param  state  The state that should be freed
 */
LIBKECCAK_GCC_ONLY(__attribute__((__unused__, __optimize__("-O0"))))
static inline void
libkeccak_hmac_free(volatile libkeccak_hmac_state_t *restrict state)
{
#ifdef __GNUC__
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wcast-qual"
#endif
	libkeccak_hmac_destroy(state);
	free((libkeccak_hmac_state_t*)state);
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
int libkeccak_hmac_copy(libkeccak_hmac_state_t *restrict, const libkeccak_hmac_state_t *restrict);

/**
 * A wrapper for `libkeccak_hmac_copy` that also allocates the duplicate
 * 
 * @param   src  The state to duplicate
 * @return       The duplicate, `NULL` on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __unused__, __warn_unused_result__, __malloc__)))
static inline libkeccak_hmac_state_t *
libkeccak_hmac_duplicate(const libkeccak_hmac_state_t *restrict src)
{
	libkeccak_hmac_state_t* restrict dest = malloc(sizeof(libkeccak_hmac_state_t));
	if (!dest || libkeccak_hmac_copy(dest, src))
		return libkeccak_hmac_free(dest), NULL;
	return dest;
}

/**
 * Calculates the allocation size required for the second argument
 * of `libkeccak_hmac_marshal` (`char* restrict data)`)
 * 
 * @param   state  The state as it will be marshalled by a subsequent call to `libkeccak_hamc_marshal`
 * @return         The allocation size needed for the buffer to which the state will be marshalled
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __unused__, __warn_unused_result__, __pure__)))
static inline size_t
libkeccak_hmac_marshal_size(const libkeccak_hmac_state_t *restrict state)
{
	return libkeccak_state_marshal_size(&state->sponge) + sizeof(size_t) +
	       ((state->key_length + 7) >> 3) + 2 * sizeof(char);
}

/**
 * Marshal a `libkeccak_hmac_state_t` into a buffer
 * 
 * @param   state  The state to marshal
 * @param   data   The output buffer
 * @return         The number of bytes stored to `data`
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
static inline size_t
libkeccak_hmac_marshal(const libkeccak_hmac_state_t *restrict state, void *restrict data_)
{
	char *restrict data = data_;
	size_t written = libkeccak_state_marshal(&state->sponge, data);
	data += written / sizeof(char);
	*(size_t *)data = state->key_length;
	data += sizeof(size_t) / sizeof(char);
	memcpy(data, state->key_opad, (state->key_length + 7) >> 3);
	data += ((state->key_length + 7) >> 3) / sizeof(char);
	data[0] = (char)!!state->key_ipad;
	data[1] = state->leftover;
	return written + sizeof(size_t) + ((state->key_length + 7) >> 3) + 2 * sizeof(char);
}

/**
 * Unmarshal a `libkeccak_hmac_state_t` from a buffer
 * 
 * @param   state  The slot for the unmarshalled state, must not be initialised (memory leak otherwise)
 * @param   data   The input buffer
 * @return         The number of bytes read from `data`, 0 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__)))
size_t libkeccak_hmac_unmarshal(libkeccak_hmac_state_t *restrict, const void *restrict);

/**
 * Gets the number of bytes the `libkeccak_hmac_state_t` stored
 * at the beginning of `data` occupies
 * 
 * @param   data  The data buffer
 * @return        The byte size of the stored state
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __warn_unused_result__, __pure__)))
static inline size_t
libkeccak_hmac_unmarshal_skip(const void *restrict data_)
{
	const char *restrict data = data_;
	size_t skip = libkeccak_state_unmarshal_skip(data);
	data += skip / sizeof(char);
	return skip + sizeof(size_t) + *(const size_t *)data + 2 * sizeof(char);
}

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
int libkeccak_hmac_fast_update(libkeccak_hmac_state_t *restrict state, const void *restrict msg, size_t msglen);

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
int libkeccak_hmac_update(libkeccak_hmac_state_t *restrict state, const void *restrict msg, size_t msglen);

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
int libkeccak_hmac_fast_digest(libkeccak_hmac_state_t *restrict state, const void *restrict msg, size_t msglen,
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
int libkeccak_hmac_digest(libkeccak_hmac_state_t *restrict state, const void *restrict msg, size_t msglen,
                          size_t bits, const char *restrict suffix, void *restrict hashsum);


#endif
