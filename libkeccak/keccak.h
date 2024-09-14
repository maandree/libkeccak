/* See LICENSE file for copyright and license details. */


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
 * Check for errors in a `struct libkeccak_spec`
 * 
 * @param   spec  The specifications datastructure to check
 * @return        Zero if error free, a `LIBKECCAK_SPEC_ERROR_*` if an error was found
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __warn_unused_result__, __pure__)))
inline int
libkeccak_spec_check(const struct libkeccak_spec *spec)
{
	unsigned long int state_size = (unsigned long int)(spec->capacity + spec->bitrate);
	uint32_t word_size = (uint32_t)(state_size / 25U);

	if (spec->bitrate <= 0)  return LIBKECCAK_SPEC_ERROR_BITRATE_NONPOSITIVE;
	if (spec->bitrate % 8)   return LIBKECCAK_SPEC_ERROR_BITRATE_MOD_8;
	if (spec->capacity <= 0) return LIBKECCAK_SPEC_ERROR_CAPACITY_NONPOSITIVE;
	if (spec->capacity % 8)  return LIBKECCAK_SPEC_ERROR_CAPACITY_MOD_8;
	if (spec->output <= 0)   return LIBKECCAK_SPEC_ERROR_OUTPUT_NONPOSITIVE;
	if (state_size > 1600)   return LIBKECCAK_SPEC_ERROR_STATE_TOO_LARGE;
	if (state_size % 25)     return LIBKECCAK_SPEC_ERROR_STATE_MOD_25;
	if (word_size % 8)       return LIBKECCAK_SPEC_ERROR_WORD_MOD_8;

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
