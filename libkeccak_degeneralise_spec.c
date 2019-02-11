/* See LICENSE file for copyright and license details. */
#include "common.h"


#ifdef __GNUC__
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif

#define deft(v, dv) (have_##v ? v : (dv))


/**
 * Convert a `struct libkeccak_generalised_spec` to a `struct libkeccak_spec`
 *
 * If you are interrested in finding errors, you should call
 * `libkeccak_spec_check(output)` if this function returns zero
 * 
 * @param   spec         The generalised input specifications, will be update with resolved automatic values
 * @param   output_spec  The specification datastructure to fill in
 * @return               Zero if `spec` is valid, a `LIBKECCAK_GENERALISED_SPEC_ERROR_*` if an error was found
 */
int
libkeccak_degeneralise_spec(struct libkeccak_generalised_spec *restrict spec,
                            struct libkeccak_spec *restrict output_spec)
{
	long int state_size, word_size, capacity, bitrate, output;
	const int have_state_size = spec->state_size != LIBKECCAK_GENERALISED_SPEC_AUTOMATIC;
	const int have_word_size  = spec->word_size  != LIBKECCAK_GENERALISED_SPEC_AUTOMATIC;
	const int have_capacity   = spec->capacity   != LIBKECCAK_GENERALISED_SPEC_AUTOMATIC;
	const int have_bitrate    = spec->bitrate    != LIBKECCAK_GENERALISED_SPEC_AUTOMATIC;
	const int have_output     = spec->output     != LIBKECCAK_GENERALISED_SPEC_AUTOMATIC;


	if (have_state_size) {
		state_size = spec->state_size;
		if (state_size <= 0)
			return LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_NONPOSITIVE;
		if (state_size > 1600)
			return LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_TOO_LARGE;
		if (state_size % 25)
			return LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_MOD_25;
	}

	if (have_word_size) {
		word_size = spec->word_size;
		if (word_size <= 0)
			return LIBKECCAK_GENERALISED_SPEC_ERROR_WORD_NONPOSITIVE;
		if (word_size > 64)
			return LIBKECCAK_GENERALISED_SPEC_ERROR_WORD_TOO_LARGE;		
		if (have_state_size && state_size != word_size * 25)
			return LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_WORD_INCOHERENCY;
		else if (!have_state_size)
			spec->state_size = 1, state_size = word_size * 25;
	}

	if (have_capacity) {
		capacity = spec->capacity;
		if (capacity <= 0)
			return LIBKECCAK_GENERALISED_SPEC_ERROR_CAPACITY_NONPOSITIVE;
		if (capacity & 7)
			return LIBKECCAK_GENERALISED_SPEC_ERROR_CAPACITY_MOD_8;
	}

	if (have_bitrate) {
		bitrate = spec->bitrate;
		if (bitrate <= 0)
			return LIBKECCAK_GENERALISED_SPEC_ERROR_BITRATE_NONPOSITIVE;
		if (bitrate & 7)
			return LIBKECCAK_GENERALISED_SPEC_ERROR_BITRATE_MOD_8;
	}

	if (have_output) {
		output = spec->output;
		if (output <= 0)
			return LIBKECCAK_GENERALISED_SPEC_ERROR_OUTPUT_NONPOSITIVE;
	}


	if (!have_bitrate && !have_capacity && !have_output) {
		state_size = deft(state_size, 1600L);
		output = ((state_size << 5) / 100L + 7L) & ~0x07L;
		bitrate = output << 1;
		capacity = state_size - bitrate;
		output = output >= 8 ? output : 8;
	} else if (!have_bitrate && !have_capacity) {
		bitrate = 1024;
		capacity = 1600 - 1024;
		state_size = deft(state_size, bitrate + capacity);
	} else if (!have_bitrate) {
		state_size = deft(state_size, 1600L);
		bitrate = state_size - capacity;
		output = deft(output, capacity == 8 ? 8 : (capacity << 1));
	} else if (!have_capacity) {
		state_size = deft(state_size, 1600L);
		capacity = state_size - bitrate;
		output = deft(output, capacity == 8 ? 8 : (capacity << 1));
	} else {
		state_size = deft(state_size, bitrate + capacity);
		output = deft(output, capacity == 8 ? 8 : (capacity << 1));
	}

	spec->capacity   = output_spec->capacity = capacity;
	spec->bitrate    = output_spec->bitrate  = bitrate;
	spec->output     = output_spec->output   = output;
	spec->state_size = state_size;
	spec->word_size  = state_size / 25;

	return 0;
}


#undef deft

#ifdef __GNUC__
# pragma GCC diagnostic pop
#endif
