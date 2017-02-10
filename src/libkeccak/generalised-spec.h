/**
 * libkeccak – Keccak-family hashing library
 * 
 * Copyright © 2014, 2015, 2017  Mattias Andrée (maandree@kth.se)
 * 
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef LIBKECCAK_GENERALISED_SPEC_H
#define LIBKECCAK_GENERALISED_SPEC_H  1


#include "spec.h"
#include "internal.h"

#include <inttypes.h>



/**
 * Value for `libkeccak_generalised_spec_t` member that
 * is used to automatically select the value
 */
#define LIBKECCAK_GENERALISED_SPEC_AUTOMATIC  (-65536L)


/**
 * Invalid `libkeccak_generalised_spec_t.state_size`: non-positive
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_NONPOSITIVE  1

/**
 * Invalid `libkeccak_generalised_spec_t.state_size`: larger than 1600
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_TOO_LARGE  2

/**
 * Invalid `libkeccak_generalised_spec_t.state_size`: not a multiple of 25
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_MOD_25  3

/**
 * Invalid `libkeccak_generalised_spec_t.word_size`: non-positive
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_WORD_NONPOSITIVE  4

/**
 * Invalid `libkeccak_generalised_spec_t.word_size`: larger than 1600 / 25
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_WORD_TOO_LARGE  5

/**
 * Invalid `libkeccak_generalised_spec_t.word_size` and
 * `libkeccak_generalised_spec_t.state_size`: `.word_size * 25 != .state_size`
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_WORD_INCOHERENCY  6

/**
 * Invalid `libkeccak_generalised_spec_t.capacity`: non-positive
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_CAPACITY_NONPOSITIVE  7

/**
 * Invalid `libkeccak_generalised_spec_t.capacity`: not a multiple of 8
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_CAPACITY_MOD_8  8

/**
 * Invalid `libkeccak_generalised_spec_t.bitrate`: non-positive
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_BITRATE_NONPOSITIVE  9

/**
 * Invalid `libkeccak_generalised_spec_t.bitrate`: not a multiple of 8
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_BITRATE_MOD_8  10

/**
 * Invalid `libkeccak_generalised_spec_t.output`: non-positive
 */
#define LIBKECCAK_GENERALISED_SPEC_ERROR_OUTPUT_NONPOSITIVE  11



/**
 * Generalised datastructure that describes the
 * parameters that should be used when hashing
 */
typedef struct libkeccak_generalised_spec
{
  /**
   * The bitrate
   */
  long bitrate;
  
  /**
   * The capacity
   */
  long capacity;
  
  /**
   * The output size
   */
  long output;
  
  /**
   * The state size
   */
  long state_size;
  
  /**
   * The word size
   */
  long word_size;
  
} libkeccak_generalised_spec_t;



/**
 * Set all specification parameters to automatic
 * 
 * @param  spec  The specification datastructure to fill in
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull, nothrow, unused)))
static inline
void libkeccak_generalised_spec_initialise(libkeccak_generalised_spec_t* restrict spec)
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
LIBKECCAK_GCC_ONLY(__attribute__((leaf, nonnull, nothrow)))
int libkeccak_degeneralise_spec(libkeccak_generalised_spec_t* restrict spec,
				libkeccak_spec_t* restrict output_spec);


#endif

