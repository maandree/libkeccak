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
#ifndef LIBKECCAK_SPEC_H
#define LIBKECCAK_SPEC_H  1


#include "internal.h"

#include <stdint.h>
#include <limits.h>


/**
 * Message suffix for SHA3 hashing
 */
#define LIBKECCAK_SHA3_SUFFIX  "01"

/**
 * Message suffix for RawSHAKE hashing
 */
#define LIBKECCAK_RAWSHAKE_SUFFIX  "11"

/**
 * Message suffix for SHAKE hashing
 */
#define LIBKECCAK_SHAKE_SUFFIX  "1111"


/**
 * Invalid `libkeccak_spec_t.bitrate`: non-positive
 */
#define LIBKECCAK_SPEC_ERROR_BITRATE_NONPOSITIVE  1

/**
 * Invalid `libkeccak_spec_t.bitrate`: not a multiple of 8
 */
#define LIBKECCAK_SPEC_ERROR_BITRATE_MOD_8  2

/**
 * Invalid `libkeccak_spec_t.capacity`: non-positive
 */
#define LIBKECCAK_SPEC_ERROR_CAPACITY_NONPOSITIVE  3

/**
 * Invalid `libkeccak_spec_t.capacity`: not a multiple of 8
 */
#define LIBKECCAK_SPEC_ERROR_CAPACITY_MOD_8  4

/**
 * Invalid `libkeccak_spec_t.output`: non-positive
 */
#define LIBKECCAK_SPEC_ERROR_OUTPUT_NONPOSITIVE  5

/**
 * Invalid `libkeccak_spec_t` values: `.bitrate + `.capacity`
 * is greater 1600 which is the largest supported state size
 */
#define LIBKECCAK_SPEC_ERROR_STATE_TOO_LARGE  6

/**
 * Invalid `libkeccak_spec_t` values:
 * `.bitrate + `.capacity` is not a multiple of 25
 */
#define LIBKECCAK_SPEC_ERROR_STATE_MOD_25  7

/**
 * Invalid `libkeccak_spec_t` values: `.bitrate + `.capacity`
 * is a not a 2-potent multiple of 25
 */
#define LIBKECCAK_SPEC_ERROR_WORD_NON_2_POTENT  8

/**
 * Invalid `libkeccak_spec_t` values: `.bitrate + `.capacity`
 * is a not multiple of 100, and thus the word size is not
 * a multiple of 8
 */
#define LIBKECCAK_SPEC_ERROR_WORD_MOD_8  9



/**
 * Datastructure that describes the parameters
 * that should be used when hashing
 */
typedef struct libkeccak_spec
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
  
} libkeccak_spec_t;



/**
 * Fill in a `libkeccak_spec_t` for a SHA3-x hashing
 * 
 * @param  spec  The specifications datastructure to fill in
 * @param  x     The value of x in `SHA3-x`, the output size
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull, nothrow)))
static inline
void libkeccak_spec_sha3(libkeccak_spec_t* restrict spec, long x)
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
static inline
void libkeccak_spec_rawshake(libkeccak_spec_t* restrict spec, long x, long d)
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
#define libkeccak_spec_shake  libkeccak_spec_rawshake


/**
 * Check for errors in a `libkeccak_spec_t`
 * 
 * @param   spec  The specifications datastructure to check
 * @return        Zero if error free, a `LIBKECCAK_SPEC_ERROR_*` if an error was found
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull, nothrow, unused, warn_unused_result, pure)))
static inline
int libkeccak_spec_check(const libkeccak_spec_t* restrict spec)
{
  long state_size = spec->capacity + spec->bitrate;
  int32_t word_size = (int32_t)(state_size / 25);
  if (spec->bitrate <= 0)   return LIBKECCAK_SPEC_ERROR_BITRATE_NONPOSITIVE;
  if (spec->bitrate % 8)    return LIBKECCAK_SPEC_ERROR_BITRATE_MOD_8;
  if (spec->capacity <= 0)  return LIBKECCAK_SPEC_ERROR_CAPACITY_NONPOSITIVE;
  if (spec->capacity % 8)   return LIBKECCAK_SPEC_ERROR_CAPACITY_MOD_8;
  if (spec->output <= 0)    return LIBKECCAK_SPEC_ERROR_OUTPUT_NONPOSITIVE;
  if (state_size > 1600)    return LIBKECCAK_SPEC_ERROR_STATE_TOO_LARGE;
  if (state_size % 25)      return LIBKECCAK_SPEC_ERROR_STATE_MOD_25;
  if (word_size % 8)        return LIBKECCAK_SPEC_ERROR_WORD_MOD_8;
  
  /* `(x & -x) != x` assumes two's complement, which of course is always
   * satisfied by GCC, however C99 guarantees that `int32_t` exists,
   * and it is basically the same thing as `long int`; with one important
   * difference: it is guaranteed to use two's complement. */
  if ((word_size & -word_size) != word_size)
    return LIBKECCAK_SPEC_ERROR_WORD_NON_2_POTENT;
  
  return 0;
}


#endif

