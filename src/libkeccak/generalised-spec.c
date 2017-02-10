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
#include "generalised-spec.h"


#ifdef __GNUC__
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif

#define have(v)      (spec->v != LIBKECCAK_GENERALISED_SPEC_AUTOMATIC)
#define copy(v)      (v = spec->v)
#define deft(v, dv)  (have_##v ? v : (dv))


/**
 * Convert a `libkeccak_generalised_spec_t` to a `libkeccak_spec_t`
 *
 * If you are interrested in finding errors, you should call
 * `libkeccak_spec_check(output)` if this function returns zero
 * 
 * @param   spec         The generalised input specifications, will be update with resolved automatic values
 * @param   output_spec  The specification datastructure to fill in
 * @return               Zero if `spec` is valid, a `LIBKECCAK_GENERALISED_SPEC_ERROR_*` if an error was found
 */
int libkeccak_degeneralise_spec(libkeccak_generalised_spec_t* restrict spec,
				libkeccak_spec_t* restrict output_spec)
{
  long state_size, word_size, capacity, bitrate, output;
  const int have_state_size = have(state_size);
  const int have_word_size  = have(word_size);
  const int have_capacity   = have(capacity);
  const int have_bitrate    = have(bitrate);
  const int have_output     = have(output);
  
  
  if (have_state_size)
    {
      copy(state_size);
      if (state_size <= 0)    return LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_NONPOSITIVE;
      if (state_size > 1600)  return LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_TOO_LARGE;
      if (state_size % 25)    return LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_MOD_25;
    }
  
  if (have_word_size)
    {
      copy(word_size);
      if (word_size <= 0)  return LIBKECCAK_GENERALISED_SPEC_ERROR_WORD_NONPOSITIVE;
      if (word_size > 64)  return LIBKECCAK_GENERALISED_SPEC_ERROR_WORD_TOO_LARGE;
      if (have_state_size && (state_size != word_size * 25))
	return LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_WORD_INCOHERENCY;
      else if (!have_state_size)
	spec->state_size = 1, state_size = word_size * 25;
    }
  
  if (have_capacity)
    {
      copy(capacity);
      if (capacity <= 0)  return LIBKECCAK_GENERALISED_SPEC_ERROR_CAPACITY_NONPOSITIVE;
      if (capacity & 7)   return LIBKECCAK_GENERALISED_SPEC_ERROR_CAPACITY_MOD_8;
    }
  
  if (have_bitrate)
    {
      copy(bitrate);
      if (bitrate <= 0)  return LIBKECCAK_GENERALISED_SPEC_ERROR_BITRATE_NONPOSITIVE;
      if (bitrate & 7)   return LIBKECCAK_GENERALISED_SPEC_ERROR_BITRATE_MOD_8;
    }
  
  if (have_output)
    {
      copy(output);
      if (output <= 0)  return LIBKECCAK_GENERALISED_SPEC_ERROR_OUTPUT_NONPOSITIVE;
    }
  
  
  if (!have_bitrate && !have_capacity && !have_output)
    {
      state_size = deft(state_size, 1600L);
      output = ((state_size << 5) / 100L + 7L) & ~0x07L;
      bitrate = output << 1;
      capacity = state_size - bitrate;
      output = output >= 8 ? output : 8;
    }
  else if (!have_bitrate && !have_capacity)
    {
      bitrate = 1024;
      capacity = 1600 - 1024;
      state_size = deft(state_size, bitrate + capacity);
    }
  else if (!have_bitrate)
    {
      state_size = deft(state_size, 1600L);
      bitrate = state_size - capacity;
      output = deft(output, capacity == 8 ? 8 : (capacity << 1));
    }
  else if (!have_capacity)
    {
      state_size = deft(state_size, 1600L);
      capacity = state_size - bitrate;
      output = deft(output, capacity == 8 ? 8 : (capacity << 1));
    }
  else
    {
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
#undef copy
#undef have

#ifdef __GNUC__
# pragma GCC diagnostic pop
#endif

