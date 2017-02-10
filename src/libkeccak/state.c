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
#include "state.h"

#include <string.h>



/**
 * Initialise a state according to hashing specifications
 * 
 * @param   state  The state that should be initialised
 * @param   spec   The specifications for the state
 * @return         Zero on success, -1 on error
 */
int libkeccak_state_initialise(libkeccak_state_t* restrict state, const libkeccak_spec_t* restrict spec)
{
  long x;
  state->r = spec->bitrate;
  state->n = spec->output;
  state->c = spec->capacity;
  state->b = state->r + state->c;
  state->w = x = state->b / 25;
  state->l = 0;
  if (x & 0xF0L)  state->l |= 4,  x >>= 4;
  if (x & 0x0CL)  state->l |= 2,  x >>= 2;
  if (x & 0x02L)  state->l |= 1;
  state->nr = 12 + (state->l << 1);
  state->wmod = (state->w == 64) ? ~0LL : (int64_t)((1ULL << state->w) - 1);
  for (x = 0; x < 25; x++)
    state->S[x] = 0;
  state->mptr = 0;
  state->mlen = (size_t)(state->r * state->b) >> 2;
  state->M = malloc(state->mlen * sizeof(char));
  return state->M == NULL ? -1 : 0;
}


/**
 * Wipe data in the state's message wihout freeing any data
 * 
 * @param  state  The state that should be wipe
 */
void libkeccak_state_wipe_message(volatile libkeccak_state_t* restrict state)
{
  volatile char* restrict M = state->M;
  size_t i;
  for (i = 0; i < state->mptr; i++)
    M[i] = 0;
}

/**
 * Wipe data in the state's sponge wihout freeing any data
 * 
 * @param  state  The state that should be wipe
 */
void libkeccak_state_wipe_sponge(volatile libkeccak_state_t* restrict state)
{
  volatile int64_t* restrict S = state->S;
  size_t i;
  for (i = 0; i < 25; i++)
    S[i] = 0;
}

/**
 * Wipe sensitive data wihout freeing any data
 * 
 * @param  state  The state that should be wipe
 */
void libkeccak_state_wipe(volatile libkeccak_state_t* restrict state)
{
  libkeccak_state_wipe_message(state);
  libkeccak_state_wipe_sponge(state);
}


/**
 * Make a copy of a state
 * 
 * @param   dest  The slot for the duplicate, must not be initialised (memory leak otherwise)
 * @param   src   The state to duplicate
 * @return        Zero on success, -1 on error
 */
int libkeccak_state_copy(libkeccak_state_t* restrict dest, const libkeccak_state_t* restrict src)
{
  memcpy(dest, src, sizeof(libkeccak_state_t));
  dest->M = malloc(src->mlen * sizeof(char));
  if (dest->M == NULL)
    return -1;
  memcpy(dest->M, src->M, src->mptr * sizeof(char));
  return 0;
}


/**
 * Marshal a `libkeccak_state_t` into a buffer
 * 
 * @param   state  The state to marshal
 * @param   data   The output buffer
 * @return         The number of bytes stored to `data`
 */
size_t libkeccak_state_marshal(const libkeccak_state_t* restrict state, char* restrict data)
{
#define set(type, var)  *((type*)data) = state->var, data += sizeof(type) / sizeof(char)
  set(long, r);
  set(long, c);
  set(long, n);
  set(long, b);
  set(long, w);
  set(int64_t, wmod);
  set(long, l);
  set(long, nr);
  memcpy(data, state->S, sizeof(state->S));
  data += sizeof(state->S) / sizeof(char);
  set(size_t, mptr);
  set(size_t, mlen);
  memcpy(data, state->M, state->mptr * sizeof(char));
  data += state->mptr;
  return sizeof(libkeccak_state_t) - sizeof(char*) + state->mptr * sizeof(char);
#undef set
}


/**
 * Unmarshal a `libkeccak_state_t` from a buffer
 * 
 * @param   state  The slot for the unmarshalled state, must not be initialised (memory leak otherwise)
 * @param   data   The input buffer
 * @return         The number of bytes read from `data`, 0 on error
 */
size_t libkeccak_state_unmarshal(libkeccak_state_t* restrict state, const char* restrict data)
{
#define get(type, var)  state->var = *((const type*)data), data += sizeof(type) / sizeof(char)
  get(long, r);
  get(long, c);
  get(long, n);
  get(long, b);
  get(long, w);
  get(int64_t, wmod);
  get(long, l);
  get(long, nr);
  memcpy(state->S, data, sizeof(state->S));
  data += sizeof(state->S) / sizeof(char);
  get(size_t, mptr);
  get(size_t, mlen);
  state->M = malloc(state->mptr * sizeof(char));
  if (state->M == NULL)
    return 0;
  memcpy(state->M, data, state->mptr * sizeof(char));
  data += state->mptr;
  return sizeof(libkeccak_state_t) - sizeof(char*) + state->mptr * sizeof(char);
#undef get
}


/**
 * Gets the number of bytes the `libkeccak_state_t` stored
 * at the beginning of `data` occupies
 * 
 * @param   data  The data buffer
 * @return        The byte size of the stored state
 */
size_t libkeccak_state_unmarshal_skip(const char* restrict data)
{
  data += (7 * sizeof(long) + 26 * sizeof(int64_t)) / sizeof(char);
  return sizeof(libkeccak_state_t) - sizeof(char*) + *(const size_t*)data * sizeof(char);
}

