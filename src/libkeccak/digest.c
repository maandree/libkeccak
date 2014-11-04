/**
 * libkeccak – Keccak-family hashing library
 * 
 * Copyright © 2014  Mattias Andrée (maandree@member.fsf.org)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "digest.h"


/**
 * Absorb the more of the message to the Keccak sponge
 * 
 * @param  state   The hashing state
 * @param  msg     The partial message
 * @param  msglen  The length of the partial message
 */
void libkeccak_update(libkeccak_state_t* restrict state, const char* restrict msg, size_t msglen)
{
}


/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * 
 * @param   state    The hashing state
 * @param   msg      The rest of the message, may be `NULL`
 * @param   msglen   The length of the partial message
 * @param   bits     The number of bits at the end of the message not covered by `msglen`
 * @param   suffix   The suffix concatenate to the message
 * @param   hashsum  Output paramter for the hashsum, may be `NULL`
 * @return           Zero on success, -1 on error
 */
int libkeccak_digest(libkeccak_state_t* restrict state, const char* restrict msg, size_t msglen,
		     size_t bits, const char* restrict suffix, char* restrict hashsum)
{
}


/**
 * Force some rounds of Keccak-f
 * 
 * @param  state  The hashing state
 * @param  times  The number of rounds
 */
void libkeccak_simple_squeeze(libkeccak_state_t* restrict state, long times)
{
  while (times--)
    libkeccak_f(state);
}


/**
 * Squeeze as much as is needed to get a digest a number of times
 * 
 * @param  state  The hashing state
 * @param  times  The number of digests
 */
void libkeccak_fast_squeeze(libkeccak_state_t* restrict state, long times)
{
  times *= (state->n - 1) / state->r + 1;
  while (times--)
    libkeccak_f(state);
}


/**
 * Squeeze out another digest
 * 
 * @param  state    The hashing state
 * @param  hashsum  Output paramter for the hashsum
 */
void libkeccak_squeeze(libkeccak_state_t* restrict state, char* restrict hashsum)
{
  long ww, nn, olen, i, j, k, ptr, rr, ni;
  int_fast64_t v;
  
  libkeccak_f(state);
  
  ww = state->w >> 3;
  nn = (state->n + 7) >> 3;
  olen = state->n;
  j = ptr = 0;
  rr = state->r >> 3;
  ni = rr > 25 ? 25 : rr;
  
  while (olen > 0)
    {
      for (i = 0; (i < ni) && (j < nn); i++)
	{
	  v = state->S[(i % 5) * 5 + i / 5];
	  for (k = 0; k++ < ww; v >>= 8)
	    if (j++ < nn)
	      hashsum[ptr++] = (char)v;
	}
      if (olen -= state->r, olen > 0)
	libkeccak_f(state);
    }
  if (n & 7)
    n[nn - 1] &= (1 << (n & 7)) - 1;
}

