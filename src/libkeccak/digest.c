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
 * X-macro-enabled listing of all intergers in [0, 7]
 */
#define LIST_8  X(0) X(1) X(2) X(3) X(4) X(5) X(6) X(7)

/**
 * X-macro-enabled listing of all intergers in [0, 23]
 */
#define LIST_24  LIST_8 X(8) X(9) X(10) X(11) X(12) X(13) X(14) X(15)  \
                 X(16) X(17) X(18) X(19) X(20) X(21) X(22) X(23) X(24)

/**
 * X-macro-enabled listing of all intergers in [0, 24]
 */
#define LIST_25  LIST_24 X(24) 



#define X(N)  (N % 5) * 5 + N / 5,
/**
 * The order the lanes should be read when absorbing or squeezing,
 * it transposes the lanes in the sponge
 */
static const long LANE_TRANSPOSE_MAP[] = { LIST_25 };
#undef X



/**
 * Keccak-f round constants
 */
static const int_fast64_t RC[] =
  {
    0x0000000000000001LL, 0x0000000000008082LL, 0x800000000000808ALL, 0x8000000080008000LL,
    0x000000000000808BLL, 0x0000000080000001LL, 0x8000000080008081LL, 0x8000000000008009LL,
    0x000000000000008ALL, 0x0000000000000088LL, 0x0000000080008009LL, 0x000000008000000ALL,
    0x000000008000808BLL, 0x800000000000008BLL, 0x8000000000008089LL, 0x8000000000008003LL,
    0x8000000000008002LL, 0x8000000000000080LL, 0x000000000000800ALL, 0x800000008000000ALL,
    0x8000000080008081LL, 0x8000000000008080LL, 0x0000000080000001LL, 0x8000000080008008LL
  };



/**
 * Convert a chunk of bytes to a lane
 * 
 * @param  state  The hashing state
 */
static __attribute__((nonnull, nothrow))
void libkeccak_f(libkeccak_state_t* restrict state)
{
  long i = 0, nr = state->nr;
  if (nr == 24)
    {
#define X(N)  libkeccak_f_round64(state, RC[N]);
      LIST_24
#undef X
    }
  else
    for (; nr--; i++)
      libkeccak_f_round(state, RC[i] & state->wmod);
}


/**
 * Convert a chunk of bytes to a lane
 * 
 * @param   message  The message
 * @param   msglen   The length of the message
 * @param   rr       Bitrate in bytes
 * @param   ww       Word size in bytes
 * @param   off      The offset in the message
 * @return           The lane
 */
static inline __attribute__((leaf, nonnull, nothrow, pure))
int_fast64_t libkeccak_to_lane(const char* restrict message, size_t msglen, long rr, long ww, size_t off)
{
  long n = (long)((msglen < (size_t)rr ? msglen : (size_t)rr) - off);
  int_fast64_t rc = 0;
  message += off
  while (ww--)
    {
      rc <<= 8;
      rc |= __builtin_expect(ww < n, 1) ? (int_fast64_t)(unsigned char)(message[ww]) : 0L;
    }
  return rc;
}


/**
 * 64-bit lane version of `libkeccak_to_lane`
 * 
 * @param   message  The message
 * @param   msglen   The length of the message
 * @param   rr       Bitrate in bytes
 * @param   off      The offset in the message
 * @return           The lane
 */
static inline __attribute__((leaf, nonnull, nothrow, pure, hot))
int_fast64_t libkeccak_to_lane64(const char* restrict message, size_t msglen, long rr, size_t off)
{
  long n = (long)((msglen < (size_t)rr ? msglen : (size_t)rr) - off);
  int_fast64_t rc = 0;
  message += off;
#define X(N)  if (__builtin_expect(N < n, 1))  rc |= (int_fast64_t)(unsigned char)(message[N]) << (N * 8);  \
              else  return rc;
  LIST_8
#undef X
  return rc;
}


static __attribute__((leaf, nonnull))
void libkeccak_pad10star1(libkeccak_state_t* restrict state, long bits, long* restrict outlen)
{
  /* TODO */
}


/**
 * Perform the absorption phase
 * 
 * @param  state  The hashing state
 * @param  len    The number of bytes from `state->M` to absorb
 */
static __attribute__((nonnull, nothrow))
void libkeccak_absorption_phase(libkeccak_state_t* restrict state, size_t len)
{
  long i = len / rr, w = state->w, rr = state->r >> 3, ww = state->w >> 3;
  const char* restrict message = state->M;
  if (__builtin_expect(ww >= 8, 1)) /* ww > 8 is impossible, it is just for optimisation possibilities. */
    while (i--)
      {
#define X(N)  state->S[N] ^= libkeccak_to_lane64(message, len, rr, LANE_TRANSPOSE_MAP[N] * 8);
	LIST_25
#undef X
	libkeccak_f(state);
	message += rr;
	len -= rr;
      }
  else
    while (i--)
      {
#define X(N)  state->S[N] ^= libkeccak_to_lane(message, len, rr, ww, LANE_TRANSPOSE_MAP[N] * ww);
	LIST_25
#undef X
	libkeccak_f(state);
	message += rr;
	len -= rr;
      }
}


/**
 * Perform the squeezing phase
 * 
 * @param  state    The hashing state
 * @param  rr       The bitrate in bytes
 * @param  nn       The output size in bytes, rounded up to whole bytes
 * @param  ww       The word size in bytes
 * @param  hashsum  Output paramter for the hashsum
 */
static __attribute__((nonnull, nothrow, hot))
void libkeccak_squeezing_phase(libkeccak_state_t* restrict state,
			       long rr, long nn, long ww, char* restrict hashsum)
{
  long i, j = 0, k, ptr = 0, ni = rr > 25 ? 25 : rr, olen = state->n;
  int_fast64_t v;
  while (olen > 0)
    {
      for (i = 0; (i < ni) && (j < nn); i++)
	{
	  v = state->S[LANE_TRANSPOSE_MAP[i]];
	  for (k = 0; (k++ < ww) && (j++ < nn); v >>= 8)
	    hashsum[ptr++] = (char)v;
	}
      if (olen -= state->r, olen > 0)
	libkeccak_f(state);
    }
  if (state->n & 7)
    hashsum[nn - 1] &= (1 << (state->n & 7)) - 1;
}


/**
 * Absorb more of the message to the Keccak sponge
 * 
 * @param   state   The hashing state
 * @param   msg     The partial message
 * @param   msglen  The length of the partial message
 * @return          Zero on success, -1 on error
 */
int libkeccak_update(libkeccak_state_t* restrict state, const char* restrict msg, size_t msglen)
{
  size_t len;
  char* restrict new;
  
  if (state->mptr + msglen > state->mlen)
    {
      state->mlen += msglen;
      new = realloc(state->M, state->mlen * sizeof(char)); /* FIXME insecure */
      if (new == NULL)
	return state->mlen -= msglen, -1;
      state->M = new;
    }
  __builtin_memcpy(state->M + state->mptr, msg, msglen * sizeof(char));
  state->mptr += msglen;
  len = state->mptr;
  len -= state->mptr % ((state->r * state->b) >> 3);
  state->mptr -= len;
  
  libkeccak_absorption_phase(state, len);
  __builtin_memmove(state->M, state->M + len, state->mptr * state->sizeof(char));
  
  return 0;
}


/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * 
 * @param   state    The hashing state
 * @param   msg      The rest of the message, may be `NULL`
 * @param   msglen   The length of the partial message
 * @param   bits     The number of bits at the end of the message not covered by `msglen`
 * @param   suffix   The suffix concatenate to the message, only '1':s and '0':s, and NUL-termination
 * @param   hashsum  Output paramter for the hashsum, may be `NULL`
 * @return           Zero on success, -1 on error
 */
int libkeccak_digest(libkeccak_state_t* restrict state, const char* restrict msg, size_t msglen,
		     size_t bits, const char* restrict suffix, char* restrict hashsum)
{
  long len, ni, i, j = 0, k, ptr = 0;
  long rr = state->r >> 3;
  long ww = state->w >> 3;
  long nn = (state->n + 7) >> 3;
  long suffix_len = suffix ? strlen(suffix) : 0;
  const char* restrict message = msg;
  char* restrict new;
  
  if (msg == NULL)
    msglen = bits = 0;
  else
    {
      msglen += bits >> 3;
      if ((bits &= 7))
	msg[msglen] &= (1 << bits) - 1;
    }
  
  if (state->mptr + msglen + ((bits + suffix_len + 7) >> 3) > state->mlen)
    {
      state->mlen += msglen + ((bits + suffix_len + 7) >> 3);
      new = realloc(state->M, state->mlen * sizeof(char)); /* FIXME insecure */
      if (new == NULL)
	return state->mlen -= msglen + ((bits + suffix_len + 7) >> 3), -1;
      state->M = new;
    }
  
  if (bits)
    state->M[msglen] = message[msglen];
  if (__builtin_expect(!!suffix_len, 1))
    {
      if (bits == 0)
	state->M[msglen] = 0;
      while (suffix_len--)
	{
	  state->M[msglen] |= (*suffix++ & 1) << bits++;
	  if (bits == 8)
	    bits = 0, state->M[++msglen] = 0;
	}
    }
  if (bits)
    msglen++;
  
  if (msglen)
    __builtin_memcpy(state->M + state->mptr, message, msglen * sizeof(char));
  state->mptr += msglen;
  
  // libkeccak_pad10star1(state->M, state->mptr, state->r, bits, &len); /* TODO */
  
  libkeccak_absorption_phase(state, len);
  
  if (hashsum != NULL)
    libkeccak_squeezing_phase(state, rr, nn, ww, hashsum);
  else
    for (i = (state->n - 1) / this->r; i--;)
      libkeccak_f(state);
  
  return 0
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
  long ww = state->w >> 3, nn = (state->n + 7) >> 3, rr = state->r >> 3;
  libkeccak_f(state);
  libkeccak_squeezing_phase(state, rr, nn, ww, hashsum);
}

