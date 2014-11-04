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
#ifndef LIBKECCAK_DIGEST_H
#define LIBKECCAK_DIGEST_H  1


#include "state.h"


/**
 * Absorb more of the message to the Keccak sponge
 * 
 * @param   state   The hashing state
 * @param   msg     The partial message
 * @param   msglen  The length of the partial message
 * @return          Zero on success, -1 on error
 */
__attribute__((nonnull))
int libkeccak_update(libkeccak_state_t* restrict state, const char* restrict msg, size_t msglen);


/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * 
 * @param   state    The hashing state
 * @param   msg      The rest of the message, may be `NULL`, may be modified
 * @param   msglen   The length of the partial message
 * @param   bits     The number of bits at the end of the message not covered by `msglen`
 * @param   suffix   The suffix concatenate to the message, only '1':s and '0':s, and NUL-termination
 * @param   hashsum  Output paramter for the hashsum, may be `NULL`
 * @return           Zero on success, -1 on error
 */
__attribute__((nonnull(1)))
int libkeccak_digest(libkeccak_state_t* restrict state, char* restrict msg, size_t msglen,
		     size_t bits, const char* restrict suffix, char* restrict hashsum);


/**
 * Force some rounds of Keccak-f
 * 
 * @param  state  The hashing state
 * @param  times  The number of rounds
 */
__attribute__((nonnull, nothrow))
void libkeccak_simple_squeeze(libkeccak_state_t* restrict state, long times);


/**
 * Squeeze as much as is needed to get a digest a number of times
 * 
 * @param  state  The hashing state
 * @param  times  The number of digests
 */
__attribute__((nonnull, nothrow))
void libkeccak_fast_squeeze(libkeccak_state_t* restrict state, long times);


/**
 * Squeeze out another digest
 * 
 * @param  state    The hashing state
 * @param  hashsum  Output paramter for the hashsum
 */
__attribute__((nonnull, nothrow))
void libkeccak_squeeze(libkeccak_state_t* restrict state, char* restrict hashsum);


#endif
