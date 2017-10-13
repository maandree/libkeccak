/* See LICENSE file for copyright and license details. */
#ifndef LIBKECCAK_DIGEST_H
#define LIBKECCAK_DIGEST_H 1

#include "state.h"
#include "internal.h"


/**
 * Absorb more of the message to the Keccak sponge
 * without wiping sensitive data when possible
 * 
 * @param   state   The hashing state
 * @param   msg     The partial message
 * @param   msglen  The length of the partial message
 * @return          Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull)))
int libkeccak_fast_update(libkeccak_state_t *restrict state, const char* restrict msg, size_t msglen);


/**
 * Absorb more of the message to the Keccak sponge
 * and wipe sensitive data when possible
 * 
 * @param   state   The hashing state
 * @param   msg     The partial message
 * @param   msglen  The length of the partial message
 * @return          Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull)))
int libkeccak_update(libkeccak_state_t *restrict state, const char *restrict msg, size_t msglen);


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
LIBKECCAK_GCC_ONLY(__attribute__((nonnull(1))))
int libkeccak_fast_digest(libkeccak_state_t *restrict state, const char *restrict msg, size_t msglen,
                          size_t bits, const char *restrict suffix, char *restrict hashsum);


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
LIBKECCAK_GCC_ONLY(__attribute__((nonnull(1))))
int libkeccak_digest(libkeccak_state_t *restrict state, const char *restrict msg, size_t msglen,
                     size_t bits, const char *restrict suffix, char *restrict hashsum);


/**
 * Force some rounds of Keccak-f
 * 
 * @param  state  The hashing state
 * @param  times  The number of rounds
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull, nothrow)))
void libkeccak_simple_squeeze(register libkeccak_state_t *restrict state, register long times);


/**
 * Squeeze as much as is needed to get a digest a number of times
 * 
 * @param  state  The hashing state
 * @param  times  The number of digests
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull, nothrow)))
void libkeccak_fast_squeeze(register libkeccak_state_t *restrict state, register long times);


/**
 * Squeeze out another digest
 * 
 * @param  state    The hashing state
 * @param  hashsum  Output parameter for the hashsum
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull, nothrow)))
void libkeccak_squeeze(register libkeccak_state_t *restrict state, register char* restrict hashsum);


#endif

