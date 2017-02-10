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
#ifndef LIBKECCAK_MAC_HMAC_H
#define LIBKECCAK_MAC_HMAC_H  1


/* The Keccak hash-function, that was selected by NIST as the SHA-3 competition winner,
 * doesn't need this nested approach and can be used to generate a MAC by simply prepending
 * the key to the message. [http://keccak.noekeon.org]
 */


#include "../spec.h"
#include "../state.h"
#include "../internal.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>



/**
 * Datastructure that describes the state of an HMAC-hashing process
 */
typedef struct libkeccak_hmac_state
{
  /**
   * The key right-padded and XOR:ed with the outer pad
   */
  char* restrict key_opad;
  
  /**
   * The key right-padded and XOR:ed with the inner pad
   */
  char* restrict key_ipad;
  /* Not marshalled, implicitly unmarshalled using `key_opad`. */
  /* Shares allocation with `key_opad`, do not `free`. */
  
  /**
   * The length of key, but at least the input block size, in bits
   */
  size_t key_length;
  
  /**
   * The state of the underlaying hash-algorithm
   */
  libkeccak_state_t sponge;
  
  /**
   * Buffer used to temporarily store bit shift message if
   * `.key_length` is not zero modulus 8
   */
  char* restrict buffer;
  
  /**
   * The allocation size of `.buffer`
   */
  size_t buffer_size;
  
  /**
   * Part of feed key, message or digest that have not been passed yet
   */
  char leftover;
  
  char __pad[sizeof(void*) / sizeof(char) - 1];
  
} libkeccak_hmac_state_t;



/**
 * Change the HMAC-hashing key on the state
 * 
 * @param   state       The state that should be reset
 * @param   key         The new key
 * @param   key_length  The length of key, in bits
 * @return              Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull(1), unused)))
int libkeccak_hmac_set_key(libkeccak_hmac_state_t* restrict state, const char* restrict key, size_t key_length);


/**
 * Initialise an HMAC hashing-state according to hashing specifications
 * 
 * @param   state       The state that should be initialised
 * @param   spec        The specifications for the state
 * @param   key         The key
 * @param   key_length  The length of key, in bits
 * @return              Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull)))
static inline
int libkeccak_hmac_initialise(libkeccak_hmac_state_t* restrict state, const libkeccak_spec_t* restrict spec,
			      const char* restrict key, size_t key_length)
{
  int saved_errno;
  if (libkeccak_state_initialise(&(state->sponge), spec) < 0)
    return -1;
  if (libkeccak_hmac_set_key(state, key, key_length) < 0)
    return saved_errno = errno, libkeccak_state_destroy(&(state->sponge)), errno = saved_errno, -1;
  state->leftover = 0;
  state->buffer = NULL;
  state->buffer_size = 0;
  return 0;
}


/**
 * Wrapper for `libkeccak_hmac_initialise` that also allocates the states
 * 
 * @param   spec        The specifications for the state
 * @param   key         The key
 * @param   key_length  The length of key, in bits
 * @return              The state, `NULL` on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull, unused, warn_unused_result, malloc)))
static inline
libkeccak_hmac_state_t* libkeccak_hmac_create(const libkeccak_spec_t* restrict spec,
					      const char* restrict key, size_t key_length)
{
  libkeccak_hmac_state_t* restrict state = malloc(sizeof(libkeccak_hmac_state_t));
  int saved_errno;
  if ((state == NULL) || libkeccak_hmac_initialise(state, spec, key, key_length))
    return saved_errno = errno, free(state), errno = saved_errno, NULL;
  return state;
}


/**
 * Reset an HMAC-hashing state according to hashing specifications,
 * you can choose whether to change the key
 * 
 * @param   state       The state that should be reset
 * @param   key         The new key, `NULL` to keep the old key
 * @param   key_length  The length of key, in bits, ignored if `key == NULL`
 * @return              Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull(1), unused)))
static inline
int libkeccak_hmac_reset(libkeccak_hmac_state_t* restrict state, const char* restrict key, size_t key_length)
{
  libkeccak_state_reset(&(state->sponge));
  return key != NULL ? libkeccak_hmac_set_key(state, key, key_length) : 0;
}


/**
 * Wipe sensitive data wihout freeing any data
 * 
 * @param  state  The state that should be wipe
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull, nothrow, optimize("-O0"))))
void libkeccak_hmac_wipe(volatile libkeccak_hmac_state_t* restrict state);


/**
 * Release resources allocation for an HMAC hashing-state without wiping sensitive data
 * 
 * @param  state  The state that should be destroyed
 */
static inline
void libkeccak_hmac_fast_destroy(libkeccak_hmac_state_t* restrict state)
{
  if (state == NULL)
    return;
  free(state->key_opad);
  state->key_opad = NULL;
  state->key_ipad = NULL;
  state->key_length = 0;
  free(state->buffer);
  state->buffer = NULL;
  state->buffer_size = 0;
}


/**
 * Release resources allocation for an HMAC hasing-state and wipe sensitive data
 * 
 * @param  state  The state that should be destroyed
 */
LIBKECCAK_GCC_ONLY(__attribute__((unused, optimize("-O0"))))
static inline
void libkeccak_hmac_destroy(volatile libkeccak_hmac_state_t* restrict state)
{
  if (state == NULL)
    return;
  libkeccak_hmac_wipe(state);
  free(state->key_opad);
  state->key_opad = NULL;
  state->key_ipad = NULL;
  state->key_length = 0;
  state->leftover = 0;
  free(state->buffer);
  state->buffer = NULL;
  state->buffer_size = 0;
}


/**
 * Wrapper for `libkeccak_fast_destroy` that also frees the allocation of the state
 * 
 * @param  state  The state that should be freed
 */
LIBKECCAK_GCC_ONLY(__attribute__((unused)))
static inline
void libkeccak_hmac_fast_free(libkeccak_hmac_state_t* restrict state)
{
  libkeccak_hmac_fast_destroy(state);
  free(state);
}


/**
 * Wrapper for `libkeccak_hmac_destroy` that also frees the allocation of the state
 * 
 * @param  state  The state that should be freed
 */
LIBKECCAK_GCC_ONLY(__attribute__((unused, optimize("-O0"))))
static inline
void libkeccak_hmac_free(volatile libkeccak_hmac_state_t* restrict state)
{
#ifdef __GNUC__
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wcast-qual"
#endif
  libkeccak_hmac_destroy(state);
  free((libkeccak_hmac_state_t*)state);
#ifdef __GNUC__
# pragma GCC diagnostic pop
#endif
}


/**
 * Make a copy of an HMAC hashing-state
 * 
 * @param   dest  The slot for the duplicate, must not be initialised (memory leak otherwise)
 * @param   src   The state to duplicate
 * @return        Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull)))
int libkeccak_hmac_copy(libkeccak_hmac_state_t* restrict dest, const libkeccak_hmac_state_t* restrict src);


/**
 * A wrapper for `libkeccak_hmac_copy` that also allocates the duplicate
 * 
 * @param   src  The state to duplicate
 * @return       The duplicate, `NULL` on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull, unused, warn_unused_result, malloc)))
static inline
libkeccak_hmac_state_t* libkeccak_hmac_duplicate(const libkeccak_hmac_state_t* restrict src)
{
  libkeccak_hmac_state_t* restrict dest = malloc(sizeof(libkeccak_hmac_state_t));
  int saved_errno;
  if ((dest == NULL) || libkeccak_hmac_copy(dest, src))
    return saved_errno = errno, libkeccak_hmac_free(dest), errno = saved_errno, NULL;
  return dest;
}


/**
 * Calculates the allocation size required for the second argument
 * of `libkeccak_hmac_marshal` (`char* restrict data)`)
 * 
 * @param   state  The state as it will be marshalled by a subsequent call to `libkeccak_hamc_marshal`
 * @return         The allocation size needed for the buffer to which the state will be marshalled
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull, nothrow, unused, warn_unused_result, pure)))
static inline
size_t libkeccak_hmac_marshal_size(const libkeccak_hmac_state_t* restrict state)
{
  return libkeccak_state_marshal_size(&(state->sponge)) + sizeof(size_t) +
         ((state->key_length + 7) >> 3) + 2 * sizeof(char);
}


/**
 * Marshal a `libkeccak_hmac_state_t` into a buffer
 * 
 * @param   state  The state to marshal
 * @param   data   The output buffer
 * @return         The number of bytes stored to `data`
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull, nothrow)))
static inline
size_t libkeccak_hmac_marshal(const libkeccak_hmac_state_t* restrict state, char* restrict data)
{
  size_t written = libkeccak_state_marshal(&(state->sponge), data);
  data += written / sizeof(char);
  *(size_t*)data = state->key_length;
  data += sizeof(size_t) / sizeof(char);
  memcpy(data, state->key_opad, (state->key_length + 7) >> 3);
  data += ((state->key_length + 7) >> 3) / sizeof(char);
  data[0] = (char)(state->key_ipad != NULL);
  data[1] = state->leftover;
  return written + sizeof(size_t) + ((state->key_length + 7) >> 3) + 2 * sizeof(char);
}


/**
 * Unmarshal a `libkeccak_hmac_state_t` from a buffer
 * 
 * @param   state  The slot for the unmarshalled state, must not be initialised (memory leak otherwise)
 * @param   data   The input buffer
 * @return         The number of bytes read from `data`, 0 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull)))
size_t libkeccak_hmac_unmarshal(libkeccak_hmac_state_t* restrict state, const char* restrict data);


/**
 * Gets the number of bytes the `libkeccak_hmac_state_t` stored
 * at the beginning of `data` occupies
 * 
 * @param   data  The data buffer
 * @return        The byte size of the stored state
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull, nothrow, warn_unused_result, pure)))
static inline
size_t libkeccak_hmac_unmarshal_skip(const char* restrict data)
{
  size_t skip = libkeccak_state_unmarshal_skip(data);
  data += skip / sizeof(char);
  return skip + sizeof(size_t) + *(const size_t*)data + 2 * sizeof(char);
}


/**
 * Absorb more, or the first part, of the message
 * without wiping sensitive data when possible
 * 
 * @param   state   The hashing state
 * @param   msg     The partial message
 * @param   msglen  The length of the partial message, in bytes
 * @return          Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull(1))))
int libkeccak_hmac_fast_update(libkeccak_hmac_state_t* restrict state, const char* restrict msg, size_t msglen);


/**
 * Absorb more, or the first part, of the message
 * and wipe sensitive data when possible
 * 
 * @param   state   The hashing state
 * @param   msg     The partial message
 * @param   msglen  The length of the partial message, in bytes
 * @return          Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull(1))))
int libkeccak_hmac_update(libkeccak_hmac_state_t* restrict state, const char* restrict msg, size_t msglen);


/**
 * Absorb the last part of the message and fetch the hash
 * without wiping sensitive data when possible
 * 
 * You may use `&(state->sponge)` for continued squeezing
 * 
 * @param   state    The hashing state
 * @param   msg      The rest of the message, may be `NULL`, may be modified
 * @param   msglen   The length of the partial message
 * @param   bits     The number of bits at the end of the message not covered by `msglen`
 * @param   suffix   The suffix concatenate to the message, only '1':s and '0':s, and NUL-termination
 * @param   hashsum  Output parameter for the hashsum, may be `NULL`
 * @return           Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull(1))))
int libkeccak_hmac_fast_digest(libkeccak_hmac_state_t* restrict state, const char* restrict msg, size_t msglen,
			       size_t bits, const char* restrict suffix, char* restrict hashsum);


/**
 * Absorb the last part of the message and fetch the hash
 * and wipe sensitive data when possible
 * 
 * You may use `&(state->sponge)` for continued squeezing
 * 
 * @param   state    The hashing state
 * @param   msg      The rest of the message, may be `NULL`, may be modified
 * @param   msglen   The length of the partial message
 * @param   bits     The number of bits at the end of the message not covered by `msglen`
 * @param   suffix   The suffix concatenate to the message, only '1':s and '0':s, and NUL-termination
 * @param   hashsum  Output parameter for the hashsum, may be `NULL`
 * @return           Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull(1))))
int libkeccak_hmac_digest(libkeccak_hmac_state_t* restrict state, const char* restrict msg, size_t msglen,
			  size_t bits, const char* restrict suffix, char* restrict hashsum);


#endif

