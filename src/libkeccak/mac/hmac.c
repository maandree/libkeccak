/**
 * libkeccak – Keccak-family hashing library
 * 
 * Copyright © 2014, 2015  Mattias Andrée (maandree@member.fsf.org)
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
#include "hmac.h"

#include "../digest.h"



/**
 * The outer pad pattern
 */
#define OUTER_PAD  0x5C

/**
 * The inner pad pattern
 */
#define INNER_PAD  0x36



/**
 * Change to HMAC-hashing key on the state
 * 
 * @param   state       The state that should be reset
 * @param   key         The new key
 * @param   key_length  The length of key, in bits
 * @return              Zero on success, -1 on error
 */
int libkeccak_hmac_set_key(libkeccak_hmac_state_t* restrict state, const char* restrict key, size_t key_length)
{
  size_t i, size, new_key_length, key_bytes;
  char* old;
  
  size = (size_t)(state->sponge.r) > key_length ? (size_t)(state->sponge.r) : key_length;
  new_key_length = size;
  size = (size + 7) >> 3;
  key_bytes = (key_length + 7) >> 3;
  
  if (size != key_bytes)
    {
      state->key_opad = realloc(old = state->key_opad, 2 * size);
      if (state->key_opad == NULL)
	return state->key_opad = old, -1;
      state->key_ipad = state->key_opad + size / sizeof(char);
    }
  
  memcpy(state->key_opad, key, key_bytes);
  if (key_length & 7)
    state->key_opad[(key_bytes >> 3) - 1] &= (1 << (key_length & 7)) - 1;
  
  if ((size_t)(state->sponge.r) > key_length)
    __builtin_memset(state->key_opad + key_bytes / sizeof(char), 0, size - key_bytes);
  
  for (i = 0; i < size; i++)
    state->key_ipad[i] = state->key_opad[i] ^ INNER_PAD,
    state->key_opad[i] ^= OUTER_PAD;
  
  state->key_length = new_key_length;
  
  return 0;
}


/**
 * Wipe sensitive data wihout freeing any data
 * 
 * @param  state  The state that should be wipe
 */
void libkeccak_hmac_wipe(volatile libkeccak_hmac_state_t* restrict state)
{
  volatile char* restrict key_pads;
  size_t i, size;
  key_pads = state->key_opad;
  size = 2 * ((state->key_length + 7) >> 3);
  libkeccak_state_wipe(&(state->sponge));
  for (i = 0; i < size; i++)
    key_pads[i] = 0;
  state->leftover = 0;
  __builtin_memset(state->buffer, 0, state->buffer_size);
}


/**
 * Make a copy of an HMAC hashing-state
 * 
 * @param   dest  The slot for the duplicate, must not be initialised (memory leak otherwise)
 * @param   src   The state to duplicate
 * @return        Zero on success, -1 on error
 */
int libkeccak_hmac_copy(libkeccak_hmac_state_t* restrict dest, const libkeccak_hmac_state_t* restrict src)
{
  int saved_errno;
  size_t size;
  
  dest->key_opad = NULL;
  dest->key_ipad = NULL;
  
  if (libkeccak_state_copy(&(dest->sponge), &(src->sponge)) < 0)
    return -1;
  
  dest->key_length = src->key_length;
  dest->leftover = src->leftover;
  
  size = (src->key_length + 7) >> 3;
  dest->key_opad = malloc(2 * size);
  if (dest->key_opad == NULL)
    return saved_errno = errno, libkeccak_state_destroy(&(dest->sponge)), errno = saved_errno, -1;
  dest->key_ipad = dest->key_opad + size / sizeof(char);
  
  memcpy(dest->key_opad, src->key_opad, size);
  memcpy(dest->key_ipad, src->key_ipad, size);
  
  return 0;
}


/**
 * Unmarshal a `libkeccak_hmac_state_t` from a buffer
 * 
 * @param   state  The slot for the unmarshalled state, must not be initialised (memory leak otherwise)
 * @param   data   The input buffer
 * @return         The number of bytes read from `data`, 0 on error
 */
size_t libkeccak_hmac_unmarshal(libkeccak_hmac_state_t* restrict state, const char* restrict data)
{
  size_t parsed, size, i;
  int saved_errno;
  
  state->key_opad = NULL;
  state->key_ipad = NULL;
  
  parsed = libkeccak_state_unmarshal(&(state->sponge), data);
  if (parsed == 0)
    return 0;
  
  data += parsed / sizeof(char);
  state->key_length = *(const size_t*)data;
  data += sizeof(size_t) / sizeof(char);
  size = (state->key_length + 7) >> 3;
  
  state->key_opad = malloc(2 * size);
  if (state->key_opad == NULL)
    return saved_errno = errno, libkeccak_state_destroy(&(state->sponge)), errno = saved_errno, -1;
  memcpy(state->key_opad, data, size);
  data += size / sizeof(char);
  
  if (data[0])
    {
      state->key_ipad = state->key_opad + size / sizeof(char);
      memcpy(state->key_ipad, state->key_opad, size);
      for (i = 0; i < size / sizeof(char); i++)
	state->key_ipad[i] ^= (char)(OUTER_PAD ^ INNER_PAD);
    }
  
  state->leftover = data[1];
  state->buffer = NULL;
  state->buffer_size = 0;
  
  return parsed + sizeof(size_t) + size + 2 * sizeof(char);
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
__attribute__((nonnull))
int libkeccak_hmac_fast_update(libkeccak_hmac_state_t* restrict state, const char* restrict msg, size_t msglen)
{
  char* old;
  size_t i;
  int n, cn;
  
  if (state->key_ipad != NULL)
    {
      if (libkeccak_fast_update(&(state->sponge), state->key_ipad, state->key_length >> 3) < 0)
	return -1;
      if (state->key_length & 7)
	state->leftover = state->key_ipad[(state->key_length >> 3)];
      state->key_ipad = NULL;
    }
  
  if (!(state->key_length & 7))
    return libkeccak_fast_update(&(state->sponge), msg, msglen);
  
  if (msglen != state->buffer_size)
    {
      state->buffer = realloc(old = state->buffer, state->buffer_size = msglen);
      if (state->buffer == NULL)
	return state->buffer = old, -1;
    }
  
  n = (int)(state->key_length & 7);
  cn = 8 - n;
  for (i = 1; i < msglen; i++)
    state->buffer[i] = (((unsigned char)(msg[i - 1])) >> cn) | (msg[i] << n);
  state->buffer[0] = (state->leftover & ((1 << n) - 1)) | (msg[0] << n);
  state->leftover = ((unsigned char)(msg[msglen - 1])) >> cn;
  
  return libkeccak_fast_update(&(state->sponge), state->buffer, msglen);
}


/**
 * Absorb more, or the first part, of the message
 * and wipe sensitive data when possible
 * 
 * @param   state   The hashing state
 * @param   msg     The partial message
 * @param   msglen  The length of the partial message, in bytes
 * @return          Zero on success, -1 on error
 */
__attribute__((nonnull))
int libkeccak_hmac_update(libkeccak_hmac_state_t* restrict state, const char* restrict msg, size_t msglen)
{
  size_t i;
  int n, cn, r, saved_errno;
  
  if (state->key_ipad != NULL)
    {
      if (libkeccak_update(&(state->sponge), state->key_ipad, state->key_length >> 3) < 0)
	return -1;
      if (state->key_length & 7)
	state->leftover = state->key_ipad[(state->key_length >> 3)];
      state->key_ipad = NULL;
    }
  
  if (!(state->key_length & 7))
    return libkeccak_update(&(state->sponge), msg, msglen);
  
  if (msglen != state->buffer_size)
    {
      free(state->buffer);
      state->buffer = malloc(state->buffer_size = msglen);
      if (state->buffer == NULL)
	return -1;
    }
  
  n = (int)(state->key_length & 7);
  cn = 8 - n;
  for (i = 1; i < msglen; i++)
    state->buffer[i] = (((unsigned char)(msg[i - 1])) >> cn) | (msg[i] << n);
  state->buffer[0] = (state->leftover & ((1 << n) - 1)) | (msg[0] << n);
  state->leftover = ((unsigned char)(msg[msglen - 1])) >> cn;
  
  r = libkeccak_update(&(state->sponge), state->buffer, msglen);
  saved_errno = errno;
  __builtin_memset(state->buffer, 0, msglen);
  errno = saved_errno;
  return r;
}

