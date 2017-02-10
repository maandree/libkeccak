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
#ifndef LIBKECCAK_FILES_H
#define LIBKECCAK_FILES_H  1


#include "../libkeccak.h"
#include "internal.h"


/**
 * Calculate a Keccak-family hashsum of a file,
 * the content of the file is assumed non-sensitive
 * 
 * @param   fd       The file descriptor of the file to hash
 * @param   state    The hashing state, should not be initialised (memory leak otherwise)
 * @param   spec     Specifications for the hashing algorithm
 * @param   suffix   The data suffix, see `libkeccak_digest`
 * @param   hashsum  Output array for the hashsum, have an allocation size of
 *                   at least `((spec->output + 7) / 8) * sizeof(char)`, may be `NULL`
 * @return           Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull(2, 3))))
int libkeccak_generalised_sum_fd(int fd, libkeccak_state_t* restrict state,
				 const libkeccak_spec_t* restrict spec,
				 const char* restrict suffix, char* restrict hashsum);


/**
 * Calculate the Keccak hashsum of a file,
 * the content of the file is assumed non-sensitive
 * 
 * @param   fd       The file descriptor of the file to hash
 * @param   state    The hashing state, should not be initialised (memory leak otherwise)
 * @param   spec     Specifications for the hashing algorithm
 * @param   hashsum  Output array for the hashsum, have an allocation size of
 *                   at least `((spec->output + 7) / 8) * sizeof(char)`, may be `NULL`
 * @return           Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull(2, 3), artificial, gnu_inline)))
static inline
int libkeccak_keccaksum_fd(int fd, libkeccak_state_t* restrict state,
			   const libkeccak_spec_t* restrict spec, char* restrict hashsum)
{
  return libkeccak_generalised_sum_fd(fd, state, spec, NULL, hashsum);
}


/**
 * Calculate the SHA3 hashsum of a file,
 * the content of the file is assumed non-sensitive
 * 
 * @param   fd       The file descriptor of the file to hash
 * @param   state    The hashing state, should not be initialised (memory leak otherwise)
 * @param   output   The output size parameter for the hashing algorithm
 * @param   hashsum  Output array for the hashsum, have an allocation size of
 *                   at least `((output + 7) / 8) * sizeof(char)`, may be `NULL`
 * @return           Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull(2), artificial, gnu_inline)))
static inline
int libkeccak_sha3sum_fd(int fd, libkeccak_state_t* restrict state,
			 long output, char* restrict hashsum)
{
  libkeccak_spec_t spec;
  libkeccak_spec_sha3(&spec, output);
  return libkeccak_generalised_sum_fd(fd, state, &spec, LIBKECCAK_SHA3_SUFFIX, hashsum);
}


/**
 * Calculate the RawSHAKE hashsum of a file,
 * the content of the file is assumed non-sensitive
 * 
 * @param   fd            The file descriptor of the file to hash
 * @param   state         The hashing state, should not be initialised (memory leak otherwise)
 * @param   semicapacity  The semicapacity parameter for the hashing algorithm
 * @param   output        The output size parameter for the hashing algorithm
 * @param   hashsum       Output array for the hashsum, have an allocation size of
 *                        at least `((output + 7) / 8) * sizeof(char)`, may be `NULL`
 * @return                Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull(2), artificial, gnu_inline)))
static inline
int libkeccak_rawshakesum_fd(int fd, libkeccak_state_t* restrict state,
			     long semicapacity, long output, char* restrict hashsum)
{
  libkeccak_spec_t spec;
  libkeccak_spec_rawshake(&spec, semicapacity, output);
  return libkeccak_generalised_sum_fd(fd, state, &spec, LIBKECCAK_RAWSHAKE_SUFFIX, hashsum);
}


/**
 * Calculate the SHAKE hashsum of a file,
 * the content of the file is assumed non-sensitive
 * 
 * @param   fd            The file descriptor of the file to hash
 * @param   state         The hashing state, should not be initialised (memory leak otherwise)
 * @param   semicapacity  The semicapacity parameter for the hashing algorithm
 * @param   output        The output size parameter for the hashing algorithm
 * @param   hashsum       Output array for the hashsum, have an allocation size of
 *                        at least `((output + 7) / 8) * sizeof(char)`, may be `NULL`
 * @return                Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((nonnull(2), artificial, gnu_inline)))
static inline
int libkeccak_shakesum_fd(int fd, libkeccak_state_t* restrict state,
			  long semicapacity, long output, char* restrict hashsum)
{
  libkeccak_spec_t spec;
  libkeccak_spec_shake(&spec, semicapacity, output);
  return libkeccak_generalised_sum_fd(fd, state, &spec, LIBKECCAK_SHAKE_SUFFIX, hashsum);
}


#endif

