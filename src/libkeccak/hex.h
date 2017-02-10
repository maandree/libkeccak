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
#ifndef LIBKECCAK_HEX_H
#define LIBKECCAK_HEX_H  1


#include "internal.h"

#include <stddef.h>


/**
 * Convert a binary hashsum to lower case hexadecimal representation
 * 
 * @param  output   Output array, should have an allocation size of at least `2 * n + 1`
 * @param  hashsum  The hashsum to convert
 * @param  n        The size of `hashsum`
 */
LIBKECCAK_GCC_ONLY(__attribute__((leaf, nonnull, nothrow)))
void libkeccak_behex_lower(char* restrict output, const char* restrict hashsum, size_t n);


/**
 * Convert a binary hashsum to upper case hexadecimal representation
 * 
 * @param  output   Output array, should have an allocation size of at least `2 * n + 1`
 * @param  hashsum  The hashsum to convert
 * @param  n        The size of `hashsum`
 */
LIBKECCAK_GCC_ONLY(__attribute__((leaf, nonnull, nothrow)))
void libkeccak_behex_upper(char* restrict output, const char* restrict hashsum, size_t n);


/**
 * Convert a hexadecimal hashsum (both lower case, upper
 * case and mixed is supported) to binary representation
 * 
 * @param  output   Output array, should have an allocation size of at least `strlen(hashsum) / 2`
 * @param  hashsum  The hashsum to convert
 */
LIBKECCAK_GCC_ONLY(__attribute__((leaf, nonnull, nothrow)))
void libkeccak_unhex(char* restrict output, const char* restrict hashsum);


#endif

