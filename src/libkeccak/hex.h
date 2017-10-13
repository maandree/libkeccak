/* See LICENSE file for copyright and license details. */
#ifndef LIBKECCAK_HEX_H
#define LIBKECCAK_HEX_H 1

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
void libkeccak_behex_lower(char *restrict output, const char *restrict hashsum, size_t n);


/**
 * Convert a binary hashsum to upper case hexadecimal representation
 * 
 * @param  output   Output array, should have an allocation size of at least `2 * n + 1`
 * @param  hashsum  The hashsum to convert
 * @param  n        The size of `hashsum`
 */
LIBKECCAK_GCC_ONLY(__attribute__((leaf, nonnull, nothrow)))
void libkeccak_behex_upper(char *restrict output, const char *restrict hashsum, size_t n);


/**
 * Convert a hexadecimal hashsum (both lower case, upper
 * case and mixed is supported) to binary representation
 * 
 * @param  output   Output array, should have an allocation size of at least `strlen(hashsum) / 2`
 * @param  hashsum  The hashsum to convert
 */
LIBKECCAK_GCC_ONLY(__attribute__((leaf, nonnull, nothrow)))
void libkeccak_unhex(char *restrict output, const char *restrict hashsum);


#endif

