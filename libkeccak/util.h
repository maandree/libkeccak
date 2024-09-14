/* See LICENSE file for copyright and license details. */


/**
 * Convert a binary hashsum to lower case hexadecimal representation
 * 
 * @param  output   Output array, should have an allocation size of at least `2 * n + 1`
 * @param  hashsum  The hashsum to convert
 * @param  n        The size of `hashsum`
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__, __nothrow__)))
void libkeccak_behex_lower(char *restrict, const void *restrict, size_t);


/**
 * Convert a binary hashsum to upper case hexadecimal representation
 * 
 * @param  output   Output array, should have an allocation size of at least `2 * n + 1`
 * @param  hashsum  The hashsum to convert
 * @param  n        The size of `hashsum`
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__, __nothrow__)))
void libkeccak_behex_upper(char *restrict, const void *restrict, size_t);


/**
 * Convert a hexadecimal hashsum (both lower case, upper
 * case and mixed is supported) to binary representation
 * 
 * @param  output   Output array, should have an allocation size of at least `strlen(hashsum) / 2`
 * @param  hashsum  The hashsum to convert
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__, __nothrow__)))
void libkeccak_unhex(void *restrict, const char *restrict);


/**
 * Calculate a Keccak-family hashsum of a file,
 * the content of the file is assumed non-sensitive
 * 
 * @param   fd       The file descriptor of the file to hash
 * @param   state    The hashing state, should not be initialised unless
 *                   `spec` is `NULL` (memory leak otherwise)
 * @param   spec     Specifications for the hashing algorithm; or `NULL`
 *                   if `spec` is already initialised
 * @param   spec     Specifications for the hashing algorithm
 * @param   suffix   The data suffix, see `libkeccak_digest`
 * @param   hashsum  Output array for the hashsum, have an allocation size of
 *                   at least `((spec->output + 7) / 8) * sizeof(char)`, may be `NULL`
 * @return           Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(2))))
int libkeccak_generalised_sum_fd(int, struct libkeccak_state *restrict, const struct libkeccak_spec *restrict,
                                 const char *restrict, void *restrict);
