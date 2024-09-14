/* See LICENSE file for copyright and license details. */


/**
 * Message suffix for SHA3 hashing
 */
#define LIBKECCAK_SHA3_SUFFIX "01"


/**
 * Fill in a `struct libkeccak_spec` for a SHA3-x hashing
 * 
 * @param  spec  The specifications datastructure to fill in
 * @param  x     The value of x in `SHA3-x`, the output size
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
inline void
libkeccak_spec_sha3(struct libkeccak_spec *spec, long int x)
{
	spec->bitrate = 1600 - 2 * x;
	spec->capacity = 2 * x;
	spec->output = x;
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
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(2), __artificial__)))
inline int
libkeccak_sha3sum_fd(int fd, struct libkeccak_state *restrict state, long output, void *restrict hashsum)
{
	struct libkeccak_spec spec;
	libkeccak_spec_sha3(&spec, output);
	return libkeccak_generalised_sum_fd(fd, state, &spec, LIBKECCAK_SHA3_SUFFIX, hashsum);
}
