/* See LICENSE file for copyright and license details. */


/**
 * Message suffix for RawSHAKE hashing
 */
#define LIBKECCAK_RAWSHAKE_SUFFIX "11"


/**
 * Fill in a `struct libkeccak_spec` for a RawSHAKEx hashing
 * 
 * @param  spec  The specifications datastructure to fill in
 * @param  x     The value of x in `RawSHAKEx`, half the capacity
 * @param  d     The output size
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
inline void
libkeccak_spec_rawshake(struct libkeccak_spec *spec, long int x, long int d)
{
	spec->bitrate = 1600 - 2 * x;
	spec->capacity = 2 * x;
	spec->output = d;
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
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(2), __artificial__)))
inline int
libkeccak_rawshakesum_fd(int fd, struct libkeccak_state *restrict state, long semicapacity, long output, void *restrict hashsum)
{
	struct libkeccak_spec spec;
	libkeccak_spec_rawshake(&spec, semicapacity, output);
	return libkeccak_generalised_sum_fd(fd, state, &spec, LIBKECCAK_RAWSHAKE_SUFFIX, hashsum);
}
