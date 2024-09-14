/* See LICENSE file for copyright and license details. */


/**
 * Message suffix for SHAKE hashing
 */
#define LIBKECCAK_SHAKE_SUFFIX "1111"


/**
 * Fill in a `struct libkeccak_spec` for a SHAKEx hashing
 * 
 * @param  spec:struct libkeccak_spec *  The specifications datastructure to fill in
 * @param  x:long                        The value of x in `SHAKEx`, half the capacity
 * @param  d:long                        The output size
 */
#define libkeccak_spec_shake libkeccak_spec_rawshake


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
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(2), __artificial__)))
inline int
libkeccak_shakesum_fd(int fd, struct libkeccak_state *restrict state, long semicapacity, long output, void *restrict hashsum)
{
	struct libkeccak_spec spec;
	libkeccak_spec_shake(&spec, semicapacity, output);
	return libkeccak_generalised_sum_fd(fd, state, &spec, LIBKECCAK_SHAKE_SUFFIX, hashsum);
}
