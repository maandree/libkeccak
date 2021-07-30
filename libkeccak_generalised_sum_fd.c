/* See LICENSE file for copyright and license details. */
#include "common.h"


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
int
libkeccak_generalised_sum_fd(int fd, struct libkeccak_state *restrict state, const struct libkeccak_spec *restrict spec,
                             const char *restrict suffix, void *restrict hashsum)
{
	ssize_t got;
#ifndef _WIN32
	struct stat attr;
#endif
	size_t blksize = 4096;
	void *restrict chunk;

	if (libkeccak_state_initialise(state, spec) < 0)
		return -1;

#ifndef _WIN32
	if (fstat(fd, &attr) == 0)
		if (attr.st_blksize > 0)
			blksize = (size_t)attr.st_blksize;
#endif

#if ALLOCA_LIMIT > 0
	if (blksize > (size_t)ALLOCA_LIMIT)
		blksize = (size_t)ALLOCA_LIMIT;
# if defined(__clang__)
	/* We are using a limit so it's just like declaring an array
	 * in a function, except we might use less of the stack. */
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Walloca"
# endif
	chunk = alloca(blksize);
# if defined(__clang__)
#  pragma clang diagnostic pop
# endif
#else
	chunk = malloc(blksize);
	if (!chunk)
		return -1;
#endif

	for (;;) {
		got = read(fd, chunk, blksize);
		if (got <= 0) {
			if (!got)
				break;
			if (errno == EINTR)
				continue;
			goto fail;
		}
		if (libkeccak_fast_update(state, chunk, (size_t)got) < 0)
			goto fail;
	}

	return libkeccak_fast_digest(state, NULL, 0, 0, suffix, hashsum);

fail:
#if ALLOCA_LIMIT <= 0
	free(chunk);
#endif
	return -1;
}
