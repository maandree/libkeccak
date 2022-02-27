/* See LICENSE file for copyright and license details. */
#include "common.h"
#include <stdio.h>


/**
 * Calculate a Keccak-family hashsum of a file,
 * the content of the file is assumed non-sensitive
 * 
 * @param   fd       The file descriptor of the file to hash
 * @param   state    The hashing state, should not be initialised unless
 *                   `spec` is `NULL` (memory leak otherwise)
 * @param   spec     Specifications for the hashing algorithm; or `NULL`
 *                   if `spec` is already initialised
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
	size_t offset;
#ifndef _WIN32
	struct stat attr;
#endif
	size_t blksize = 4096;
	unsigned char *restrict chunk;
	size_t chunksize, extrasize, extrachunks;
	size_t chunks, chunkmod;

	if (spec && libkeccak_state_initialise(state, spec) < 0)
		return -1;

	chunksize = libkeccak_zerocopy_chunksize(state);
	extrasize = ((suffix ? strlen(suffix) : 0) + 2 + 7) >> 3;
	extrachunks = (extrasize + (chunksize - 1)) / chunksize;

#ifndef _WIN32
	if (fstat(fd, &attr) == 0)
		if (attr.st_blksize > 0)
			blksize = (size_t)attr.st_blksize;
#endif

	chunks = blksize / chunksize;
	chunkmod = blksize % chunksize;
	if (chunkmod) {
		blksize -= chunkmod;
		blksize += chunksize;
		chunks += 1;
	}
	if (chunks < extrachunks + 1)
		blksize = (extrachunks + 1) * chunksize;

#if ALLOCA_LIMIT > 0
	if (blksize > (size_t)ALLOCA_LIMIT) {
		blksize = (size_t)ALLOCA_LIMIT;
		blksize -= blksize % chunksize;
		if (!blksize)
			blksize = chunksize;
	}
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

	offset = 0;
	for (;;) {
		got = read(fd, &chunk[offset], blksize - offset);
		if (got <= 0) {
			if (!got)
				break;
			if (errno == EINTR)
				continue;
			goto fail;
		}
		offset += (size_t)got;
		if (offset == blksize) {
			libkeccak_zerocopy_update(state, chunk, blksize);
			offset = 0;
		}
	}

	if (extrasize > blksize - offset) {
		chunkmod = offset % chunksize;
		libkeccak_zerocopy_update(state, chunk, offset - chunkmod);
		__builtin_memcpy(chunk, &chunk[offset - chunkmod], chunkmod * sizeof(char));
		offset = chunkmod;
	}

	libkeccak_zerocopy_digest(state, chunk, offset, 0, suffix, hashsum);
	return 0;

fail:
#if ALLOCA_LIMIT <= 0
	free(chunk);
#endif
	return -1;
}
