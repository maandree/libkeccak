/* See LICENSE file for copyright and license details. */
#include "files.h"

#include <sys/stat.h>
#include <alloca.h>
#include <errno.h>
#include <stddef.h>
#include <unistd.h>



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
libkeccak_generalised_sum_fd(int fd, libkeccak_state_t *restrict state,
                             const libkeccak_spec_t *restrict spec,
                             const char *restrict suffix, char *restrict hashsum)
{
	ssize_t got;
	struct stat attr;
	size_t blksize = 4096;
	char *restrict chunk;

	if (libkeccak_state_initialise(state, spec) < 0)
		return -1;

	if (fstat(fd, &attr) == 0)
		if (attr.st_blksize > 0)
			blksize = (size_t)(attr.st_blksize);
  
	chunk = alloca(blksize);

	for (;;) {
		got = read(fd, chunk, blksize);
		if (got < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (got == 0)
			break;
		if (libkeccak_fast_update(state, chunk, (size_t)got) < 0)
			return -1;
	}

	return libkeccak_fast_digest(state, NULL, 0, 0, suffix, hashsum);
}
