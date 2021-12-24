/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Make a copy of a state
 * 
 * @param   dest  The slot for the duplicate, must not be initialised (memory leak otherwise)
 * @param   src   The state to duplicate
 * @return        Zero on success, -1 on error
 */
int
libkeccak_state_copy(struct libkeccak_state *restrict dest, const struct libkeccak_state *restrict src)
{
	memcpy(dest, src, sizeof(struct libkeccak_state));
	if (src->mlen) {
		dest->M = malloc(src->mlen * sizeof(char));
		if (!dest->M)
			return -1;
		memcpy(dest->M, src->M, src->mptr * sizeof(char));
	} else {
		dest->M = NULL;
	}
	return 0;
}
