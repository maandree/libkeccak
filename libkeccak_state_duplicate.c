/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * A wrapper for `libkeccak_state_copy` that also allocates the duplicate
 * 
 * @param   src  The state to duplicate
 * @return       The duplicate, `NULL` on error
 */
struct libkeccak_state *
libkeccak_state_duplicate(const struct libkeccak_state *src)
{
	struct libkeccak_state *dest = malloc(sizeof(struct libkeccak_state));
	if (!dest || libkeccak_state_copy(dest, src)) {
		libkeccak_state_free(dest);
		return NULL;
	}
	return dest;
}
