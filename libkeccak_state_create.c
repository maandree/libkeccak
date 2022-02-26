/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Wrapper for `libkeccak_state_initialise` that also allocates the states
 * 
 * @param   spec  The specifications for the state
 * @return        The state, `NULL` on error
 */
struct libkeccak_state *
libkeccak_state_create(const struct libkeccak_spec *spec)
{
	struct libkeccak_state *state = malloc(sizeof(struct libkeccak_state));
	if (!state || libkeccak_state_initialise(state, spec)) {
		free(state);
		return NULL;
	}
	return state;
}
