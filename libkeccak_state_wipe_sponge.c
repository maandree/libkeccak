/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Wipe data in the state's sponge wihout freeing any data
 * 
 * @param  state  The state that should be wipe
 */
void
libkeccak_state_wipe_sponge(volatile struct libkeccak_state *state)
{
	volatile int64_t *restrict S = state->S;
	size_t i;

	for (i = 0; i < 25; i++)
		S[i] = 0;
}
