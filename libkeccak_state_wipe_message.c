/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Wipe data in the state's message wihout freeing any data
 * 
 * @param  state  The state that should be wipe
 */
void
libkeccak_state_wipe_message(volatile struct libkeccak_state *state)
{
	volatile unsigned char *restrict M = state->M;
	size_t i;

	for (i = 0; i < state->mptr; i++)
		M[i] = 0;
}
