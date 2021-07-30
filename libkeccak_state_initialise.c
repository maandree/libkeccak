/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Initialise a state according to hashing specifications
 * 
 * @param   state  The state that should be initialised
 * @param   spec   The specifications for the state
 * @return         Zero on success, -1 on error
 */
int
libkeccak_state_initialise(struct libkeccak_state *restrict state, const struct libkeccak_spec *restrict spec)
{
	long int x;

	state->r = spec->bitrate;
	state->n = spec->output;
	state->c = spec->capacity;
	state->b = state->r + state->c;
	state->w = x = state->b / 25;
	state->l = 0;

	if (x & 0xF0L) {
		state->l |= 4;
		x >>= 4;
	}
	if (x & 0x0CL) {
		state->l |= 2;
		x >>= 2;
	}
	if (x & 0x02L) {
		state->l |= 1;
	}

	state->nr = 12 + (state->l << 1);
	state->wmod = (state->w == 64) ? ~0LL : (int64_t)((1ULL << state->w) - 1);
	for (x = 0; x < 25; x++)
		state->S[x] = 0;
	state->mptr = 0;
	state->mlen = (size_t)(state->r * state->b) >> 2;

	state->M = malloc(state->mlen * sizeof(char));
	return state->M == NULL ? -1 : 0;
}
