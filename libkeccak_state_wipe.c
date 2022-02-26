/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Wipe sensitive data wihout freeing any data
 * 
 * @param  state  The state that should be wipe
 */
void
libkeccak_state_wipe(volatile struct libkeccak_state *state)
{
	libkeccak_state_wipe_message(state);
	libkeccak_state_wipe_sponge(state);
}
