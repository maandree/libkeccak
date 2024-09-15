/* See LICENSE file for copyright and license details. */


/**
 * Reset a state according to hashing specifications
 * 
 * @param  state  The state that should be reset
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
inline void
libkeccak_state_reset(struct libkeccak_state *state)
{
	state->mptr = 0;
	memset(&state->S, 0, sizeof(state->S));
}


/**
 * Wipe data in the state's message without freeing any data
 * 
 * @param  state  The state that should be wipe
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__, __nothrow__, __optimize__("-O0"))))
void libkeccak_state_wipe_message(volatile struct libkeccak_state *);


/**
 * Wipe data in the state's sponge without freeing any data
 * 
 * @param  state  The state that should be wipe
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__, __nothrow__, __optimize__("-O0"))))
void libkeccak_state_wipe_sponge(volatile struct libkeccak_state *);


/**
 * Wipe sensitive data without freeing any data
 * 
 * @param  state  The state that should be wipe
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __optimize__("-O0"))))
void libkeccak_state_wipe(volatile struct libkeccak_state *);


/**
 * Wrapper for `libkeccak_state_initialise` that also allocates the states
 * 
 * @param   spec  The specifications for the state
 * @return        The state, `NULL` on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __warn_unused_result__, __malloc__)))
struct libkeccak_state *libkeccak_state_create(const struct libkeccak_spec *);


/**
 * Release resources allocation for a state,
 * without wiping sensitive data, and deallocate
 * the state object itself
 * 
 * @param  state  The state that should be freed
 */
inline void
libkeccak_state_fast_free(struct libkeccak_state *state)
{
	if (state) {
		free(state->M);
		state->M = NULL;
		free(state);
	}
}


/**
 * Release resources allocation for a state, and wipe
 * sensitive data, and deallocate the state object itself
 * 
 * @param  state  The state that should be freed
 */
LIBKECCAK_GCC_ONLY(__attribute__((__optimize__("-O0"))))
inline void
libkeccak_state_free(volatile struct libkeccak_state *state)
{
#ifdef __GNUC__
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wcast-qual"
#endif
	if (state) {
		libkeccak_state_wipe(state);
		free(state->M);
		state->M = NULL;
		free((struct libkeccak_state *)state);
	}
#ifdef __GNUC__
# pragma GCC diagnostic pop
#endif
}


/**
 * Make a copy of a state
 * 
 * @param   dest  The slot for the duplicate, must not be initialised (memory leak otherwise)
 * @param   src   The state to duplicate
 * @return        Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__)))
int libkeccak_state_copy(struct libkeccak_state *restrict, const struct libkeccak_state *restrict);


/**
 * A wrapper for `libkeccak_state_copy` that also allocates the duplicate
 * 
 * @param   src  The state to duplicate
 * @return       The duplicate, `NULL` on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __warn_unused_result__, __malloc__)))
struct libkeccak_state *libkeccak_state_duplicate(const struct libkeccak_state *);


/**
 * Marshal a `struct libkeccak_state` into a buffer
 * 
 * @param   state  The state to marshal
 * @param   data   The output buffer, can be `NULL`
 * @return         The number of bytes stored to `data`
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__(1), __nothrow__)))
size_t libkeccak_state_marshal(const struct libkeccak_state *restrict, void *restrict);


/**
 * Unmarshal a `struct libkeccak_state` from a buffer
 * 
 * @param   state  The slot for the unmarshalled state, must not be
 *                 initialised (memory leak otherwise), can be `NULL`
 * @param   data   The input buffer
 * @return         The number of bytes read from `data`, 0 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__leaf__, __nonnull__(2))))
size_t libkeccak_state_unmarshal(struct libkeccak_state *restrict, const void *restrict);
