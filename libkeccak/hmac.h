/* See LICENSE file for copyright and license details. */


/*
 * The Keccak hash-function, that was selected by NIST as the SHA-3 competition winner,
 * doesn't need this nested approach and can be used to generate a MAC by simply prepending
 * the key to the message. [http://keccak.noekeon.org] HMAC-SHA3-224, HMAC-SHA3-256,
 * HMAC-SHA3-384, and HMAC-SHA3-512 are however approved by NIST.
 */


/**
 * Data structure that describes the state of an HMAC-hashing process
 */
struct libkeccak_hmac_state {
	/**
	 * The key right-padded and XOR:ed with the outer pad
	 */
	unsigned char *restrict key_opad;

	/**
	 * The key right-padded and XOR:ed with the inner pad
	 */
	unsigned char *restrict key_ipad;
	/* Not marshalled, implicitly unmarshalled using `key_opad`. */
	/* Shares allocation with `key_opad`, do not `free`. */

	/**
	 * The length of key, but at least the input block size, in bits
	 */
	size_t key_length;

	/**
	 * The state of the underlaying hash-algorithm
	 */
	struct libkeccak_state sponge;

	/**
	 * Buffer used to temporarily store bit shift message if
	 * `.key_length` is not zero modulus 8
	 */
	unsigned char *restrict buffer;

	/**
	 * The allocation size of `.buffer`
	 */
	size_t buffer_size;

	/**
	 * Part of feed key, message or digest that have not been passed yet
	 */
	unsigned char leftover;

	char _pad[sizeof(void *) - 1];
};


/**
 * Change the HMAC-hashing key on the state
 * 
 * @param   state       The state that should be reset
 * @param   key         The new key
 * @param   key_length  The length of key, in bits
 * @return              Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1))))
int libkeccak_hmac_set_key(struct libkeccak_hmac_state *restrict, const void *restrict, size_t);


/**
 * Initialise an HMAC hashing-state according to hashing specifications
 * 
 * @param   state       The state that should be initialised
 * @param   spec        The specifications for the state
 * @param   key         The key
 * @param   key_length  The length of key, in bits
 * @return              Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__)))
inline int
libkeccak_hmac_initialise(struct libkeccak_hmac_state *restrict state, const struct libkeccak_spec *restrict spec,
                          const void *restrict key, size_t key_length)
{
	if (libkeccak_state_initialise(&state->sponge, spec) < 0)
		return -1;
	if (libkeccak_hmac_set_key(state, key, key_length) < 0) {
		libkeccak_state_destroy(&state->sponge);
		return -1;
	}
	state->leftover = 0;
	state->buffer = NULL;
	state->buffer_size = 0;
	return 0;
}


/**
 * Wrapper for `libkeccak_hmac_initialise` that also allocates the states
 * 
 * @param   spec        The specifications for the state
 * @param   key         The key
 * @param   key_length  The length of key, in bits
 * @return              The state, `NULL` on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __warn_unused_result__, __malloc__)))
inline struct libkeccak_hmac_state *
libkeccak_hmac_create(const struct libkeccak_spec *restrict spec, const void *restrict key, size_t key_length)
{
	struct libkeccak_hmac_state *state = malloc(sizeof(struct libkeccak_hmac_state));
	if (!state || libkeccak_hmac_initialise(state, spec, key, key_length)) {
		free(state);
		return NULL;
	}
	return state;
}


/**
 * Reset an HMAC-hashing state according to hashing specifications,
 * you can choose whether to change the key
 * 
 * @param   state       The state that should be reset
 * @param   key         The new key, `NULL` to keep the old key
 * @param   key_length  The length of key, in bits, ignored if `key == NULL`
 * @return              Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1))))
inline int
libkeccak_hmac_reset(struct libkeccak_hmac_state *restrict state, const void *restrict key, size_t key_length)
{
	libkeccak_state_reset(&state->sponge);
	return key ? libkeccak_hmac_set_key(state, key, key_length) : 0;
}


/**
 * Wipe sensitive data wihout freeing any data
 * 
 * @param  state  The state that should be wipe
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __optimize__("-O0"))))
void libkeccak_hmac_wipe(volatile struct libkeccak_hmac_state *);


/**
 * Release resources allocation for an HMAC hashing-state without wiping sensitive data
 * 
 * @param  state  The state that should be destroyed
 */
inline void
libkeccak_hmac_fast_destroy(struct libkeccak_hmac_state *state)
{
	if (!state)
		return;
	free(state->key_opad);
	state->key_opad = NULL;
	state->key_ipad = NULL;
	state->key_length = 0;
	free(state->buffer);
	state->buffer = NULL;
	state->buffer_size = 0;
}


/**
 * Release resources allocation for an HMAC hasing-state and wipe sensitive data
 * 
 * @param  state  The state that should be destroyed
 */
LIBKECCAK_GCC_ONLY(__attribute__((__optimize__("-O0"))))
inline void
libkeccak_hmac_destroy(volatile struct libkeccak_hmac_state *state)
{
	if (!state)
		return;
	libkeccak_hmac_wipe(state);
	free(state->key_opad);
	state->key_opad = NULL;
	state->key_ipad = NULL;
	state->key_length = 0;
	state->leftover = 0;
	free(state->buffer);
	state->buffer = NULL;
	state->buffer_size = 0;
}


/**
 * Wrapper for `libkeccak_fast_destroy` that also frees the allocation of the state
 * 
 * @param  state  The state that should be freed
 */
inline void
libkeccak_hmac_fast_free(struct libkeccak_hmac_state *state)
{
	libkeccak_hmac_fast_destroy(state);
	free(state);
}


/**
 * Wrapper for `libkeccak_hmac_destroy` that also frees the allocation of the state
 * 
 * @param  state  The state that should be freed
 */
LIBKECCAK_GCC_ONLY(__attribute__((__optimize__("-O0"))))
inline void
libkeccak_hmac_free(volatile struct libkeccak_hmac_state *state)
{
#ifdef __GNUC__
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wcast-qual"
#endif
	libkeccak_hmac_destroy(state);
	free((struct libkeccak_hmac_state *)state);
#ifdef __GNUC__
# pragma GCC diagnostic pop
#endif
}


/**
 * Make a copy of an HMAC hashing-state
 * 
 * @param   dest  The slot for the duplicate, must not be initialised (memory leak otherwise)
 * @param   src   The state to duplicate
 * @return        Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__)))
int libkeccak_hmac_copy(struct libkeccak_hmac_state *restrict, const struct libkeccak_hmac_state *restrict);


/**
 * A wrapper for `libkeccak_hmac_copy` that also allocates the duplicate
 * 
 * @param   src  The state to duplicate
 * @return       The duplicate, `NULL` on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __warn_unused_result__, __malloc__)))
inline struct libkeccak_hmac_state *
libkeccak_hmac_duplicate(const struct libkeccak_hmac_state *src)
{
	struct libkeccak_hmac_state *dest = malloc(sizeof(struct libkeccak_hmac_state));
	if (!dest || libkeccak_hmac_copy(dest, src)) {
		libkeccak_hmac_free(dest);
		return NULL;
	}
	return dest;
}


/**
 * Marshal a `struct libkeccak_hmac_state` into a buffer
 * 
 * @param   state  The state to marshal
 * @param   data   The output buffer, can be `NULL`
 * @return         The number of bytes stored to `data`
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1), __nothrow__)))
inline size_t
libkeccak_hmac_marshal(const struct libkeccak_hmac_state *restrict state, void *restrict data_)
{
	unsigned char *restrict data = data_;
	size_t written = libkeccak_state_marshal(&state->sponge, data);
	if (data) {
		data += written;
#if defined(__clang__)
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wcast-align"
#endif
		memcpy(data, &state->key_length, sizeof(state->key_length));
#if defined(__clang__)
# pragma clang diagnostic pop
#endif
		data += sizeof(size_t);
		memcpy(data, state->key_opad, (state->key_length + 7) >> 3);
		data += (state->key_length + 7) >> 3;
		data[0] = (unsigned char)!!state->key_ipad;
		data[1] = state->leftover;
	}
	return written + sizeof(size_t) + ((state->key_length + 7) >> 3) + 2 * sizeof(char);
}


/**
 * Unmarshal a `struct libkeccak_hmac_state` from a buffer
 * 
 * @param   state  The slot for the unmarshalled state, must not be
 *                 initialised (memory leak otherwise), can be `NULL`
 * @param   data   The input buffer
 * @return         The number of bytes read from `data`, 0 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(2))))
size_t libkeccak_hmac_unmarshal(struct libkeccak_hmac_state *restrict, const void *restrict);


/**
 * Absorb more, or the first part, of the message
 * without wiping sensitive data when possible
 * 
 * @param   state   The hashing state
 * @param   msg     The partial message
 * @param   msglen  The length of the partial message, in bytes
 * @return          Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1))))
int libkeccak_hmac_fast_update(struct libkeccak_hmac_state *restrict state, const void *restrict msg, size_t msglen);


/**
 * Absorb more, or the first part, of the message
 * and wipe sensitive data when possible
 * 
 * @param   state   The hashing state
 * @param   msg     The partial message
 * @param   msglen  The length of the partial message, in bytes
 * @return          Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1))))
int libkeccak_hmac_update(struct libkeccak_hmac_state *restrict state, const void *restrict msg, size_t msglen);


/**
 * Absorb the last part of the message and fetch the hash
 * without wiping sensitive data when possible
 * 
 * You may use `&state->sponge` for continued squeezing
 * 
 * @param   state    The hashing state
 * @param   msg      The rest of the message, may be `NULL`, may be modified
 * @param   msglen   The length of the partial message
 * @param   bits     The number of bits at the end of the message not covered by `msglen`
 * @param   suffix   The suffix concatenate to the message, only '1':s and '0':s, and NUL-termination
 * @param   hashsum  Output parameter for the hashsum, may be `NULL`
 * @return           Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1))))
int libkeccak_hmac_fast_digest(struct libkeccak_hmac_state *restrict state, const void *restrict msg, size_t msglen,
                               size_t bits, const char *restrict suffix, void *restrict hashsum);


/**
 * Absorb the last part of the message and fetch the hash
 * and wipe sensitive data when possible
 * 
 * You may use `&state->sponge` for continued squeezing
 * 
 * @param   state    The hashing state
 * @param   msg      The rest of the message, may be `NULL`, may be modified
 * @param   msglen   The length of the partial message
 * @param   bits     The number of bits at the end of the message not covered by `msglen`
 * @param   suffix   The suffix concatenate to the message, only '1':s and '0':s, and NUL-termination
 * @param   hashsum  Output parameter for the hashsum, may be `NULL`
 * @return           Zero on success, -1 on error
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1))))
int libkeccak_hmac_digest(struct libkeccak_hmac_state *restrict state, const void *restrict msg, size_t msglen,
                          size_t bits, const char *restrict suffix, void *restrict hashsum);
