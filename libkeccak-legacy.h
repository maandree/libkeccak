/* See LICENSE file for copyright and license details. */


LIBKECCAK_GCC_ONLY(__attribute__((__deprecated__("Use struct libkeccak_spec instead of libkeccak_spec_t"))))
typedef struct libkeccak_spec libkeccak_spec_t;

LIBKECCAK_GCC_ONLY(__attribute__((__deprecated__("Use struct libkeccak_generalised_spec instead of libkeccak_generalised_spec_t"))))
typedef struct libkeccak_generalised_spec libkeccak_generalised_spec_t;

LIBKECCAK_GCC_ONLY(__attribute__((__deprecated__("Use struct libkeccak_state instead of libkeccak_state_t"))))
typedef struct libkeccak_state libkeccak_state_t;

LIBKECCAK_GCC_ONLY(__attribute__((__deprecated__("Use struct libkeccak_hmac_state instead of libkeccak_hmac_state_t"))))
typedef struct libkeccak_hmac_state libkeccak_hmac_state_t;

LIBKECCAK_GCC_ONLY(__attribute__((__deprecated__("Use libkeccak_hmac_unmarshal(NULL, data) instead of libkeccak_hmac_unmarshal_skip(data)"))))
static inline size_t
libkeccak_hmac_unmarshal_skip(const void *data)
{
	return libkeccak_hmac_unmarshal(NULL, data);
}

LIBKECCAK_GCC_ONLY(__attribute__((__deprecated__("Use libkeccak_state_unmarshal(NULL, data) instead of libkeccak_state_unmarshal_skip(data)"))))
static inline size_t
libkeccak_state_unmarshal_skip(const void *data)
{
	return libkeccak_state_unmarshal(NULL, data);
}

LIBKECCAK_GCC_ONLY(__attribute__((__deprecated__("Use libkeccak_hmac_marshal(state, NULL) instead of libkeccak_hmac_marshal_size(state)"))))
static inline size_t
libkeccak_hmac_marshal_size(const struct libkeccak_hmac_state *state)
{
	return libkeccak_hmac_marshal(state, NULL);
}

LIBKECCAK_GCC_ONLY(__attribute__((__deprecated__("Use libkeccak_state_marshal(state, NULL) instead of libkeccak_state_marshal_size(state)"))))
static inline size_t
libkeccak_state_marshal_size(const struct libkeccak_state *state)
{
	return libkeccak_state_marshal(state, NULL);
}
