/* See LICENSE file for copyright and license details. */
#include "common.h"


#define X(N) (N % 5) * 5 + N / 5
/**
 * The order the lanes should be read when absorbing or squeezing,
 * it transposes the lanes in the sponge
 */
static const long int LANE_TRANSPOSE_MAP[] = { LIST_25(X, COMMA) };
#undef X


#include "1600.c"
#include "800.c"
#include "400.c"
#include "200.c"


/**
 * Convert a chunk of bytes to a lane
 * 
 * @param  state  The hashing state
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __gnu_inline__)))
static inline void
libkeccak_f(register struct libkeccak_state *state)
{
	register long int i = 0;
	register long int nr = state->nr;

	if (nr == 24) {
		for (; i < nr; i++)
			libkeccak_f_round64(state, rc64[i]);
	} else if (nr == 22) {
		for (; i < nr; i++)
			libkeccak_f_round32(state, rc32[i]);
	} else if (nr == 20) {
		for (; i < nr; i++)
			libkeccak_f_round16(state, rc16[i]);
	} else if (nr == 18) {
		libkeccak_f8(state);
	}
}


/**
 * Right-pad message with a 10*1-pad
 * 
 * @param   r       Should be `state->r` where `state` is the hashing state
 * @param   msg     The message to append padding to; should have `r / 8`
 *                  extra bytes allocated at the end for the function to
 *                  write the pad to
 * @param   msglen  The length of the message to append padding to
 * @param   bits    The number of bits in the end of the message that does not make a whole byte
 * @return          The length of the message after padding
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __gnu_inline__)))
static inline size_t
libkeccak_pad10star1(register size_t r, unsigned char *msg, size_t msglen, register size_t bits)
{
	register size_t nrf = msglen - !!bits;
	register size_t len = (nrf << 3) | bits;
	register size_t ll = len % r;
	register unsigned char b = (unsigned char)(bits ? (msg[nrf] | (1 << bits)) : 1);

	if (r - 8 <= ll && ll <= r - 2) {
		msg[nrf] = (unsigned char)(b ^ 0x80);
		msglen = nrf + 1;
	} else {
		len = ++nrf << 3;
		len = (len - (len % r) + (r - 8)) >> 3;
		msglen = len + 1;

		msg[nrf - 1] = b;
		__builtin_memset(&msg[nrf], 0, (len - nrf) * sizeof(char));
		msg[len] = (unsigned char)0x80;
	}
	return msglen;
}


/**
 * Perform the absorption phase
 * 
 * @param  state    The hashing state
 * @param  message  The bytes to absorb
 * @param  len      The number of bytes from `message` to absorb
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
static void
libkeccak_absorption_phase(register struct libkeccak_state *restrict state,
                           register const unsigned char *restrict message, register size_t len)
{
	register long int rr = state->r >> 3;
	register long int ww = state->w >> 3;
	register long int n = (long)len / rr;

	if (__builtin_expect(ww == 8, 1)) {
		while (n--) {
#define X(N) state->S.w64[N] ^= libkeccak_to_lane64(message, len, rr, (size_t)(LANE_TRANSPOSE_MAP[N] * 8))
			LIST_25(X, ;);
#undef X
			libkeccak_f(state);
			message += (size_t)rr;
			len -= (size_t)rr;
		}
	} else if (__builtin_expect(ww == 4, 1)) {
		while (n--) {
#define X(N) state->S.w32[N] ^= libkeccak_to_lane32(message, len, rr, (size_t)(LANE_TRANSPOSE_MAP[N] * 4))
			LIST_25(X, ;);
#undef X
			libkeccak_f(state);
			message += (size_t)rr;
			len -= (size_t)rr;
		}
	} else if (__builtin_expect(ww == 2, 1)) {
		while (n--) {
#define X(N) state->S.w16[N] ^= libkeccak_to_lane16(message, len, rr, (size_t)(LANE_TRANSPOSE_MAP[N] * 2))
			LIST_25(X, ;);
#undef X
			libkeccak_f(state);
			message += (size_t)rr;
			len -= (size_t)rr;
		}
	} else if (__builtin_expect(ww == 1, 1)) {
		while (n--) {
#define X(N) state->S.w8[N] ^= libkeccak_to_lane8(message, len, rr, (size_t)(LANE_TRANSPOSE_MAP[N] * 1))
			LIST_25(X, ;);
#undef X
			libkeccak_f(state);
			message += (size_t)rr;
			len -= (size_t)rr;
		}
	}
}


/**
 * Perform the squeezing phase
 * 
 * @param  state    The hashing state
 * @param  rr       The bitrate in bytes
 * @param  nn       The output size in bytes, rounded up to whole bytes
 * @param  ww       The word size in bytes
 * @param  hashsum  Output parameter for the hashsum
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __hot__)))
static void
libkeccak_squeezing_phase(register struct libkeccak_state *restrict state, long int rr,
                          long int nn, long int ww, register unsigned char *restrict hashsum)
{
	register long int ni = (rr - 1) / ww + 1;
	auto long int olen = state->n;
	auto long int i, j = 0;
	register long int k;
	if (__builtin_expect(ww == 8, 1)) {
		register uint64_t v;
		while (olen > 0) {
			for (i = 0; i < ni && j < nn; i++) {
				v = state->S.w64[LANE_TRANSPOSE_MAP[i]];
				for (k = 0; k++ < ww && j++ < nn; v >>= 8)
					*hashsum++ = (unsigned char)v;
			}
			olen -= state->r;
			if (olen > 0)
				libkeccak_f(state);
		}
		if (state->n & 7)
			hashsum[-1] &= (unsigned char)((1 << (state->n & 7)) - 1);
	} else if (__builtin_expect(ww == 4, 1)) {
		register uint32_t v;
		while (olen > 0) {
			for (i = 0; i < ni && j < nn; i++) {
				v = state->S.w32[LANE_TRANSPOSE_MAP[i]];
				for (k = 0; k++ < ww && j++ < nn; v >>= 8)
					*hashsum++ = (unsigned char)v;
			}
			olen -= state->r;
			if (olen > 0)
				libkeccak_f(state);
		}
		if (state->n & 7)
			hashsum[-1] &= (unsigned char)((1 << (state->n & 7)) - 1);
	} else if (__builtin_expect(ww == 2, 1)) {
		register uint16_t v;
		while (olen > 0) {
			for (i = 0; i < ni && j < nn; i++) {
				v = state->S.w16[LANE_TRANSPOSE_MAP[i]];
				for (k = 0; k++ < ww && j++ < nn; v >>= 8)
					*hashsum++ = (unsigned char)v;
			}
			olen -= state->r;
			if (olen > 0)
				libkeccak_f(state);
		}
		if (state->n & 7)
			hashsum[-1] &= (unsigned char)((1 << (state->n & 7)) - 1);
	} else if (__builtin_expect(ww == 1, 1)) {
		register uint8_t v;
		while (olen > 0) {
			for (i = 0; i < ni && j < nn; i++, j++) {
				v = state->S.w8[LANE_TRANSPOSE_MAP[i]];
				*hashsum++ = (unsigned char)v;
			}
			olen -= state->r;
			if (olen > 0)
				libkeccak_f(state);
		}
		if (state->n & 7)
			hashsum[-1] &= (unsigned char)((1 << (state->n & 7)) - 1);
	}
}


/**
 * Absorb more of the message to the Keccak sponge
 * without copying the data to an internal buffer
 * 
 * It is safe to run zero-copy functions before non-zero-copy
 * functions for the same state, running zero-copy functions
 * after non-zero-copy functions on the other hand can
 * cause the message to be misread
 * 
 * @param  state   The hashing state
 * @param  msg     The partial message
 * @param  msglen  The length of the partial message; must be a
 *                 multiple of `libkeccak_zerocopy_chunksize(state)`
 *                 (undefined behaviour otherwise)
 */
void
libkeccak_zerocopy_update(struct libkeccak_state *restrict state, const void *restrict msg, size_t msglen)
{
	libkeccak_absorption_phase(state, msg, msglen);
}


/**
 * Absorb more of the message to the Keccak sponge
 * without wiping sensitive data when possible
 * 
 * @param   state   The hashing state
 * @param   msg     The partial message
 * @param   msglen  The length of the partial message
 * @return          Zero on success, -1 on error
 */
int
libkeccak_fast_update(struct libkeccak_state *restrict state, const void *restrict msg, size_t msglen)
{
	size_t len;
	auto unsigned char *restrict new;

	if (__builtin_expect(state->mptr + msglen > state->mlen, 0)) {
		state->mlen += msglen;
		new = realloc(state->M, state->mlen * sizeof(char));
		if (!new) {
			state->mlen -= msglen;
			return -1;
		}
		state->M = new;
	}

	__builtin_memcpy(state->M + state->mptr, msg, msglen * sizeof(char));
	state->mptr += msglen;
	len = state->mptr;
	len -= state->mptr % (size_t)(state->r >> 3);
	state->mptr -= len;

	libkeccak_absorption_phase(state, state->M, len);
	__builtin_memmove(state->M, state->M + len, state->mptr * sizeof(char));

	return 0;
}


/**
 * Absorb more of the message to the Keccak sponge
 * and wipe sensitive data when possible
 * 
 * @param   state   The hashing state
 * @param   msg     The partial message
 * @param   msglen  The length of the partial message
 * @return          Zero on success, -1 on error
 */
int
libkeccak_update(struct libkeccak_state *restrict state, const void *restrict msg, size_t msglen)
{
	size_t len;
	auto unsigned char *restrict new;

	if (__builtin_expect(state->mptr + msglen > state->mlen, 0)) {
		state->mlen += msglen;
		new = malloc(state->mlen * sizeof(char));
		if (!new) {
			state->mlen -= msglen;
			return -1;
		}
		libkeccak_state_wipe_message(state);
		free(state->M);
		state->M = new;
	}

	__builtin_memcpy(state->M + state->mptr, msg, msglen * sizeof(char));
	state->mptr += msglen;
	len = state->mptr;
	len -= state->mptr % (size_t)(state->r >> 3);
	state->mptr -= len;

	libkeccak_absorption_phase(state, state->M, len);
	__builtin_memmove(state->M, state->M + len, state->mptr * sizeof(char));

	return 0;
}


/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * without copying the data to an internal buffer
 * 
 * It is safe to run zero-copy functions before non-zero-copy
 * functions for the same state, running zero-copy functions
 * after non-zero-copy functions on the other hand can
 * cause the message to be misread
 * 
 * @param  state    The hashing state
 * @param  msg_     The rest of the message; will be edited; extra memory
 *                  shall be allocated such that `suffix` and a 10*1 pad (which
 *                  is at least 2 bits long) can be added in a way that makes its
 *                  length a multiple of `libkeccak_zerocopy_chunksize(state)`
 * @param  msglen   The length of the partial message
 * @param  bits     The number of bits at the end of the message not covered by `msglen`
 * @param  suffix   The suffix concatenate to the message, only '1':s and '0':s, and NUL-termination
 * @param  hashsum  Output parameter for the hashsum, may be `NULL`
 */
void
libkeccak_zerocopy_digest(struct libkeccak_state *restrict state, void *restrict msg_, size_t msglen,
                          size_t bits, const char *restrict suffix, void *restrict hashsum)
{
	unsigned char *restrict msg = msg_;
	register long int rr = state->r >> 3;
	auto size_t suffix_len = suffix ? __builtin_strlen(suffix) : 0;
	register long int i;

	if (!msg) {
		msglen = 0;
		bits = 0;
	} else {
		msglen += bits >> 3;
		bits &= 7;
	}

	if (bits)
		msg[msglen] = msg[msglen] & (unsigned char)((1 << bits) - 1);
	if (__builtin_expect(!!suffix_len, 1)) {
		if (!bits)
			msg[msglen] = 0;
		while (suffix_len--) {
			msg[msglen] |= (unsigned char)((*suffix++ & 1) << bits++);
			if (bits == 8) {
				bits = 0;
				msg[++msglen] = 0;
			}
		}
	}
	if (bits)
		msglen++;

	msglen = libkeccak_pad10star1((size_t)state->r, msg, msglen, bits);
	libkeccak_absorption_phase(state, msg, msglen);

	if (hashsum) {
		libkeccak_squeezing_phase(state, rr, (state->n + 7) >> 3, state->w >> 3, hashsum);
	} else {
		for (i = (state->n - 1) / state->r; i--;)
			libkeccak_f(state);
	}
}


/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * without wiping sensitive data when possible
 * 
 * @param   state    The hashing state
 * @param   msg_     The rest of the message, may be `NULL`
 * @param   msglen   The length of the partial message
 * @param   bits     The number of bits at the end of the message not covered by `msglen`
 * @param   suffix   The suffix concatenate to the message, only '1':s and '0':s, and NUL-termination
 * @param   hashsum  Output parameter for the hashsum, may be `NULL`
 * @return           Zero on success, -1 on error
 */
int
libkeccak_fast_digest(struct libkeccak_state *restrict state, const void *restrict msg_, size_t msglen,
                      size_t bits, const char *restrict suffix, void *restrict hashsum)
{
	const unsigned char *restrict msg = msg_;
	auto unsigned char *restrict new;
	register long int rr = state->r >> 3;
	auto size_t suffix_len = suffix ? __builtin_strlen(suffix) : 0;
	register size_t ext;
	register long int i;

	if (!msg) {
		msglen = 0;
		bits = 0;
	} else {
		msglen += bits >> 3;
		bits &= 7;
	}

	ext = msglen + ((bits + suffix_len + 7) >> 3) + (size_t)rr;
	if (__builtin_expect(state->mptr + ext > state->mlen, 0)) {
		state->mlen += ext;
		new = realloc(state->M, state->mlen * sizeof(char));
		if (!new) {
			state->mlen -= ext;
			return -1;
		}
		state->M = new;
	}

	if (msglen)
		__builtin_memcpy(state->M + state->mptr, msg, msglen * sizeof(char));
	state->mptr += msglen;

	if (bits)
		state->M[state->mptr] = msg[msglen] & (unsigned char)((1 << bits) - 1);
	if (__builtin_expect(!!suffix_len, 1)) {
		if (!bits)
			state->M[state->mptr] = 0;
		while (suffix_len--) {
			state->M[state->mptr] |= (unsigned char)((*suffix++ & 1) << bits++);
			if (bits == 8) {
				bits = 0;
				state->M[++(state->mptr)] = 0;
			}
		}
	}
	if (bits)
		state->mptr++;

	state->mptr = libkeccak_pad10star1((size_t)state->r, state->M, state->mptr, bits);
	libkeccak_absorption_phase(state, state->M, state->mptr);

	if (hashsum) {
		libkeccak_squeezing_phase(state, rr, (state->n + 7) >> 3, state->w >> 3, hashsum);
	} else {
		for (i = (state->n - 1) / state->r; i--;)
			libkeccak_f(state);
	}

	return 0;
}


/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * and wipe sensitive data when possible
 * 
 * @param   state    The hashing state
 * @param   msg_     The rest of the message, may be `NULL`
 * @param   msglen   The length of the partial message
 * @param   bits     The number of bits at the end of the message not covered by `msglen`
 * @param   suffix   The suffix concatenate to the message, only '1':s and '0':s, and NUL-termination
 * @param   hashsum  Output parameter for the hashsum, may be `NULL`
 * @return           Zero on success, -1 on error
 */
int
libkeccak_digest(struct libkeccak_state *restrict state, const void *restrict msg_, size_t msglen,
                 size_t bits, const char *restrict suffix, void *restrict hashsum)
{
	const unsigned char *restrict msg = msg_;
	auto unsigned char *restrict new;
	register long int rr = state->r >> 3;
	auto size_t suffix_len = suffix ? __builtin_strlen(suffix) : 0;
	register size_t ext;
	register long int i;

	if (!msg) {
		msglen = 0;
		bits = 0;
	} else {
		msglen += bits >> 3;
		bits &= 7;
	}

	ext = msglen + ((bits + suffix_len + 7) >> 3) + (size_t)rr;
	if (__builtin_expect(state->mptr + ext > state->mlen, 0)) {
		state->mlen += ext;
		new = malloc(state->mlen * sizeof(char));
		if (!new) {
			state->mlen -= ext;
			return -1;
		}
		libkeccak_state_wipe_message(state);
		free(state->M);
		state->M = new;
	}

	if (msglen)
		__builtin_memcpy(state->M + state->mptr, msg, msglen * sizeof(char));
	state->mptr += msglen;

	if (bits)
		state->M[state->mptr] = msg[msglen] & (unsigned char)((1 << bits) - 1);
	if (__builtin_expect(!!suffix_len, 1)) {
		if (!bits)
			state->M[state->mptr] = 0;
		while (suffix_len--) {
			state->M[state->mptr] |= (unsigned char)((*suffix++ & 1) << bits++);
			if (bits == 8) {
				bits = 0;
				state->M[++(state->mptr)] = 0;
			}
		}
	}
	if (bits)
		state->mptr++;

	state->mptr = libkeccak_pad10star1((size_t)state->r, state->M, state->mptr, bits);
	libkeccak_absorption_phase(state, state->M, state->mptr);

	if (hashsum) {
		libkeccak_squeezing_phase(state, rr, (state->n + 7) >> 3, state->w >> 3, hashsum);
	} else {
		for (i = (state->n - 1) / state->r; i--;)
			libkeccak_f(state);
	}

	return 0;
}


/**
 * Force some rounds of Keccak-f
 * 
 * @param  state  The hashing state
 * @param  times  The number of rounds
 */
void
libkeccak_simple_squeeze(register struct libkeccak_state *state, register long int times)
{
	while (times--)
		libkeccak_f(state);
}


/**
 * Squeeze as much as is needed to get a digest a number of times
 * 
 * @param  state  The hashing state
 * @param  times  The number of digests
 */
extern inline void libkeccak_fast_squeeze(register struct libkeccak_state *state, register long int times);


/**
 * Squeeze out another digest
 * 
 * @param  state    The hashing state
 * @param  hashsum  Output parameter for the hashsum
 */
void
libkeccak_squeeze(register struct libkeccak_state *restrict state, register void *restrict hashsum)
{
	libkeccak_f(state);
	libkeccak_squeezing_phase(state, state->r >> 3, (state->n + 7) >> 3, state->w >> 3, hashsum);
}
