/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * X-macro-enabled listing of all intergers in [0, 4]
 */
#define LIST_5 X(0) X(1) X(2) X(3) X(4)

/**
 * X-macro-enabled listing of all intergers in [0, 7]
 */
#define LIST_8 LIST_5 X(5) X(6) X(7)

/**
 * X-macro-enabled listing of all intergers in [0, 24]
 */
#define LIST_25 LIST_8 X(8) X(9) X(10) X(11) X(12) X(13) X(14) X(15)\
                X(16) X(17) X(18) X(19) X(20) X(21) X(22) X(23) X(24)



#define X(N) (N % 5) * 5 + N / 5,
/**
 * The order the lanes should be read when absorbing or squeezing,
 * it transposes the lanes in the sponge
 */
static const long int LANE_TRANSPOSE_MAP[] = { LIST_25 };
#undef X



/**
 * Keccak-f round constants
 */
static const uint_fast64_t RC[] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
	0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
	0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
	0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
	0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};


/**
 * Rotate a word
 * 
 * @param   x:int_fast64_t     The value to rotate
 * @param   n:long             Rotation steps, may be zero mod `w`
 * @param   w:long             `state->w`
 * @param   wmod:int_fast64_t  `state->wmod`
 * @return  :int_fast64_t      The value rotated
 */
#define rotate(x, n, w, wmod) ((((x) >> ((w) - ((n) % (w)))) | ((x) << ((n) % (w)))) & (wmod))


/**
 * Rotate a 64-bit word
 * 
 * @param   x:int_fast64_t  The value to rotate
 * @param   n:long          Rotation steps, may not be zero
 * @return   :int_fast64_t  The value rotated
 */
#define rotate64(x, n) ((int_fast64_t)(((uint64_t)(x) >> (64L - (n))) | ((uint64_t)(x) << (n))))


/**
 * Perform one round of computation
 * 
 * @param  state  The hashing state
 * @param  rc     The round contant for this round
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __hot__)))
static void
libkeccak_f_round(register struct libkeccak_state *restrict state, register int_fast64_t rc)
{
	int_fast64_t *restrict A = state->S;
	int_fast64_t B[25];
	int_fast64_t C[5];
	int_fast64_t da, db, dc, dd, de;
	int_fast64_t wmod = state->wmod;
	long int w = state->w;

	/* θ step (step 1 of 3). */
#define X(N) C[N] = A[N * 5] ^ A[N * 5 + 1] ^ A[N * 5 + 2] ^ A[N * 5 + 3] ^ A[N * 5 + 4];
	LIST_5;
#undef X

	/* θ step (step 2 of 3). */
	da = C[4] ^ rotate(C[1], 1, w, wmod);
	dd = C[2] ^ rotate(C[4], 1, w, wmod);
	db = C[0] ^ rotate(C[2], 1, w, wmod);
	de = C[3] ^ rotate(C[0], 1, w, wmod);
	dc = C[1] ^ rotate(C[3], 1, w, wmod);

	/* ρ and π steps, with last two part of θ. */
#define X(bi, ai, dv, r) B[bi] = rotate(A[ai] ^ dv, r, w, wmod)
	B[0] = A[0] ^ da;   X( 1, 15, dd, 28);  X( 2,  5, db,  1);  X( 3, 20, de, 27);  X( 4, 10, dc, 62);
	X( 5,  6, db, 44);  X( 6, 21, de, 20);  X( 7, 11, dc,  6);  X( 8,  1, da, 36);  X( 9, 16, dd, 55);
	X(10, 12, dc, 43);  X(11,  2, da,  3);  X(12, 17, dd, 25);  X(13,  7, db, 10);  X(14, 22, de, 39);
	X(15, 18, dd, 21);  X(16,  8, db, 45);  X(17, 23, de,  8);  X(18, 13, dc, 15);  X(19,  3, da, 41);
	X(20, 24, de, 14);  X(21, 14, dc, 61);  X(22,  4, da, 18);  X(23, 19, dd, 56);  X(24,  9, db,  2);
#undef X

	/* ξ step. */
#define X(N) A[N] = B[N] ^ ((~(B[(N + 5) % 25])) & B[(N + 10) % 25]);
	LIST_25;
#undef X

	/* ι step. */
	A[0] ^= rc;
}


/**
 * 64-bit word version of `libkeccak_f_round`
 * 
 * @param  state  The hashing state
 * @param  rc     The round contant for this round
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __hot__)))
static void
libkeccak_f_round64(register struct libkeccak_state *restrict state, register int_fast64_t rc)
{
	int_fast64_t *restrict A = state->S;
	int_fast64_t B[25];
	int_fast64_t C[5];
	int_fast64_t da, db, dc, dd, de;

	/* θ step (step 1 of 3). */
#define X(N) C[N] = A[N * 5] ^ A[N * 5 + 1] ^ A[N * 5 + 2] ^ A[N * 5 + 3] ^ A[N * 5 + 4];
	LIST_5;
#undef X

	/* θ step (step 2 of 3). */
	da = C[4] ^ rotate64(C[1], 1);
	dd = C[2] ^ rotate64(C[4], 1);
	db = C[0] ^ rotate64(C[2], 1);
	de = C[3] ^ rotate64(C[0], 1);
	dc = C[1] ^ rotate64(C[3], 1);

	/* ρ and π steps, with last two part of θ. */
#define X(bi, ai, dv, r) B[bi] = rotate64(A[ai] ^ dv, r)
	B[0] = A[0] ^ da;   X( 1, 15, dd, 28);  X( 2,  5, db,  1);  X( 3, 20, de, 27);  X( 4, 10, dc, 62);
	X( 5,  6, db, 44);  X( 6, 21, de, 20);  X( 7, 11, dc,  6);  X( 8,  1, da, 36);  X( 9, 16, dd, 55);
	X(10, 12, dc, 43);  X(11,  2, da,  3);  X(12, 17, dd, 25);  X(13,  7, db, 10);  X(14, 22, de, 39);
	X(15, 18, dd, 21);  X(16,  8, db, 45);  X(17, 23, de,  8);  X(18, 13, dc, 15);  X(19,  3, da, 41);
	X(20, 24, de, 14);  X(21, 14, dc, 61);  X(22,  4, da, 18);  X(23, 19, dd, 56);  X(24,  9, db,  2);
#undef X

	/* ξ step. */
#define X(N) A[N] = B[N] ^ ((~(B[(N + 5) % 25])) & B[(N + 10) % 25]);
	LIST_25;
#undef X

	/* ι step. */
	A[0] ^= rc;
}


/**
 * Convert a chunk of bytes to a lane
 * 
 * @param  state  The hashing state
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __gnu_inline__)))
static inline void
libkeccak_f(register struct libkeccak_state *restrict state)
{
	register long int i = 0;
	register long int nr = state->nr;
	register long int wmod = state->wmod;
	if (nr == 24) {
		for (; i < nr; i++)
			libkeccak_f_round64(state, (int_fast64_t)(RC[i]));
	} else {
		for (; i < nr; i++)
			libkeccak_f_round(state, (int_fast64_t)(RC[i] & (uint_fast64_t)wmod));
	}
}


/**
 * Convert a chunk of bytes to a lane
 * 
 * @param   message  The message
 * @param   msglen   The length of the message
 * @param   rr       Bitrate in bytes
 * @param   ww       Word size in bytes
 * @param   off      The offset in the message
 * @return           The lane
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __pure__, __warn_unused_result__, __gnu_inline__)))
static inline int_fast64_t
libkeccak_to_lane(register const unsigned char *restrict message, register size_t msglen,
                  register long int rr, register long int ww, size_t off)
{
	register long int n = (long)((msglen < (size_t)rr ? msglen : (size_t)rr) - off);
	int_fast64_t rc = 0;
	message += off;
	while (ww--) {
		rc <<= 8;
		rc |= __builtin_expect(ww < n, 1) ? (int_fast64_t)(unsigned char)(message[ww]) : 0L;
	}
	return rc;
}


/**
 * 64-bit lane version of `libkeccak_to_lane`
 * 
 * @param   message  The message
 * @param   msglen   The length of the message
 * @param   rr       Bitrate in bytes
 * @param   off      The offset in the message
 * @return           The lane
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __pure__, __hot__, __warn_unused_result__, __gnu_inline__)))
static inline int_fast64_t
libkeccak_to_lane64(register const unsigned char *restrict message, register size_t msglen, register long int rr, size_t off)
{
	register long int n = (long)((msglen < (size_t)rr ? msglen : (size_t)rr) - off);
	int_fast64_t rc = 0;
	message += off;
#define X(N) if (__builtin_expect(N < n, 1)) rc |= (int_fast64_t)(unsigned char)(message[N]) << (N * 8);\
             else  return rc;
	LIST_8;
#undef X
	return rc;
}


/**
 * pad 10*1
 * 
 * @param  state  The hashing state, `state->M` and `state->mptr` will be updated,
 *                `state->M` should have `state->r / 8` bytes left over at the end
 * @param  bits   The number of bits in the end of the message that does not make a whole byte
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __gnu_inline__)))
static inline void
libkeccak_pad10star1(register struct libkeccak_state *restrict state, register size_t bits)
{
	register size_t r = (size_t)(state->r);
	register size_t nrf = state->mptr - !!bits;
	register size_t len = (nrf << 3) | bits;
	register size_t ll = len % r;
	register unsigned char b = (unsigned char)(bits ? (state->M[nrf] | (1 << bits)) : 1);

	if (r - 8 <= ll && ll <= r - 2) {
		state->M[nrf] = (unsigned char)(b ^ 0x80);
		state->mptr = nrf + 1;
	} else {
		len = ++nrf << 3;
		len = (len - (len % r) + (r - 8)) >> 3;
		state->mptr = len + 1;

		state->M[nrf - 1] = b;
		__builtin_memset(state->M + nrf, 0, (len - nrf) * sizeof(char));
		state->M[len] = (unsigned char)0x80;
	}
}


/**
 * Perform the absorption phase
 * 
 * @param  state  The hashing state
 * @param  len    The number of bytes from `state->M` to absorb
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__)))
static void
libkeccak_absorption_phase(register struct libkeccak_state *restrict state, register size_t len)
{
	register long int rr = state->r >> 3;
	register long int ww = state->w >> 3;
	register long int n = (long)len / rr;
	register const unsigned char *restrict message = state->M;
	if (__builtin_expect(ww >= 8, 1)) { /* ww > 8 is impossible, it is just for optimisation possibilities. */
		while (n--) {
#define X(N) state->S[N] ^= libkeccak_to_lane64(message, len, rr, (size_t)(LANE_TRANSPOSE_MAP[N] * 8));
			LIST_25;
#undef X
			libkeccak_f(state);
			message += (size_t)rr;
			len -= (size_t)rr;
		}
	} else {
		while (n--) {
#define X(N) state->S[N] ^= libkeccak_to_lane(message, len, rr, ww, (size_t)(LANE_TRANSPOSE_MAP[N] * ww));
			LIST_25;
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
	register int_fast64_t v;
	register long int ni = rr / ww;
	auto long int olen = state->n;
	auto long int i, j = 0;
	register long int k;
	while (olen > 0) {
		for (i = 0; i < ni && j < nn; i++) {
			v = state->S[LANE_TRANSPOSE_MAP[i]];
			for (k = 0; k++ < ww && j++ < nn; v >>= 8)
				*hashsum++ = (unsigned char)v;
		}
		if (olen -= state->r, olen > 0)
			libkeccak_f(state);
	}
	if (state->n & 7)
		hashsum[-1] &= (unsigned char)((1 << (state->n & 7)) - 1);
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
		if (!new)
			return state->mlen -= msglen, -1;
		state->M = new;
	}

	__builtin_memcpy(state->M + state->mptr, msg, msglen * sizeof(char));
	state->mptr += msglen;
	len = state->mptr;
	len -= state->mptr % (size_t)((state->r * state->b) >> 3);
	state->mptr -= len;

	libkeccak_absorption_phase(state, len);
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
		if (!new)
			return state->mlen -= msglen, -1;
		libkeccak_state_wipe_message(state);
		free(state->M);
		state->M = new;
	}

	__builtin_memcpy(state->M + state->mptr, msg, msglen * sizeof(char));
	state->mptr += msglen;
	len = state->mptr;
	len -= state->mptr % (size_t)((state->r * state->b) >> 3);
	state->mptr -= len;

	libkeccak_absorption_phase(state, len);
	__builtin_memmove(state->M, state->M + len, state->mptr * sizeof(char));

	return 0;
}


/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * without wiping sensitive data when possible
 * 
 * @param   state    The hashing state
 * @param   msg      The rest of the message, may be `NULL`
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

	if (!msg)
		msglen = bits = 0;
	else
		msglen += bits >> 3, bits &= 7;

	ext = msglen + ((bits + suffix_len + 7) >> 3) + (size_t)rr;
	if (__builtin_expect(state->mptr + ext > state->mlen, 0)) {
		state->mlen += ext;
		new = realloc(state->M, state->mlen * sizeof(char));
		if (!new)
			return state->mlen -= ext, -1;
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
			if (bits == 8)
				bits = 0, state->M[++(state->mptr)] = 0;
		}
	}
	if (bits)
		state->mptr++;

	libkeccak_pad10star1(state, bits);
	libkeccak_absorption_phase(state, state->mptr);

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
 * @param   msg      The rest of the message, may be `NULL`
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

	if (!msg)
		msglen = bits = 0;
	else
		msglen += bits >> 3, bits &= 7;

	ext = msglen + ((bits + suffix_len + 7) >> 3) + (size_t)rr;
	if (__builtin_expect(state->mptr + ext > state->mlen, 0)) {
		state->mlen += ext;
		new = malloc(state->mlen * sizeof(char));
		if (!new)
			return state->mlen -= ext, -1;
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
			if (bits == 8)
				bits = 0, state->M[++(state->mptr)] = 0;
		}
	}
	if (bits)
		state->mptr++;

	libkeccak_pad10star1(state, bits);
	libkeccak_absorption_phase(state, state->mptr);

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
libkeccak_simple_squeeze(register struct libkeccak_state *restrict state, register long int times)
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
void
libkeccak_fast_squeeze(register struct libkeccak_state *restrict state, register long int times)
{
	times *= (state->n - 1) / state->r + 1;
	while (times--)
		libkeccak_f(state);
}


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
