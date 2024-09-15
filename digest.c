/* See LICENSE file for copyright and license details. */
#include "common.h"


#define X(N) (N % 5) * 5 + N / 5
/**
 * The order the lanes should be read when absorbing or squeezing,
 * it transposes the lanes in the sponge
 */
static const long int LANE_TRANSPOSE_MAP[] = { LIST_25(X, COMMA) };
#undef X


/**
 * 64-bit Keccak-f round constants
 */
static const uint64_t rc64[] = {
	UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082), UINT64_C(0x800000000000808A), UINT64_C(0x8000000080008000),
	UINT64_C(0x000000000000808B), UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
	UINT64_C(0x000000000000008A), UINT64_C(0x0000000000000088), UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000A),
	UINT64_C(0x000000008000808B), UINT64_C(0x800000000000008B), UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
	UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080), UINT64_C(0x000000000000800A), UINT64_C(0x800000008000000A),
	UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080), UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
};


/**
 * 32-bit Keccak-f round constants
 */
static const uint32_t rc32[] = {
	UINT32_C(0x00000001), UINT32_C(0x00008082), UINT32_C(0x0000808A), UINT32_C(0x80008000),
	UINT32_C(0x0000808B), UINT32_C(0x80000001), UINT32_C(0x80008081), UINT32_C(0x00008009),
	UINT32_C(0x0000008A), UINT32_C(0x00000088), UINT32_C(0x80008009), UINT32_C(0x8000000A),
	UINT32_C(0x8000808B), UINT32_C(0x0000008B), UINT32_C(0x00008089), UINT32_C(0x00008003),
	UINT32_C(0x00008002), UINT32_C(0x00000080), UINT32_C(0x0000800A), UINT32_C(0x8000000A),
	UINT32_C(0x80008081), UINT32_C(0x00008080)
};


/**
 * 16-bit Keccak-f round constants
 */
static const uint16_t rc16[] = {
	UINT16_C(0x0001), UINT16_C(0x8082), UINT16_C(0x808A), UINT16_C(0x8000),
	UINT16_C(0x808B), UINT16_C(0x0001), UINT16_C(0x8081), UINT16_C(0x8009),
	UINT16_C(0x008A), UINT16_C(0x0088), UINT16_C(0x8009), UINT16_C(0x000A),
	UINT16_C(0x808B), UINT16_C(0x008B), UINT16_C(0x8089), UINT16_C(0x8003),
	UINT16_C(0x8002), UINT16_C(0x0080), UINT16_C(0x800A), UINT16_C(0x000A)
};


/**
 * 8-bit Keccak-f round constants
 */
static const uint8_t rc8[] = {
	UINT8_C(0x01), UINT8_C(0x82), UINT8_C(0x8A), UINT8_C(0x00),
	UINT8_C(0x8B), UINT8_C(0x01), UINT8_C(0x81), UINT8_C(0x09),
	UINT8_C(0x8A), UINT8_C(0x88), UINT8_C(0x09), UINT8_C(0x0A),
	UINT8_C(0x8B), UINT8_C(0x8B), UINT8_C(0x89), UINT8_C(0x03),
	UINT8_C(0x02), UINT8_C(0x80)
};


/**
 * Rotate a word
 * 
 * @param   x:uint_fast64_t     The value to rotate
 * @param   n:long int          Rotation steps, may be zero mod `w`
 * @param   w:long int          `state->w`
 * @param   wmod:uint_fast64_t  `state->wmod`
 * @return  :uint_fast64_t      The value rotated
 */
#define rotate(x, n, w, wmod) ((((x) >> ((w) - ((n) % (w)))) | ((x) << ((n) % (w)))) & (wmod))


/**
 * Rotate a 64-bit word
 * 
 * @param   x:uint64_t  The value to rotate
 * @param   n:long int  Rotation steps, may not be zero
 * @return   :uint64_t  The value rotated
 */
#define rotate64(x, n) ((uint64_t)(((uint64_t)(x) >> (64L - (n))) | ((uint64_t)(x) << (n))))


/**
 * Rotate a 32-bit word
 * 
 * @param   x:uint32_t  The value to rotate
 * @param   n:long int  Rotation steps, may not be zero
 * @return   :uint32_t  The value rotated
 */
#define rotate32(x, n) ((uint32_t)(((uint32_t)(x) >> (32L - (n))) | ((uint32_t)(x) << (n))))


/**
 * Rotate a 16-bit word
 * 
 * @param   x:uint16_t  The value to rotate
 * @param   n:long int  Rotation steps, may not be zero
 * @return   :uint16_t  The value rotated
 */
#define rotate16(x, n) ((uint16_t)(((uint16_t)(x) >> (16L - (n))) | ((uint16_t)(x) << (n))))


/**
 * Rotate a 8-bit word
 * 
 * @param   x:uint8_t   The value to rotate
 * @param   n:long int  Rotation steps, may not be zero
 * @return   :uint8_t   The value rotated
 */
#define rotate8(x, n) ((uint8_t)(((uint8_t)(x) >> (8L - (n))) | ((uint8_t)(x) << (n))))


/**
 * Perform one round of computation
 * 
 * @param  state  The hashing state
 * @param  rc     The round contant for this round
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __hot__)))
static void
libkeccak_f_round(register struct libkeccak_state *state, register uint64_t rc)
{
	uint64_t *restrict A = state->S.w64;
	uint_fast64_t B[25];
	uint_fast64_t C[5];
	uint_fast64_t da, db, dc, dd, de;
	uint_fast64_t wmod = state->wmod;
	long int w = state->w;

	/* θ step (step 1 of 3). */
#define X(N) C[N] = A[N * 5] ^ A[N * 5 + 1] ^ A[N * 5 + 2] ^ A[N * 5 + 3] ^ A[N * 5 + 4]
	LIST_5(X, ;);
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
#define X(N) A[N] = B[N] ^ ((~(B[(N + 5) % 25])) & B[(N + 10) % 25])
	LIST_25(X, ;);
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
libkeccak_f_round64(register struct libkeccak_state *state, register uint64_t rc)
{
	uint64_t *restrict A = state->S.w64;
	uint64_t B[25], C[5], da, db, dc, dd, de;

	/* θ step (step 1 of 3). */
#define X(N) C[N] = A[N * 5] ^ A[N * 5 + 1] ^ A[N * 5 + 2] ^ A[N * 5 + 3] ^ A[N * 5 + 4]
	LIST_5(X, ;);
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
#define X(N) A[N] = B[N] ^ ((~(B[(N + 5) % 25])) & B[(N + 10) % 25])
	LIST_25(X, ;);
#undef X

	/* ι step. */
	A[0] ^= rc;
}


/**
 * 32-bit word version of `libkeccak_f_round`
 * 
 * @param  state  The hashing state
 * @param  rc     The round contant for this round
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __hot__)))
static void
libkeccak_f_round32(register struct libkeccak_state *state, register uint32_t rc)
{
	uint32_t *restrict A = state->S.w32;
	uint32_t B[25], C[5], da, db, dc, dd, de;

	/* θ step (step 1 of 3). */
#define X(N) C[N] = A[N * 5] ^ A[N * 5 + 1] ^ A[N * 5 + 2] ^ A[N * 5 + 3] ^ A[N * 5 + 4]
	LIST_5(X, ;);
#undef X

	/* θ step (step 2 of 3). */
	da = C[4] ^ rotate32(C[1], 1);
	dd = C[2] ^ rotate32(C[4], 1);
	db = C[0] ^ rotate32(C[2], 1);
	de = C[3] ^ rotate32(C[0], 1);
	dc = C[1] ^ rotate32(C[3], 1);

	/* ρ and π steps, with last two part of θ. */
#define X(bi, ai, dv, r) B[bi] = rotate32(A[ai] ^ dv, (r & 31))
	B[0] = A[0] ^ da;   X( 1, 15, dd, 28);  X( 2,  5, db,  1);  X( 3, 20, de, 27);  X( 4, 10, dc, 62);
	X( 5,  6, db, 44);  X( 6, 21, de, 20);  X( 7, 11, dc,  6);  X( 8,  1, da, 36);  X( 9, 16, dd, 55);
	X(10, 12, dc, 43);  X(11,  2, da,  3);  X(12, 17, dd, 25);  X(13,  7, db, 10);  X(14, 22, de, 39);
	X(15, 18, dd, 21);  X(16,  8, db, 45);  X(17, 23, de,  8);  X(18, 13, dc, 15);  X(19,  3, da, 41);
	X(20, 24, de, 14);  X(21, 14, dc, 61);  X(22,  4, da, 18);  X(23, 19, dd, 56);  X(24,  9, db,  2);
#undef X

	/* ξ step. */
#define X(N) A[N] = (uint32_t)(B[N] ^ ((~(B[(N + 5) % 25])) & B[(N + 10) % 25]))
	LIST_25(X, ;);
#undef X

	/* ι step. */
	A[0] ^= rc;
}


/**
 * 16-bit word version of `libkeccak_f_round`
 * 
 * @param  state  The hashing state
 * @param  rc     The round contant for this round
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __hot__)))
static void
libkeccak_f_round16(register struct libkeccak_state *state, register uint16_t rc)
{
	uint16_t *restrict A = state->S.w16;
	uint16_t B[25], C[5], da, db, dc, dd, de;

	/* θ step (step 1 of 3). */
#define X(N) C[N] = A[N * 5] ^ A[N * 5 + 1] ^ A[N * 5 + 2] ^ A[N * 5 + 3] ^ A[N * 5 + 4]
	LIST_5(X, ;);
#undef X

	/* θ step (step 2 of 3). */
	da = C[4] ^ rotate16(C[1], 1);
	dd = C[2] ^ rotate16(C[4], 1);
	db = C[0] ^ rotate16(C[2], 1);
	de = C[3] ^ rotate16(C[0], 1);
	dc = C[1] ^ rotate16(C[3], 1);

	/* ρ and π steps, with last two part of θ. */
#define X(bi, ai, dv, r) B[bi] = rotate16(A[ai] ^ dv, (r & 15))
	B[0] = A[0] ^ da;   X( 1, 15, dd, 28);  X( 2,  5, db,  1);  X( 3, 20, de, 27);  X( 4, 10, dc, 62);
	X( 5,  6, db, 44);  X( 6, 21, de, 20);  X( 7, 11, dc,  6);  X( 8,  1, da, 36);  X( 9, 16, dd, 55);
	X(10, 12, dc, 43);  X(11,  2, da,  3);  X(12, 17, dd, 25);  X(13,  7, db, 10);  X(14, 22, de, 39);
	X(15, 18, dd, 21);  X(16,  8, db, 45);  X(17, 23, de,  8);  X(18, 13, dc, 15);  X(19,  3, da, 41);
	X(20, 24, de, 14);  X(21, 14, dc, 61);  X(22,  4, da, 18);  X(23, 19, dd, 56);  X(24,  9, db,  2);
#undef X

	/* ξ step. */
#define X(N) A[N] = (uint16_t)(B[N] ^ ((~(B[(N + 5) % 25])) & B[(N + 10) % 25]))
	LIST_25(X, ;);
#undef X

	/* ι step. */
	A[0] ^= rc;
}


/**
 * 8-bit word version of `libkeccak_f_round`
 * 
 * @param  state  The hashing state
 * @param  rc     The round contant for this round
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __hot__)))
static void
libkeccak_f_round8(register struct libkeccak_state *state, register uint8_t rc)
{
	uint8_t *restrict A = state->S.w8;
	uint8_t B[25], C[5], da, db, dc, dd, de;

	/* θ step (step 1 of 3). */
#define X(N) C[N] = A[N * 5] ^ A[N * 5 + 1] ^ A[N * 5 + 2] ^ A[N * 5 + 3] ^ A[N * 5 + 4]
	LIST_5(X, ;);
#undef X

	/* θ step (step 2 of 3). */
	da = C[4] ^ rotate8(C[1], 1);
	dd = C[2] ^ rotate8(C[4], 1);
	db = C[0] ^ rotate8(C[2], 1);
	de = C[3] ^ rotate8(C[0], 1);
	dc = C[1] ^ rotate8(C[3], 1);

	/* ρ and π steps, with last two part of θ. */
#define X(bi, ai, dv, r) B[bi] = rotate8(A[ai] ^ dv, (r & 7))
	B[0] = A[0] ^ da;   X( 1, 15, dd, 28);  X( 2,  5, db,  1);  X( 3, 20, de, 27);  X( 4, 10, dc, 62);
	X( 5,  6, db, 44);  X( 6, 21, de, 20);  X( 7, 11, dc,  6);  X( 8,  1, da, 36);  X( 9, 16, dd, 55);
	X(10, 12, dc, 43);  X(11,  2, da,  3);  X(12, 17, dd, 25);  X(13,  7, db, 10);  X(14, 22, de, 39);
	X(15, 18, dd, 21);  X(16,  8, db, 45);  X(17, 23, de,  8);  X(18, 13, dc, 15);  X(19,  3, da, 41);
	X(20, 24, de, 14);  X(21, 14, dc, 61);  X(22,  4, da, 18);  X(23, 19, dd, 56);  X(24,  9, db,  2);
#undef X

	/* ξ step. */
#define X(N) A[N] = (uint8_t)(B[N] ^ ((~(B[(N + 5) % 25])) & B[(N + 10) % 25]))
	LIST_25(X, ;);
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
libkeccak_f(register struct libkeccak_state *state)
{
	register long int i = 0;
	register long int nr = state->nr;
	register uint_fast64_t wmod = state->wmod;

	if (nr == 24) {
		for (; i < nr; i++)
			libkeccak_f_round64(state, rc64[i]);
		return;
	}

	if (nr == 22) {
		for (; i < nr; i++)
			libkeccak_f_round32(state, rc32[i]);
		return;
	}

	if (nr == 20) {
		for (; i < nr; i++)
			libkeccak_f_round16(state, rc16[i]);
		return;
	}

	if (nr == 18) {
		for (; i < nr; i++)
			libkeccak_f_round8(state, rc8[i]);
		return;
	}

	for (; i < nr; i++)
		libkeccak_f_round(state, rc64[i] & wmod);
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
static inline uint64_t
libkeccak_to_lane(register const unsigned char *restrict message, register size_t msglen,
                  register long int rr, register long int ww, size_t off)
{
	register long int n = (long)((msglen < (size_t)rr ? msglen : (size_t)rr) - off);
	uint_fast64_t rc = 0;
	message += off;
	while (ww--) {
		rc <<= 8;
		rc |= __builtin_expect(ww < n, 1) ? (uint_fast64_t)(unsigned char)message[ww] : 0L;
	}
	return (uint64_t)rc;
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
static inline uint64_t
libkeccak_to_lane64(register const unsigned char *message, register size_t msglen, register long int rr, size_t off)
{
	register long int n = (long)((msglen < (size_t)rr ? msglen : (size_t)rr) - off);
	uint64_t rc = 0;
	message += off;
#define X(N) if (__builtin_expect(N < n, 1)) rc |= (uint64_t)message[N] << (N * 8);\
             else return rc
	LIST_8(X, ;);
#undef X
	return rc;
}


/**
 * 32-bit lane version of `libkeccak_to_lane`
 * 
 * @param   message  The message
 * @param   msglen   The length of the message
 * @param   rr       Bitrate in bytes
 * @param   off      The offset in the message
 * @return           The lane
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __pure__, __hot__, __warn_unused_result__, __gnu_inline__)))
static inline uint32_t
libkeccak_to_lane32(register const unsigned char *message, register size_t msglen, register long int rr, size_t off)
{
	register long int n = (long)((msglen < (size_t)rr ? msglen : (size_t)rr) - off);
	uint32_t rc = 0;
	message += off;
#define X(N) if (__builtin_expect(N < n, 1)) rc |= (uint32_t)message[N] << (N * 8);\
             else return rc
	LIST_4(X, ;);
#undef X
	return rc;
}


/**
 * 16-bit lane version of `libkeccak_to_lane`
 * 
 * @param   message  The message
 * @param   msglen   The length of the message
 * @param   rr       Bitrate in bytes
 * @param   off      The offset in the message
 * @return           The lane
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __pure__, __hot__, __warn_unused_result__, __gnu_inline__)))
static inline uint16_t
libkeccak_to_lane16(register const unsigned char *message, register size_t msglen, register long int rr, size_t off)
{
	register long int n = (long)((msglen < (size_t)rr ? msglen : (size_t)rr) - off);
	uint16_t rc = 0;
	message += off;
#define X(N) if (__builtin_expect(N < n, 1)) rc |= (uint16_t)message[N] << (N * 8);\
             else return rc
	LIST_2(X, ;);
#undef X
	return rc;
}


/**
 * 8-bit lane version of `libkeccak_to_lane`
 * 
 * @param   message  The message
 * @param   msglen   The length of the message
 * @param   rr       Bitrate in bytes
 * @param   off      The offset in the message
 * @return           The lane
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __pure__, __hot__, __warn_unused_result__, __gnu_inline__)))
static inline uint8_t
libkeccak_to_lane8(register const unsigned char *message, register size_t msglen, register long int rr, size_t off)
{
	register long int n = (long)((msglen < (size_t)rr ? msglen : (size_t)rr) - off);
	uint8_t rc = 0;
	message += off;
#define X(N) if (__builtin_expect(N < n, 1)) rc |= (uint8_t)(unsigned char)message[N] << (N * 8);\
             else return (uint8_t)rc
	LIST_1(X, ;);
#undef X
	return (uint8_t)rc;
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
		return;
	}

	if (__builtin_expect(ww == 4, 1)) {
		while (n--) {
#define X(N) state->S.w32[N] ^= libkeccak_to_lane32(message, len, rr, (size_t)(LANE_TRANSPOSE_MAP[N] * 4))
			LIST_25(X, ;);
#undef X
			libkeccak_f(state);
			message += (size_t)rr;
			len -= (size_t)rr;
		}
		return;
	}

	if (__builtin_expect(ww == 2, 1)) {
		while (n--) {
#define X(N) state->S.w16[N] ^= libkeccak_to_lane16(message, len, rr, (size_t)(LANE_TRANSPOSE_MAP[N] * 2))
			LIST_25(X, ;);
#undef X
			libkeccak_f(state);
			message += (size_t)rr;
			len -= (size_t)rr;
		}
		return;
	}

	if (__builtin_expect(ww == 1, 1)) {
		while (n--) {
#define X(N) state->S.w8[N] ^= libkeccak_to_lane8(message, len, rr, (size_t)(LANE_TRANSPOSE_MAP[N] * 1))
			LIST_25(X, ;);
#undef X
			libkeccak_f(state);
			message += (size_t)rr;
			len -= (size_t)rr;
		}
		return;
	}

	while (n--) {
#define X(N) state->S.w64[N] ^= libkeccak_to_lane(message, len, rr, ww, (size_t)(LANE_TRANSPOSE_MAP[N] * ww))
		LIST_25(X, ;);
#undef X
		libkeccak_f(state);
		message += (size_t)rr;
		len -= (size_t)rr;
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
	register uint64_t v;
	register long int ni = rr / ww + !!(rr % ww);
	auto long int olen = state->n;
	auto long int i, j = 0;
	register long int k;
	while (olen > 0) {
		for (i = 0; i < ni && j < nn; i++) {
			if (__builtin_expect(ww == 8, 1)) v = state->S.w64[LANE_TRANSPOSE_MAP[i]]; else
			if (__builtin_expect(ww == 4, 1)) v = state->S.w32[LANE_TRANSPOSE_MAP[i]]; else
			if (__builtin_expect(ww == 2, 1)) v = state->S.w16[LANE_TRANSPOSE_MAP[i]]; else
			if (__builtin_expect(ww == 1, 1)) v = state->S.w8[LANE_TRANSPOSE_MAP[i]]; else
			v = state->S.w64[LANE_TRANSPOSE_MAP[i]];
			for (k = 0; k++ < ww && j++ < nn; v >>= 8)
				*hashsum++ = (unsigned char)(v & 0xFFU);
		}
		olen -= state->r;
		if (olen > 0)
			libkeccak_f(state);
	}
	if (state->n & 7)
		hashsum[-1] &= (unsigned char)((1 << (state->n & 7)) - 1);
}


/**
 * Absorb more of the message to the Keccak sponge
 * without copying the data to an internal buffer
 * 
 * It is safe run zero-copy functions before non-zero-copy
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
 * It is safe run zero-copy functions before non-zero-copy
 * functions for the same state, running zero-copy functions
 * after non-zero-copy functions on the other hand can
 * cause the message to be misread
 * 
 * @param  state    The hashing state
 * @param  msg_     The rest of the message; will be edited; extra memory
 *                  shall be allocated such that `suffix` and a 10*1 pad (which
 *                  is at least 2 bits long) can be added in a why the makes it's
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
