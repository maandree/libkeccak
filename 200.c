/* See LICENSE file for copyright and license details. */


/**
 * 8-bit Keccak-f round constants
 */
static const uint_fast8_t rc8[] = {
	UINT8_C(0x01), UINT8_C(0x82), UINT8_C(0x8A), UINT8_C(0x00),
	UINT8_C(0x8B), UINT8_C(0x01), UINT8_C(0x81), UINT8_C(0x09),
	UINT8_C(0x8A), UINT8_C(0x88), UINT8_C(0x09), UINT8_C(0x0A),
	UINT8_C(0x8B), UINT8_C(0x8B), UINT8_C(0x89), UINT8_C(0x03),
	UINT8_C(0x02), UINT8_C(0x80)
};


/**
 * Rotate a 8-bit word
 * 
 * @param   x:uint8_t   The value to rotate
 * @param   n:long int  Rotation steps, may not be zero
 * @return   :uint8_t   The value rotated
 */
#define rotate8(x, n) ((uint_fast8_t)(((uint_fast8_t)(x) >> (8L - (n))) | ((uint_fast8_t)(x) << (n))))


/**
 * 8-bit word version of `libkeccak_f`
 * 
 * @param  state  The hashing state
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__, __nothrow__, __hot__)))
static void
libkeccak_f8(register struct libkeccak_state *state)
{
#define A state->S.w8

	uint_fast8_t B[25], C[5], da, db, dc, dd, de;
	int i;

	for (i = 0; i < 18; i++) {
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
#define X(bi, ai, dv, r) B[bi] = rotate8(A[ai] ^ dv, r)
		B[0] = A[0] ^ da;  X( 1, 15, dd, 4);  X( 2,  5, db, 1);  X( 3, 20, de, 3);  X( 4, 10, dc, 6);
		X( 5,  6, db, 4);  X( 6, 21, de, 4);  X( 7, 11, dc, 6);  X( 8,  1, da, 4);  X( 9, 16, dd, 7);
		X(10, 12, dc, 3);  X(11,  2, da, 3);  X(12, 17, dd, 1);  X(13,  7, db, 2);  X(14, 22, de, 7);
		X(15, 18, dd, 5);  X(16,  8, db, 5);  B[17] = A[23]^de;  X(18, 13, dc, 7);  X(19,  3, da, 1);
		X(20, 24, de, 6);  X(21, 14, dc, 5);  X(22,  4, da, 2);  B[23] = A[19]^dd;  X(24,  9, db, 2);
#undef X

		/* ξ step. */
#define X(N) A[N] = (uint8_t)(B[N] ^ ((~(B[(N + 5) % 25])) & B[(N + 10) % 25]))
		LIST_25(X, ;);
#undef X

		/* ι step. */
		A[0] ^= rc8[i];
	}

#undef A
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
	if (__builtin_expect(0 < n, 1))
		return (uint8_t)message[off];
	return 0;
}
