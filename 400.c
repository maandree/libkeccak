/* See LICENSE file for copyright and license details. */


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
 * Rotate a 16-bit word
 * 
 * @param   x:uint16_t  The value to rotate
 * @param   n:long int  Rotation steps, may not be zero
 * @return   :uint16_t  The value rotated
 */
#define rotate16(x, n) ((uint16_t)(((uint16_t)(x) >> (16L - (n))) | ((uint16_t)(x) << (n))))


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
#define X(bi, ai, dv, r) B[bi] = rotate16(A[ai] ^ dv, r)
	B[0] = A[0] ^ da;   X( 1, 15, dd, 12);  X( 2,  5, db,  1);  X( 3, 20, de, 11);  X( 4, 10, dc, 14);
	X( 5,  6, db, 12);  X( 6, 21, de,  4);  X( 7, 11, dc,  6);  X( 8,  1, da,  4);  X( 9, 16, dd,  7);
	X(10, 12, dc, 11);  X(11,  2, da,  3);  X(12, 17, dd,  9);  X(13,  7, db, 10);  X(14, 22, de,  7);
	X(15, 18, dd,  5);  X(16,  8, db, 13);  X(17, 23, de,  8);  X(18, 13, dc, 15);  X(19,  3, da,  9);
	X(20, 24, de, 14);  X(21, 14, dc, 13);  X(22,  4, da,  2);  X(23, 19, dd,  8);  X(24,  9, db,  2);
#undef X

	/* ξ step. */
#define X(N) A[N] = (uint16_t)(B[N] ^ ((~(B[(N + 5) % 25])) & B[(N + 10) % 25]))
	LIST_25(X, ;);
#undef X

	/* ι step. */
	A[0] ^= rc;
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
