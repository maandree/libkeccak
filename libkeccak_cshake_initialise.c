#include <stdio.h>
/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Encode a number in big-endian with a size prefix
 * 
 * @param   state     The hashing state the feed the number to
 * @param   buf       Buffer that is at least `byterate` bytes large
 * @param   byterate  The byterate of the hashing algorithm
 * @param   value     The number to send to the hashing sponge
 * @param   off       Current offset in `buf`
 * @return            New offset in `buf`
 */
static size_t
encode_left(struct libkeccak_state *restrict state, uint8_t *restrict buf, size_t byterate, size_t value, size_t off)
{
	size_t x, n, j, i = off;

	for (x = value, n = 0; x; x >>= 8)
		n += 1;
	if (!n)
		n = 1;
	buf[i++] = (uint8_t)n;
	if (i == byterate) {
		libkeccak_zerocopy_update(state, buf, byterate);
		i = 0;
	}

	for (j = 0; j < n;) {
		buf[i++] = (uint8_t)(value >> ((n - ++j) << 3));
		if (i == byterate) {
			libkeccak_zerocopy_update(state, buf, byterate);
			i = 0;
		}
	}

	return i;
}


/**
 * Encode a number in big-endian with a size prefix
 * 
 * @param   state     The hashing state the feed the number to
 * @param   buf       Buffer that is at least `byterate` bytes large
 * @param   byterate  The byterate of the hashing algorithm
 * @param   value     The number to send to the hashing sponge
 * @param   off       Current offset in `buf`
 * @param   bitoff    The number of bits to shift the encoded message left
 * @return            New offset in `buf`
 */
static size_t
encode_left_shifted(struct libkeccak_state *restrict state, uint8_t *restrict buf,
                    size_t byterate, size_t value, size_t off, size_t bitoff)
{
	size_t x, n, j, i = off;
	uint16_t v;

	for (x = value, n = 0; x; x >>= 8)
		n += 1;
	if (!n)
		n = 1;
	v = (uint16_t)((n & 255UL) << bitoff);
	buf[i++] |= (uint8_t)v;
	if (i == byterate) {
		libkeccak_zerocopy_update(state, buf, byterate);
		i = 0;
	}
	buf[i] = (uint8_t)(n >> 8);

	for (j = 0; j < n;) {
		v = (uint16_t)(((value >> ((n - ++j) << 3)) & 255UL) << bitoff);
		buf[i++] |= (uint8_t)v;
		if (i == byterate) {
			libkeccak_zerocopy_update(state, buf, byterate);
			i = 0;
		}
		buf[i] = (uint8_t)(v >> 8);
	}

	return i;
}


/**
 * Feed text to the sponge
 * 
 * @param  state     The hashing state tofeed
 * @param  buf       Buffer that is at least `byterate` bytes large
 * @param  text      Text to feed the sponge
 * @param  bytes     The number of whole bytes in `text`
 * @param  bits      The number of bits at the end of `text`
 *                   that does not make up a whole byte
 * @param  suffix    Bit-string (encoded with ASCII 0/1 digits)
 *                   of additional bytes after `text`
 * @param  off       The current byte offset in `buf`
 * @param  byterate  The byterate of the hashing algorithm
 * @param  bitoffp   Output parameter for the non-whole
 *                   byte bit-offset (current must be 0)
 * @return           The new byte offset in `buf`
 */
static size_t
feed_text(struct libkeccak_state *restrict state, uint8_t *restrict buf, const uint8_t *restrict text, size_t bytes,
          size_t bits, const char *restrict suffix, size_t off, size_t byterate, size_t *restrict bitoffp)
{
	size_t n, bitoff;

	if (off) {
		n = bytes < byterate - off ? bytes : byterate - off;
		memcpy(&buf[off], text, n);
		off += n;
		if (off == byterate) {
			libkeccak_zerocopy_update(state, buf, byterate);
			off = 0;
		}
		text = &text[n];
		bytes -= n;
	}
	if (bytes) {
		n = bytes;
		n -= bytes %= byterate;
		libkeccak_zerocopy_update(state, text, n);
		text = &text[n];
	}
	memcpy(&buf[off], text, bytes + !!bits);
	off += bytes;
	bitoff = bits;
	if (!bitoff)
		buf[off] = 0;
	for (; *suffix; suffix++) {
		if (*suffix == '1')
			buf[off] |= (uint8_t)(1 << bitoff);
		if (++bitoff == 8) {
			if (++off == byterate) {
				libkeccak_zerocopy_update(state, buf, byterate);
				off = 0;
			}
			bitoff = 0;
			buf[off] = 0;
		}
	}

	*bitoffp = bitoff;
	return off;
}


/**
 * Feed text to the sponge
 * 
 * @param  state     The hashing state tofeed
 * @param  buf       Buffer that is at least `byterate` bytes large
 * @param  text      Text to feed the sponge
 * @param  bytes     The number of whole bytes in `text`
 * @param  bits      The number of bits at the end of `text`
 *                   that does not make up a whole byte
 * @param  suffix    Bit-string (encoded with ASCII 0/1 digits)
 *                   of additional bytes after `text`
 * @param  off       The current byte offset in `buf`
 * @param  byterate  The byterate of the hashing algorithm
 * @param  bitoffp   Pointer to the non-whole byte bit-offset,
 *                   shall be the current (non-zero) bit-offset
 *                   upon entry and will be set to the new
 *                   bit-offset on return
 * @return           The new byte offset in `buf`
 */
static size_t
feed_text_shifted(struct libkeccak_state *restrict state, uint8_t *restrict buf, const uint8_t *restrict text, size_t bytes,
                  size_t bits, const char *restrict suffix, size_t off, size_t byterate, size_t *restrict bitoffp)
{
	size_t i, bitoff = *bitoffp;
	uint16_t v;

	for (i = 0; i < bytes; i++) {
		v = (uint16_t)((uint16_t)text[i] << bitoff);
		buf[off] |= (uint8_t)v;
		if (++off == byterate) {
			libkeccak_zerocopy_update(state, buf, byterate);
			off = 0;
		}
		buf[off] = (uint8_t)(v >> 8);
	}
	if (bits) {
		v = (uint16_t)((uint16_t)text[bytes] << bitoff);
		buf[off] |= (uint8_t)v;
		bitoff += bits;
		if (bitoff >= 8) {
			if (++off == byterate) {
				libkeccak_zerocopy_update(state, buf, byterate);
				off = 0;
			}
			bitoff &= 7;
			buf[off] = (uint8_t)(v >> 8);
		}
	}
	if (!bitoff)
		buf[off] = 0;
	for (; *suffix; suffix++) {
		if (*suffix == '1')
			buf[off] |= (uint8_t)(1 << bitoff);
		if (++bitoff == 8) {
			if (++off == byterate) {
				libkeccak_zerocopy_update(state, buf, byterate);
				off = 0;
			}
			bitoff = 0;
			buf[off] = 0;
		}
	}

	*bitoffp = bitoff;
	return off;
}


/**
 * Create and absorb the initialisation blocks for cSHAKE hashing
 * 
 * @param  state       The hashing state
 * @param  n_text      Function name-string
 * @param  n_len       Byte-length of `n_text` (only whole byte)
 * @param  n_bits      Bit-length of `n_text`, minus `n_len * 8`
 * @param  n_suffix    Bit-string, represented by a NUL-terminated
 *                     string of '1':s and '0's:, making up the part
 *                     after `n_text` of the function-name bit-string;
 *                     `NULL` is treated as the empty string
 * @param  s_text      Customisation-string
 * @param  s_len       Byte-length of `s_text` (only whole byte)
 * @param  s_bits      Bit-length of `s_text`, minus `s_len * 8`
 * @param  s_suffix    Bit-string, represented by a NUL-terminated
 *                     string of '1':s and '0's:, making up the part
 *                     after `s_text` of the customisation bit-string;
 *                     `NULL` is treated as the empty string
 */
void
libkeccak_cshake_initialise(struct libkeccak_state *restrict state,
                            const void *n_text, size_t n_len, size_t n_bits, const char *n_suffix,
                            const void *s_text, size_t s_len, size_t s_bits, const char *s_suffix)
{
	size_t off = 0, bitoff, byterate = (size_t)state->r >> 3;

	if (!n_suffix)
		n_suffix = "";
	if (!s_suffix)
		s_suffix = "";

	if (!n_len && !s_len && !n_bits && !s_bits && !*n_suffix && !*s_suffix)
		return;

	n_len += n_bits >> 3;
	s_len += s_bits >> 3;
	n_bits &= 7;
	s_bits &= 7;

	off = encode_left(state, state->M, byterate, byterate, off);
	off = encode_left(state, state->M, byterate, (n_len << 3) + n_bits + strlen(n_suffix), off);
	off = feed_text(state, state->M, n_text, n_len, n_bits, n_suffix, off, byterate, &bitoff);

	if (!bitoff) {
		off = encode_left(state, state->M, byterate, (s_len << 3) + s_bits + strlen(s_suffix), off);
		off = feed_text(state, state->M, s_text, s_len, s_bits, s_suffix, off, byterate, &bitoff);
	} else {
		off = encode_left_shifted(state, state->M, byterate, (s_len << 3) + s_bits + strlen(s_suffix), off, bitoff);
		off = feed_text_shifted(state, state->M, s_text, s_len, s_bits, s_suffix, off, byterate, &bitoff);
	}

	if (bitoff)
		off++;
	if (off) {
		memset(&state->M[off], 0, byterate - off);
		libkeccak_zerocopy_update(state, state->M, byterate);
	}
}
