/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Convert a hexadecimal hashsum (both lower case, upper
 * case and mixed is supported) to binary representation
 * 
 * @param  output_  Output array, should have an allocation size of at least `strlen(hashsum) / 2`
 * @param  hashsum  The hashsum to convert
 */
void
libkeccak_unhex(void *restrict output_, const char *restrict hashsum)
{
	unsigned char *restrict output = output_;
	size_t n = strlen(hashsum) / 2;
	unsigned char a, b;

	while (n--) {
		a = (unsigned char)hashsum[2 * n + 0];
		b = (unsigned char)hashsum[2 * n + 1];

		a = (unsigned char)((a & 15) + (a > '9' ? 9 : 0));
		b = (unsigned char)((b & 15) + (b > '9' ? 9 : 0));

		a = (unsigned char)(a << 4);
		a |= b;
		output[n] = a;
	}
}
