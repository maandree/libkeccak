/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Convert a binary hashsum to lower case hexadecimal representation
 * 
 * @param  output    Output array, should have an allocation size of at least `2 * n + 1`
 * @param  hashsum_  The hashsum to convert
 * @param  n         The size of `hashsum`
 */
void
libkeccak_behex_lower(char *restrict output, const void *restrict hashsum_, size_t n)
{
	const unsigned char *restrict hashsum = hashsum_;

	output[2 * n] = '\0';
	while (n--) {
		output[2 * n + 0] = "0123456789abcdef"[(hashsum[n] >> 4) & 15];
		output[2 * n + 1] = "0123456789abcdef"[(hashsum[n] >> 0) & 15];
	}
}
