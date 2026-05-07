/* See LICENSE file for copyright and license details. */
#include "../common.h"


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
#define S(X)\
	X"0", X"1", X"2", X"3", X"4", X"5", X"6", X"7",\
	X"8", X"9", X"a", X"b", X"c", X"d", X"e", X"f"
#if defined(__GNUC__)
	__attribute__((__nonstring__))
#endif
	static const char lut[256][2] = {
		S("0"), S("1"), S("2"), S("3"), S("4"), S("5"), S("6"), S("7"),
		S("8"), S("9"), S("a"), S("b"), S("c"), S("d"), S("e"), S("f")
	};

	const unsigned char *restrict hashsum = hashsum_;

	output[2 * n] = '\0';
	while (n--) {
		output[2 * n + 0] = lut[hashsum[n]][0];
		output[2 * n + 1] = lut[hashsum[n]][1];
	}
}
