/* See LICENSE file for copyright and license details. */
#include "../common.h"


/**
 * Convert a binary hashsum to upper case hexadecimal representation
 * 
 * @param  output    Output array, should have an allocation size of at least `2 * n + 1`
 * @param  hashsum_  The hashsum to convert
 * @param  n         The size of `hashsum`
 */
void
libkeccak_behex_upper(char *restrict output, const void *restrict hashsum_, size_t n)
{
#define S(X)\
	X"0", X"1", X"2", X"3", X"4", X"5", X"6", X"7",\
	X"8", X"9", X"A", X"B", X"C", X"D", X"E", X"F"
#if defined(__GNUC__)
	__attribute__((__nonstring__))
#endif
	static const char lut[256][2] = {
		S("0"), S("1"), S("2"), S("3"), S("4"), S("5"), S("6"), S("7"),
		S("8"), S("9"), S("A"), S("B"), S("C"), S("D"), S("E"), S("F")
	};

	const unsigned char *restrict hashsum = hashsum_;

	output[2 * n] = '\0';
	while (n--) {
		output[2 * n + 0] = lut[hashsum[n]][0];
		output[2 * n + 1] = lut[hashsum[n]][1];
	}
}
