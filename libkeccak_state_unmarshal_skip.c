/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Gets the number of bytes the `libkeccak_state_t` stored
 * at the beginning of `data` occupies
 * 
 * @param   data  The data buffer
 * @return        The byte size of the stored state
 */
size_t
libkeccak_state_unmarshal_skip(const void *restrict data_)
{
	const char *restrict data = data_;
	data += (7 * sizeof(long int) + 26 * sizeof(int64_t)) / sizeof(char);
	return sizeof(libkeccak_state_t) - sizeof(char *) + *(const size_t *)data * sizeof(char);
}
