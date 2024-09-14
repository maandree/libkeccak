/* See LICENSE file for copyright and license details. */


/**
 * Get message suffix for cSHAKE hashing
 * 
 * @param   nlen  Whether the function-name bit string is non-empty
 * @param   slen  Whether the customisation bit string is non-empty
 * @return        The message suffix to use
 */
LIBKECCAK_GCC_ONLY(__attribute__((__nothrow__, __warn_unused_result__, __const__, __returns_nonnull__)))
inline const char *
libkeccak_cshake_suffix(size_t nlen, size_t slen)
{
	return (nlen || slen) ? "00" : LIBKECCAK_SHAKE_SUFFIX;
}


/**
 * Fill in a `struct libkeccak_spec` for a cSHAKEx hashing
 * 
 * @param  spec:struct libkeccak_spec *  The specifications datastructure to fill in
 * @param  x:long                        The value of x in `cSHAKEx`, half the capacity
 * @param  d:long                        The output size
 */
#define libkeccak_spec_cshake libkeccak_spec_rawshake


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
LIBKECCAK_GCC_ONLY(__attribute__((__nonnull__(1), __nothrow__)))
void libkeccak_cshake_initialise(struct libkeccak_state *restrict,
                                 const void *, size_t, size_t, const char *,
                                 const void *, size_t, size_t, const char *);


/* TODO add libkeccak_cshakesum_fd */
