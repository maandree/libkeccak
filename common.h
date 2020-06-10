/* See LICENSE file for copyright and license details. */
#include "libkeccak.h"


#include <sys/stat.h>
#if defined(__GLIBC__) || defined(__sun) || defined(__CYGWIN__)
#include <alloca.h>
#elif defined(_WIN32)
#include <malloc.h>
#if !defined(alloca)
#define alloca _alloca  // for clang with MS Codegen
#endif
#endif
#include <errno.h>
#include <unistd.h>


/* Use built in functions and branching optimisation if available */
#ifndef __GNUC__
# define __builtin_expect(expression, expect) expression
# define __builtin_memset(dest, c, n) memset(dest, c, n)
# define __builtin_memcpy(dest, src, n) memcpy(dest, src, n)
# define __builtin_memmove(dest, src, n) memmove(dest, src, n)
#endif


/**
 * The outer pad pattern for HMAC
 */
#define HMAC_OUTER_PAD 0x5C

/**
 * The inner pad pattern for HMAC
 */
#define HMAC_INNER_PAD 0x36


#ifdef NEED_EXPLICIT_BZERO
static void *(*volatile my_explicit_memset)(void *, int, size_t) = memset;
static __attribute__((__optimize__("-O0"))) void
my_explicit_bzero(void *ptr, size_t size)
{
	(*my_explicit_memset)(ptr, 0, size);
}
#endif
