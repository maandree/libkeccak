/* See LICENSE file for copyright and license details. */
#include "libkeccak.h"


#ifndef ALLOCA_LIMIT
# define ALLOCA_LIMIT (16UL << 10)
#endif


#include <sys/stat.h>
#if ALLOCA_LIMIT > 0
# if defined(__GLIBC__) || defined(__sun) || defined(__CYGWIN__) || defined(__APPLE__)
#  include <alloca.h>
# elif defined(_WIN32)
#  include <malloc.h>
#  if !defined(alloca)
#   define alloca _alloca  /* For clang with MS Codegen */
#  endif
# endif
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

# if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wunknown-attributes"
# endif
__attribute__((__optimize__("-O0")))
static void
my_explicit_bzero(void *ptr, size_t size)
{
	(*my_explicit_memset)(ptr, 0, size);
}
# if defined(__clang__)
#  pragma clang diagnostic pop
# endif
#endif
