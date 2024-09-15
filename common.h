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
# define __builtin_strlen(s) strlen(s)
#endif


/**
 * Literal comma that can be passed as a macro argument
 */
#define COMMA ,

/**
 * X-macro-enabled listing of all intergers in [0, 1]
 * 
 * @param  X(int)  The macro to expand 2 times
 * @param  D       Code to insert between each expansion of `X`
 */
#define LIST_2(X, D)\
	X(0) D X(1)

/**
 * X-macro-enabled listing of all intergers in [0, 3]
 * 
 * @param  X(int)  The macro to expand 4 times
 * @param  D       Code to insert between each expansion of `X`
 */
#define LIST_4(X, D)\
	X(0) D X(1) D X(2) D X(3)

/**
 * X-macro-enabled listing of all intergers in [0, 4]
 * 
 * @param  X(int)  The macro to expand 5 times
 * @param  D       Code to insert between each expansion of `X`
 */
#define LIST_5(X, D)\
	X(0) D X(1) D X(2) D X(3) D X(4)

/**
 * X-macro-enabled listing of all intergers in [0, 7]
 * 
 * @param  X(int)  The macro to expand 8 times
 * @param  D       Code to insert between each expansion of `X`
 */
#define LIST_8(X, D)\
	X(0) D X(1) D X(2) D X(3) D X(4) D\
	X(5) D X(6) D X(7)

/**
 * X-macro-enabled listing of all intergers in [0, 24]
 * 
 * @param  X(int)  The macro to expand 25 times
 * @param  D       Code to insert between each expansion of `X`
 */
#define LIST_25(X, D)\
	X( 0) D X( 1) D X( 2) D X( 3) D X( 4) D\
	X( 5) D X( 6) D X( 7) D X( 8) D X( 9) D\
	X(10) D X(11) D X(12) D X(13) D X(14) D\
	X(15) D X(16) D X(17) D X(18) D X(19) D\
	X(20) D X(21) D X(22) D X(23) D X(24)


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
