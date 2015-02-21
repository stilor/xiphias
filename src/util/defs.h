/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Miscellaneous definitions.
*/

#ifndef __util_defs_h_
#define __util_defs_h_

#include <stddef.h>
#include <stdint.h>

#include <stdio.h>
#include <stdlib.h>

// FIXME: find a better place for such common defs?

/// Calculate the number of elements in an array
#define sizeofarray(a) ((size_t)(sizeof(a) / sizeof(*a)))

/// Strip 'const' qualifier from a pointer.
#define DECONST(v)  ((void *)(uintptr_t)(v))

/// Denote a function to be called at initialization time
#define __constructor __attribute__((__constructor__))

/// Denote a function that does not return
#define __noreturn __attribute__((__noreturn__))

/// Denote a function taking printf-style argument
#define __printflike(f,a) __attribute__((__format__(__printf__,f,a)))

/// Return the least of two values
#define min(a,b)    ({ \
            __typeof__(a) __a = (a); \
            __typeof__(b) __b = (b); \
            (__a < __b) ? __a : __b; \
        })

/// Return the biggest of two values
#define max(a,b)    ({ \
            __typeof__(a) __a = (a); \
            __typeof__(b) __b = (b); \
            (__a > __b) ? __a : __b; \
        })

/// Custom assertion macro.
// FIXME: conditional OOPS -> convert to error handling or assert
#if defined(NO_OOPS)
// OOPS versions for coverage testing
static inline void
__oops_assert(unsigned long c)
{
    if (!c) { exit(1); }
}

static inline void __noreturn
__oops(void)
{
    exit(1);
}

#define OOPS_ASSERT(c) __oops_assert((unsigned long)(c))
#define OOPS __oops()
#else
#define OOPS_ASSERT(c) do { \
    if (!(c)) { \
        fprintf(stderr, "OOPS [%s] at %s:%d\n", #c, __FILE__, __LINE__); \
        abort(); \
    } \
} while (0)
#define OOPS do { \
    fprintf(stderr, "OOPS at %s:%d\n", __FILE__, __LINE__); \
    abort(); \
} while (0)
#endif

#endif
