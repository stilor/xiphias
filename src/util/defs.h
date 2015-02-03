/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Miscellaneous definitions.
*/

#ifndef __util_defs_h_
#define __util_defs_h_

#include <stddef.h>
#include <stdint.h>

// FIXME: For now, just print and exit. Will implement cleanup registration
// later. Also, save errors into a given error handle.
#include <stdio.h>
#include <stdlib.h>

/// Custom assertion macro.
// FIXME: conditional OOPS -> convert to error handling or assert
#define OOPS_ASSERT(c) do { \
    if (!(c)) { \
        fprintf(stderr, "OOPS [%s] at %s:%d\n", #c, __FILE__, __LINE__); \
        abort(); \
    } \
} while (0)

// FIXME: find a better place for such common defs?

/// Calculate the number of elements in an array
#define sizeofarray(a) ((size_t)(sizeof(a) / sizeof(*a)))

/// Strip 'const' qualifier from a pointer.
#define DECONST(v)  ((void *)(uintptr_t)(v))

/// Denote a function to be called at initialization time
#define __constructor __attribute__((__constructor__))

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

#endif
