/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Miscellaneous definitions.
*/

#ifndef __util_defs_h_
#define __util_defs_h_

#include <stddef.h>
#include <stdint.h>

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

#include "oops.h"

#endif
