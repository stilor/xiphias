/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Miscellaneous definitions. At this time, GCC-centric.
*/

#ifndef __util_defs_h_
#define __util_defs_h_

#include <stddef.h>
#include <stdint.h>

/// Calculate the number of elements in an array
#define sizeofarray(a) ((size_t)(sizeof(a) / sizeof(*a)))

/// Produce a pointer right past the end of the array
#define endofarray(a) (&(a)[sizeofarray(a)])

/// Concatenate after replacing macros in arguments
#define concat(a,b) __concat(a,b)
#define __concat(a,b)   a##b

/// Strip 'const' qualifier from a pointer.
#define DECONST(v)  ((void *)(uintptr_t)(v))

/// Denote a function to be called at initialization time
#define __constructor __attribute__((__constructor__))

/// Denote a function that does not return
#define __noreturn __attribute__((__noreturn__))

/// Denote unused function/variable
#define __unused __attribute__((__unused__))

/// Denote a function taking printf-style argument
#define __printflike(f,a) __attribute__((__format__(__printf__,f,a)))

/// Warn if the result is not checked
#define __warn_unused_result __attribute__((__warn_unused_result__))

/// Denote an unreachable point in a program
#define __unreachable() __builtin_unreachable()

/// Check if two types are compatible.
#define __types_compat(t1, t2) __builtin_types_compatible_p(t1, t2)

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

#if !defined(OOPS_COVERAGE)
#include "util/oops.h"
#else
#include "test/common/oops.h"
#endif

#endif
