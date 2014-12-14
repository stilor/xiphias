/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Fail-safe utility functions.
*/

#ifndef __xutil_h_
#define __xutil_h_

#include <stddef.h>
#include <stdint.h>

// FIXME: For now, just print and exit. Will implement cleanup registration
// later. Also, save errors into a given error handle.
#include <stdio.h>
#include <stdlib.h>
#define OOPS do { \
    fprintf(stderr, "OOPS at %s:%d\n", __FILE__, __LINE__); \
    abort(); \
} while (0)

// FIXME: conditional OOPS -> convert to error handling or assert
#define OOPS_ASSERT(c) do { \
    if (!(c)) { \
        fprintf(stderr, "OOPS [%s] at %s:%d\n", #c, __FILE__, __LINE__); \
        abort(); \
    } \
} while (0)

// FIXME: find a better place for such common defs?
#define DECONST(v)  ((void *)(uintptr_t)(v))
#define __constructor __attribute__((__constructor__))
#define min(a,b)    ({ \
            __typeof__(a) __a = (a); \
            __typeof__(b) __b = (b); \
            (__a < __b) ? __a : __b; \
        })

#define max(a,b)    ({ \
            __typeof__(a) __a = (a); \
            __typeof__(b) __b = (b); \
            (__a > __b) ? __a : __b; \
        })

/**
    Allocate memory.

    @param sz Size of chunk to be allocated
    @return Allocated pointer
*/
void *xmalloc(size_t sz);

#endif
