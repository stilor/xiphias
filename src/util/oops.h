/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Custom assertions. Disabled inlining on coverage runs.
    Included via <util/defs.h> - but separate so that this file
    is excluded from coverage testing.
*/

#ifndef __util_oops_h_
#define __util_oops_h_

#include <stdio.h>
#include <stdlib.h>

#if defined(NO_OOPS)
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
