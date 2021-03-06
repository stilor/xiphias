/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Custom assertions. Use either abort()-type, or test assertions.
*/

#ifndef __util_oops_h_
#define __util_oops_h_

#include <stdio.h>
#include <stdlib.h>

#define OOPS_ASSERT(c) \
    ((c) ? (void)0 : \
        ( \
            fprintf(stderr, "OOPS assertion failed [%s] at %s:%d\n", #c, __FILE__, __LINE__), \
            abort(), \
            (void)0 \
        ) \
    )

#define OOPS \
    ( \
        fprintf(stderr, "OOPS at %s:%d\n", __FILE__, __LINE__), \
        abort(), \
        (void)0 \
    )

#define OOPS_UNREACHABLE OOPS

#define OOPS_EXPECT_BEGIN() \
        do { \
            if (0) { \

#define OOPS_EXPECT_END(oopsdidnothappen) \
            } \
            /* assume it did happen - OOPS not overridden unless testing coverage */ \
        } while (0)

#endif
