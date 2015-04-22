/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Custom assertions. Disabled inlining on coverage runs.
    Included via <util/defs.h> - but separate so that this file
    is excluded from coverage testing.
*/

#ifndef __test_common_oops_h_
#define __test_common_oops_h_

#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>

#include "util/defs.h"

extern jmp_buf *oops_buf;

#define OOPS_EXPECT_BEGIN() \
        do { \
            jmp_buf expect_oops_buf; \
            if (!setjmp(expect_oops_buf)) { \
                oops_buf = &expect_oops_buf;

#define OOPS_EXPECT_END(oopsdidnothappen) \
                printf("Expected OOPS, but did not happen\n"); \
                oopsdidnothappen; \
            } \
            else { \
                oops_buf = NULL; \
            } \
        } while (0)

static inline void __noreturn
__oops(void)
{
    printf("OOPS in coverage run\n");
    if (!oops_buf) {
        exit(1);
    }
    else {
        longjmp(*oops_buf, 1);
    }
}

static inline void
__oops_assert(unsigned long c)
{
    if (!c) {
        __oops();
    }
}

#define OOPS_ASSERT(c)      __oops_assert((unsigned long)(c))
#define OOPS                __oops()
#define OOPS_UNREACHABLE    __unreachable()

#endif
