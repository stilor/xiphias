/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Custom assertions. Disabled inlining on coverage runs.
    Included via <util/defs.h> - but separate so that this file
    is excluded from coverage testing.
*/

#ifndef __test_oops_h_
#define __test_oops_h_

#if !defined(OOPS_COVERAGE)

#define EXPECT_OOPS_BEGIN() \
        do { \
            if (0) { \

#define EXPECT_OOPS_END(oopsdidnothappen) \
            } \
            /* assume it did happen - OOPS not overridden unless testing coverage */ \
        } while (0)

#else

// Local, overriding versions below
#undef OOPS
#undef OOPS_ASSERT

#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>

extern jmp_buf *oops_buf;

#define EXPECT_OOPS_BEGIN() \
        do { \
            jmp_buf expect_oops_buf; \
            if (!setjmp(expect_oops_buf)) { \
                oops_buf = &expect_oops_buf;

#define EXPECT_OOPS_END(oopsdidnothappen) \
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

#define OOPS_ASSERT(c) __oops_assert((unsigned long)(c))
#define OOPS __oops()

#endif

#endif
