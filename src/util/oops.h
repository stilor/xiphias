/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Custom assertions. Use either abort()-type, or test assertions.
*/

#ifndef __util_oops_h_
#define __util_oops_h_

#include <stdio.h>
#include <stdlib.h>

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

#define OOPS_UNREACHABLE OOPS

#include "test/oops.h"

#endif
