/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/**
    @file
    OOPS global variables for coverage tests
*/
#include <setjmp.h>
#include "util/defs.h"

/**
    Pointer to recovery buffer.
    @todo Because of this, bin/xmlreader has to depend on test
    library even in non-coverage mode. Need to build normal/coverage
    objects alongside each other, and be able to specify different
    dependencies in each mode.
*/
jmp_buf *oops_buf;
