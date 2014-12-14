/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

#include <stdio.h>
#include <stdlib.h>

#include "util/xutil.h"

void *
xmalloc(size_t sz)
{
    void *rv;

    if ((rv = malloc(sz)) == NULL) {
        OOPS;
    }
    return rv;
}
