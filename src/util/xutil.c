/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/defs.h"

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

void *
xrealloc(const void *ptr, size_t sz)
{
    void *rv;

    if ((rv = realloc(DECONST(ptr), sz)) == NULL) {
        OOPS;
    }
    return rv;
}

void
xfree(const void *ptr)
{
    if (ptr) {
        free(DECONST(ptr));
    }
}

char *
xstrdup(const char *s)
{
    char *rv;

    if ((rv = strdup(s)) == NULL) {
        OOPS;
    }
    return rv;
}
