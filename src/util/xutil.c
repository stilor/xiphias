/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

#include <stdarg.h>
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
        OOPS_ASSERT(0);
    }
    return rv;
}

void *
xrealloc(const void *ptr, size_t sz)
{
    void *rv;

    if ((rv = realloc(DECONST(ptr), sz)) == NULL) {
        OOPS_ASSERT(0);
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
        OOPS_ASSERT(0);
    }
    return rv;
}

#define DFLT_VASPRINTF_SIZE     128
char *
xvasprintf(const char *fmt, va_list ap)
{
    va_list ap0;
    size_t alloc, reqd;
    char *buf;

    // Save in case we need to redo the vsnprintf()
    va_copy(ap0, ap);

    // Start with default-size buffer. Most messages are smaller than that; if
    // we see the message has been truncated - reallocate it with a proper size
    alloc = DFLT_VASPRINTF_SIZE;
    buf = xmalloc(alloc);
    reqd = vsnprintf(buf, alloc, fmt, ap);
    if (reqd >= alloc) {
        alloc = reqd + 1;
        buf = xrealloc(buf, alloc);
        (void)vsnprintf(buf, alloc, fmt, ap0);
    }
    return buf;
}
