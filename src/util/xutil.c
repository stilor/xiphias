/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/defs.h"

#include "util/xutil.h"

/**
    Allocate memory.

    @param sz Size of chunk to be allocated
    @return Allocated pointer
*/
void *
xmalloc(size_t sz)
{
    void *rv;

    if ((rv = malloc(sz)) == NULL) {
        OOPS_ASSERT(0);
    }
    return rv;
}

/**
    Reallocate memory.

    @param ptr Current allocation
    @param sz Desired size
    @return Reallocated memory
*/
void *
xrealloc(const void *ptr, size_t sz)
{
    void *rv;

    if ((rv = realloc(DECONST(ptr), sz)) == NULL) {
        OOPS_ASSERT(0);
    }
    return rv;
}

/**
    Free memory.

    @param ptr Pointer to be freed; safe to pass NULL here
    @return None
*/
void
xfree(const void *ptr)
{
    if (ptr) {
        free(DECONST(ptr));
    }
}

/**
    String duplication.

    @param s String to be duplicated
    @return Allocated copy of the string
*/
char *
xstrdup(const char *s)
{
    char *rv;

    if ((rv = strdup(s)) == NULL) {
        OOPS_ASSERT(0);
    }
    return rv;
}

/**
    Allocating sprintf.

    @param fmt Format
    @param ap Arguments
    @return Allocated string
*/
char *
xvasprintf(const char *fmt, va_list ap)
{
    const size_t default_vasprintf_size = 128;
    va_list ap0;
    size_t alloc, reqd;
    char *buf;

    // Save in case we need to redo the vsnprintf()
    va_copy(ap0, ap);

    // Start with default-size buffer. Most messages are smaller than that; if
    // we see the message has been truncated - reallocate it with a proper size
    alloc = default_vasprintf_size;
    buf = xmalloc(alloc);
    reqd = vsnprintf(buf, alloc, fmt, ap);
    if (reqd >= alloc) {
        alloc = reqd + 1;
        buf = xrealloc(buf, alloc);
        (void)vsnprintf(buf, alloc, fmt, ap0);
    }
    return buf;
}
