/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/**
    @file
    Fail-safe functions: we don't expect a failure from any of them;
    any error is an immediate assertion-like termination of the
    application.
*/
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
    void *rv = NULL;

    if (sz) {
        rv = malloc(sz);
        OOPS_ASSERT(rv);
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

    if (sz) {
        rv = realloc(DECONST(ptr), sz);
        OOPS_ASSERT(rv);
    }
    else {
        free(DECONST(ptr));
        rv = NULL;
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

    rv = strdup(s);
    OOPS_ASSERT(rv);
    return rv;
}

/**
    String duplication, limited size.

    @param s String to be duplicated
    @param sz Maximum number of characters to duplicate
    @return Allocated copy of the string
*/
char *
xstrndup(const char *s, size_t sz)
{
    char *rv;

    rv = xmalloc(sz + 1);
    strncpy(rv, s, sz);
    rv[sz] = '\0';
    return rv;
}

/**
    Allocating vsprintf.

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

/**
    Allocating sprintf.

    @param fmt Format
    @return Allocated string
*/
char *
xasprintf(const char *fmt, ...)
{
    va_list ap;
    char *rv;

    va_start(ap, fmt);
    rv = xvasprintf(fmt, ap);
    va_end(ap);
    return rv;
}
