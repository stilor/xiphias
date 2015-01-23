/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Fail-safe utility functions.
*/

#ifndef __util_xutil_h_
#define __util_xutil_h_

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

/**
    Allocate memory.

    @param sz Size of chunk to be allocated
    @return Allocated pointer
*/
void *xmalloc(size_t sz);

/**
    Reallocate memory.

    @param ptr Current allocation
    @param sz Desired size
    @return Reallocated memory
*/
void *xrealloc(const void *ptr, size_t sz);

/**
    Free memory.

    @param ptr Pointer to be freed
    @return None
*/
void xfree(const void *ptr);

/**
    String duplication.

    @param s String to be duplicated
    @return Allocated copy of the string
*/
char *xstrdup(const char *s);

/**
    Allocating sprintf.

    @param fmt Format
    @param ap Arguments
    @return Allocated string
*/
char *xvasprintf(const char *fmt, va_list ap);

/// FIXME: these functions assume the host compiler uses UTF-8 or something similarly compatible.
/// If this library is ever to support non-UTF-8 systems, will need to implement them (EBCDIC?)
#define xstrcmp(s1, s2)         strcmp((s1), (s2))
#define xstrncmp(s1, s2, l)     strcmp((s1), (s2), (l))
#define xchareq(c1, c2)         ((c1) == (c2))
#define xcharin(c1, cs, ce)     ((c1) >= (cs) && (c1) <= (ce))
#endif
