/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Fail-safe utility functions.
*/

#ifndef __util_xutil_h_
#define __util_xutil_h_

#include <stddef.h>
#include <stdint.h>

/**
    Allocate memory.

    @param sz Size of chunk to be allocated
    @return Allocated pointer
*/
void *xmalloc(size_t sz);

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


/// FIXME: these functions assume the host compiler uses UTF-8 or something similarly compatible.
/// If this library is ever to support non-UTF-8 systems, will need to implement them (EBCDIC?)
#define xstrcmp(s1, s2)         strcmp((s1), (s2))
#define xstrncmp(s1, s2, l)     strcmp((s1), (s2), (l))

#endif
