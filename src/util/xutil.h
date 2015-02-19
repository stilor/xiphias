/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Fail-safe utility functions.
*/

#ifndef __util_xutil_h_
#define __util_xutil_h_

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "defs.h"

void *xmalloc(size_t sz);
void *xrealloc(const void *ptr, size_t sz);
void xfree(const void *ptr);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t sz);
char *xvasprintf(const char *fmt, va_list ap);
char *xasprintf(const char *fmt, ...) __printflike(1,2);

/**
    Compare a UTF-8 string to a local-encoded string.

    @param us Unicode string
    @param ls Local-encoded string
    @return true if strings match, false otherwise
*/
static inline bool
xustreq(const uint8_t *us, const char *ls)
{
    return !strcmp((const char *)us, ls);
}

/**
    Compare a part of a UTF-8 string to a part of a local-encoded string.

    @param us Unicode string
    @param ls Local-encoded string
    @param n Number of bytes to compare
    @return true if strings match, false otherwise
*/
static inline bool
xustrneq(const uint8_t *us, const char *ls, size_t n)
{
    return !strncmp((const char *)us, ls, n);
}

/**
    Check if a UCS-4 code point is equal to locally-encoded character.

    @param uc UCS-4 character
    @param lc Locally-encoded character
    @return true if characters are equal
*/
static inline bool
xuchareq(uint32_t uc, char lc)
{
    return uc == (unsigned char)lc;
}

/**
    Check if a UCS-4 character is in range defined by locally-encoded
    characters. Note that the range order is in UCS-4 ordering!

    @param uc UCS-4 character
    @param lb Range start, locally-encoded
    @param le Range end, locally-encoded
    @param true if in range
*/
static inline bool
xucharin(uint32_t uc, char lb, char le)
{
    return uc >= (unsigned char)lb && uc <= (unsigned char)le;
}

/**
    Wrapper for xstrndup, in case UTF-8 needs to be converted to local
    encoding.

    @param us Unicode string
    @param sz Size of the unicode string, in bytes
    @return Copied string in local encoding
*/
static inline char *
xustrndup(const uint8_t *us, size_t sz)
{
    return xstrndup((const char *)us, sz);
}

#endif
