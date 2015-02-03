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

void *xmalloc(size_t sz);
void *xrealloc(const void *ptr, size_t sz);
void xfree(const void *ptr);
char *xstrdup(const char *s);
char *xvasprintf(const char *fmt, va_list ap);

// FIXME: functions below assume the host compiler uses UTF-8 or something similarly compatible.
// If this library is ever to support non-UTF-8 systems, will need to implement them (EBCDIC?)
// Arguments starting with 'l' indicate a character/string in a local (host) encoding

/// Compare a UTF-8 string to a local-encoded string
#define xstrcmp(s1, ls2)         strcmp((s1), (ls2))

/// Compare a limited number of characters in a UTF-8 string to a local-encoded string
#define xstrncmp(s1, ls2, n)     strcmp((s1), (ls2), (n))

/// Check if character c1 (UCS-4) is equal to local character lc2
#define xchareq(c1, lc2)         ((c1) == (lc2))

/// Check if character c1 (UCS-4) is in range [lcs..lce] (range based on Unicode order)
#define xcharin(c1, lcs, lce)    ((c1) >= (lcs) && (c1) <= (lce))

#endif
