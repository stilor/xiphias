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

#endif
