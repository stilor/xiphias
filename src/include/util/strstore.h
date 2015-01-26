/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Reference-counted string storage.
*/

#ifndef __util_strstore_h_
#define __util_strstore_h_

#include <stddef.h>

/// Opaque hash for string storage
typedef struct strstore_s strstore_t;

strstore_t *strstore_create(unsigned int order);
void strstore_destroy(strstore_t *store);
const char *strstore_ndup(strstore_t *store, const char *s, size_t len);
void strstore_free(strstore_t *store, const char *s);

#endif
