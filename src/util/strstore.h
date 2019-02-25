/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Reference-counted string storage.
*/

#ifndef __util_strstore_h_
#define __util_strstore_h_

#include <stddef.h>
#include "unicode/unicode.h"

/// Opaque hash for string storage
typedef struct strstore_s strstore_t;

// TBD add an option to limit the comparison length when hashing the string?
strstore_t *strstore_create(unsigned int order);
void strstore_destroy(strstore_t *store);
const utf8_t *strstore_ndup(strstore_t *store, const utf8_t *s, size_t len);
const utf8_t *strstore_dup(strstore_t *store, const utf8_t *s);
bool strstore_isempty(strstore_t *store);
void strstore_free(strstore_t *store, const utf8_t *s);

#endif
