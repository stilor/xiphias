/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    String-keyed hash.
*/

#ifndef __util_strhash_h_
#define __util_strhash_h_

#include <stddef.h>

#include "util/defs.h"

/// Opaque hash for string storage
typedef struct strhash_s strhash_t;

/// Function to destroy payload when it is evicted from the hash
typedef void (*strhash_payload_destroy_cb_t)(void *);

strhash_t *strhash_create(unsigned int order, strhash_payload_destroy_cb_t payload_destroy);
void strhash_destroy(strhash_t *hash);
const void *strhash_set(strhash_t *hash, const void *s, size_t len, void *payload);
void *strhash_get(strhash_t *hash, const void *s, size_t len);

#endif
