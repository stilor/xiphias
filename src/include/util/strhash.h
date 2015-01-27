/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    String-keyed hash.
*/

#ifndef __util_strhash_h_
#define __util_strhash_h_

#include <stddef.h>

/// Opaque hash for string storage
typedef struct strhash_s strhash_t;

strhash_t *strhash_create(unsigned int order, void (*payload_destroy)(void *));
void strhash_destroy(strhash_t *hash);
void strhash_setn(strhash_t *hash, const char *s, size_t len, void *payload);
void *strhash_getn(strhash_t *hash, const char *s, size_t len);

static inline void
strhash_set(strhash_t *hash, const char *s, void *payload)
{
    strhash_setn(hash, s, strlen(s), payload);
}

static inline void *
strhash_get(strhash_t *hash, const char *s)
{
    return strhash_getn(hash, s, strlen(s));
}

#endif
