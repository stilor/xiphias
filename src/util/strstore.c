/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Implementation of refcounted string storage.
*/
#include <stdint.h>
#include <string.h>

#include "util/defs.h"
#include "util/queue.h"
#include "util/xutil.h"
#include "util/murmurhash.h"

#include "util/strstore.h"

/// String storage item
typedef struct item_s {
    SLIST_ENTRY(item_s) link;   ///< All items in a bucket
    size_t len;                 ///< Length of the string
    uint32_t hval;              ///< Hash value of the string
    uint32_t refcnt;            ///< Reference count
    utf8_t str[];               ///< Actual string
} item_t;

/// Bucket in a storage
typedef SLIST_HEAD(bucket_s, item_s) bucket_t;

/// Internal structure of a string storage
struct strstore_s {
    uint32_t bucket_mask;       ///< Mask to get bucket # from hash value
    bucket_t buckets[];         ///< Storage buckets
};

/**
    Create a string storage of the specified size.

    @param order log2 of the number of buckets in the storage
    @return Storage handle
*/
strstore_t *
strstore_create(unsigned int order)
{
    strstore_t *store;
    uint32_t i;

    // 0 does not make much sense; 32 is the max number of bits in hash value
    OOPS_ASSERT(order > 0 && order < 32);
    i = 1 << order;
    store = xmalloc(sizeof(strstore_t) + i * sizeof(bucket_t));
    store->bucket_mask = --i;
    do {
        SLIST_INIT(&store->buckets[i]);
    } while (i--);
    return store;
}

/**
    Destroy string storage with all the strings in it

    @param store Storage to destroy
    @return Nothing
*/
void
strstore_destroy(strstore_t *store)
{
    bucket_t *bucket;
    item_t *item;
    uint32_t i;

    for (i = 0; i <= store->bucket_mask; i++) {
        bucket = &store->buckets[i];
        while ((item = SLIST_FIRST(bucket)) != NULL) {
            SLIST_REMOVE_HEAD(bucket, link);
            xfree(item);
        }
    }
    xfree(store);
}

/**
    Find if the string is already in the storage and if not,
    store it. Then return the storage's copy.

    @param store Store to use
    @param s String to duplicate. It must not contain NUL characters
        inside the string, but may not be NUL-terminated.
    @param len Length of the duplicated string
    @return Stored copy of the string. Always NUL terminated at @a len.
*/
const utf8_t *
strstore_ndup(strstore_t *store, const utf8_t *s, size_t len)
{
    uint32_t hval = murmurhash32(s, len);
    bucket_t *bucket = &store->buckets[hval & store->bucket_mask];
    item_t *item;

    // Search if the string is already in store
    SLIST_FOREACH(item, bucket, link) {
        if (item->hval == hval && item->len == len && !memcmp(item->str, s, len)) {
            // Hit!
            item->refcnt++;
            return item->str;
        }
    }

    // Not in store, create a new item
    item = xmalloc(sizeof(item_t) + len + 1);
    item->len = len;
    item->hval = hval;
    item->refcnt = 1;
    memcpy(item->str, s, len);
    item->str[len] = 0;
    SLIST_INSERT_HEAD(bucket, item, link);
    return item->str;
}

/**
    Release a reference to a stored string. If it was the last reference,
    remove the string from the storage.

    @param store Store to use
    @param s String to be released. The string pointer must be the one
        returned by strstore_ndup().
    @return Nothing.
*/
void
strstore_free(strstore_t *store, const utf8_t *s)
{
    size_t len = strlen((const char *)s); // Secret knowledge: NUL terminates string in UTF8, too
    uint32_t hval = murmurhash32(s, len);
    bucket_t *bucket = &store->buckets[hval & store->bucket_mask];
    item_t *prev, *item;

    // Search if the string is already in store
    prev = NULL;
    SLIST_FOREACH(item, bucket, link) {
        if (item->hval == hval && item->len == len && !memcmp(item->str, s, len)) {
            // Found!
            if (!--item->refcnt) {
                // No more references
                if (prev) {
                    SLIST_REMOVE_AFTER(prev, link);
                }
                else {
                    SLIST_REMOVE_HEAD(bucket, link);
                }
                xfree(item);
            }
            return;
        }
        prev = item;
    }

    // Expected but not found in the store.
    OOPS;
}
