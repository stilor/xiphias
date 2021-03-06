/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Implementation of string-keyed hash.
*/
#include <stdint.h>
#include <string.h>

#include "util/defs.h"
#include "util/queue.h"
#include "util/xutil.h"
#include "util/murmurhash.h"

#include "util/strhash.h"

/// String storage item
typedef struct item_s {
    SLIST_ENTRY(item_s) link;   ///< All items in a bucket
    size_t len;                 ///< Length of the string
    uint32_t hval;              ///< Hash value of the string
    void *payload;              ///< Actual structure stored
    uint8_t key[];              ///< String used as a key
} item_t;

/// Bucket in a storage
typedef SLIST_HEAD(bucket_s, item_s) bucket_t;

/// Internal structure of a string storage
struct strhash_s {
    /// Callback to destroy freed hash item
    void (*payload_destroy)(void *i);

    uint32_t bucket_mask;       ///< Mask to get bucket # from hash value
    bucket_t buckets[];         ///< Storage buckets
};

/**
    Create a string hash of the specified size.

    @param order log2 of the number of buckets in the storage
    @param payload_destroy Callback function to destroy hash item when freed,
        NULL if no destuctor needs to be called
    @return String-keyed hash
*/
strhash_t *
strhash_create(unsigned int order, strhash_payload_destroy_cb_t payload_destroy)
{
    strhash_t *hash;
    uint32_t i;

    // 0 does not make much sense; 32 is the max number of bits in hash value
    OOPS_ASSERT(order < 32);
    i = 1 << order;
    hash = xmalloc(sizeof(strhash_t) + i * sizeof(bucket_t));
    hash->payload_destroy = payload_destroy;
    hash->bucket_mask = --i;
    do {
        SLIST_INIT(&hash->buckets[i]);
    } while (i--);
    return hash;
}

/**
    Destroy string hash with all items in it.

    @param hash String-keyed hash to destroy
    @return Nothing
*/
void
strhash_destroy(strhash_t *hash)
{
    bucket_t *bucket;
    item_t *item;
    uint32_t i;

    for (i = 0; i <= hash->bucket_mask; i++) {
        bucket = &hash->buckets[i];
        while ((item = SLIST_FIRST(bucket)) != NULL) {
            SLIST_REMOVE_HEAD(bucket, link);
            if (hash->payload_destroy) {
                hash->payload_destroy(item->payload);
            }
            xfree(item);
        }
    }
    xfree(hash);
}

/**
    Set/delete an item in a hash.

    @param hash String-keyed hash
    @param key Key to the hash. It must not contain NUL characters
        inside the string, but may not be NUL-terminated. It is tailored for NUL-terminated
        strings (char, utf8_t) but can use any binary blobs as a key.
    @param len Length of the key string
    @param payload Value to store in the hash
    @return Pointer to the "permanent" key string (that is stored in hash as long as the
        item itself), NUL-terminated.
*/
const void *
strhash_set(strhash_t *hash, const void *key, size_t len, void *payload)
{
    uint32_t hval = murmurhash32(key, len);
    bucket_t *bucket = &hash->buckets[hval & hash->bucket_mask];
    item_t *item, *prev;

    // Search if the item is already in a hash
    prev = NULL;
    SLIST_FOREACH(item, bucket, link) {
        if (item->hval == hval && item->len == len && !memcmp(item->key, key, len)) {
            if (item->payload != payload) {
                // Free the old item and either set the new value, or delete
                hash->payload_destroy(item->payload);
                if (payload) {
                    item->payload = payload; // Save new value
                }
                else {
                    // Delete
                    if (prev) {
                        SLIST_REMOVE_AFTER(prev, link);
                    }
                    else {
                        SLIST_REMOVE_HEAD(bucket, link);
                    }
                    xfree(item);
                    return NULL;
                }
            }
            return item->key;
        }
        prev = item;
    }

    // Not found, create a new record
    item = xmalloc(sizeof(item_t) + len + 1);
    item->len = len;
    item->hval = hval;
    item->payload = payload;
    memcpy(item->key, key, len);
    item->key[len] = '\0';
    SLIST_INSERT_HEAD(bucket, item, link);
    return item->key;
}

/**
    Get a value from the hash.

    @param hash String-keyed hash.
    @param key Key to the hash
    @param len Length of the key string
    @return Nothing.
*/
void *
strhash_get(strhash_t *hash, const void *key, size_t len)
{
    uint32_t hval = murmurhash32(key, len);
    bucket_t *bucket = &hash->buckets[hval & hash->bucket_mask];
    item_t *item;

    SLIST_FOREACH(item, bucket, link) {
        if (item->hval == hval && item->len == len && !memcmp(item->key, key, len)) {
            return item->payload;
        }
    }
    return NULL; // Not found in the hash
}

/**
    Iterator over all items in hash.

    @param hash String-keyed hash
    @param cb Callback for each element
    @param arg Argument to callback
    @return Nothing
*/
void
strhash_foreach(strhash_t *hash, strhash_foreach_cb_t cb, void *arg)
{
    item_t *item, *temp;
    uint32_t i;

    for (i = 0; i <= hash->bucket_mask; i++) {
        SLIST_FOREACH_SAFE(item, &hash->buckets[i], link, temp) {
            cb(arg, item->key, item->len, item->payload);
        }
    }
}
