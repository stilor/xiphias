/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Murmurhash 3 implementation.
    According to Murmurhash home page, https://code.google.com/p/smhasher/,
    "All MurmurHash versions are public domain software, and the author
    disclaims all copyright to their code."

    Based on http://smhasher.googlecode.com/svn/trunk/MurmurHash3.cpp.
    This adapted version implements only 32-bit version (according to
    documentation, it is faster for small strings - which is expected use
    case).
*/
#include <stdint.h>
#include "util/defs.h"
#include "util/murmurhash.h"

/// Value used as a seed
#define MURMUR_SEED     0

/**
    Rotate 32-bit value left.

    @param x Value
    @param r Number of bits
    @return Rotated value
*/
static inline uint32_t
rotl32(uint32_t x, int8_t r)
{
  return (x << r) | (x >> (32 - r));
}

/**
    Architecture-specific 32-bit read, possibly unaligned.

    @param base Base pointer
    @param idx Index
    @return 32-bit value obtained
*/
static inline uint32_t
fetch32(uint32_t *base, int idx)
{
#if defined(__i386__) || defined(__x86_64__)
    return base[idx];
#else
#warning "Need implementation of unaligned 32-bit reads for this architecture"
    uint32_t val;

    memcpy(val, &base[idx], 4);
    return val;
#endif
}

/**
    32-bit version of MurmurHash3.

    @param key Key to be hashed
    @param len Size of the key
    @return Hash value
*/
uint32_t
murmurhash32(const void *key, size_t len)
{
    const uint8_t *data = (const uint8_t *)key;
    const int nblocks = len / 4;
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    uint32_t h1 = MURMUR_SEED;
    int i;

    // Body
    const uint32_t *blocks = (const uint32_t *)(data + nblocks * 4);
    for (i = -nblocks; i; i++) {
        uint32_t k1 = blocks[i];

        k1 *= c1;
        k1 = rotl32(k1, 15);
        k1 *= c2;

        h1 ^= k1;
        h1 = rotl32(h1, 13);
        h1 = h1 * 5 + 0xe6546b64;
    }

    // Tail
    const uint8_t *tail = data + nblocks * 4;
    uint32_t k1 = 0;
    switch (len & 3) {
    case 3:
        k1 ^= tail[2] << 16;
        // FALLTHRU
    case 2:
        k1 ^= tail[1] << 8;
        // FALLTHRU
    case 1:
        k1 ^= tail[0];
        k1 *= c1;
        k1 = rotl32(k1, 15);
        k1 *= c2;
        h1 ^= k1;
    }

    // Finalization
    h1 ^= len;
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;
    return h1;
}
