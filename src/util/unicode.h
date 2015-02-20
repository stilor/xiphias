/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Unicode functions
*/
#ifndef __util_unicode_h_
#define __util_unicode_h_

#include "ucs4data.h"

/// Character indicating an error or unrecognized byte in the stream
#define UCS4_REPLACEMENT_CHARACTER   0xFFFD

/// Used as a sentinel code
#define UCS4_STOPCHAR    (0xFFFFFFFF)

/// Absence of a character; may be OR'ed with UCS4_LASTCHAR
#define UCS4_NOCHAR      (0x0FFFFFFF)

/// OR'ed by conditional read functions to indicate a stop after the current character
#define UCS4_LASTCHAR    (0x80000000)

/// Maximum allowed UCS-4 codepoint
#define UCS4_MAX         (0x0010FFFF)

/// Maximum number of bytes to encode a character in UTF-8
#define UTF8_LEN_MAX    4


/**
    Helper function for implementing decoders: get UTF-8 encoding
    length for a code point.

    @param cp Code point (Unicode character)
    @return Length (1 or more bytes)
*/
static inline size_t
utf8_len(uint32_t cp)
{
    if (cp < 0x80) {
        return 1;   // ASCII-compatible, single byte
    }
    else if (cp < 0x800) {
        return 2;   // 5-bit start, 6-bit trailing
    }
    else if (cp < 0x10000) {
        return 3;   // 4-bit start, 2x 6-bit trailing
    }
    else if (cp <= UCS4_MAX) { // Unicode limit
        return 4;   // 3-bit start, 3x 6-bit trailing
    }
    else {
        OOPS_ASSERT(0);
    }
}

/**
    Helper function for implementing decoders: store UTF-8 multibyte
    sequence at the specified pointer and advance the pointer.

    @param p Pointer to pointer where the code point is stored
    @param cp Code point
    @return None
*/
static inline void
utf8_store(uint8_t **pp, uint32_t cp)
{
    uint8_t *p = *pp;

    if (cp < 0x80) {
        *p++ = cp;
    }
    else if (cp < 0x800) {
        *p++ = 0xC0 | (cp >> 6);
        *p++ = 0x80 | (cp & 0x3F);
    }
    else if (cp < 0x10000) {
        *p++ = 0xE0 | (cp >> 12);
        *p++ = 0x80 | ((cp >> 6) & 0x3F);
        *p++ = 0x80 | (cp & 0x3F);
    }
    else if (cp < 0x110000) {
        *p++ = 0xF0 | (cp >> 18);
        *p++ = 0x80 | ((cp >> 12) & 0x3F);
        *p++ = 0x80 | ((cp >> 6) & 0x3F);
        *p++ = 0x80 | (cp & 0x3F);
    }
    else {
        OOPS_ASSERT(0);
    }
    *pp = p;
}

#endif
