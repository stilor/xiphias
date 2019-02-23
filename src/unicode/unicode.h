/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Unicode functions
*/
#ifndef __unicode_unicode_h_
#define __unicode_unicode_h_

#include <stdint.h>
#include <string.h>

#include "util/xutil.h"

/// Character indicating an error or unrecognized byte in the stream
#define UCS4_REPLACEMENT_CHARACTER   0xFFFD

/// Used as a sentinel code
#define UCS4_STOPCHAR   (0xFFFFFFFF)

/// Absence of a character; may be OR'ed with UCS4_LASTCHAR
#define UCS4_NOCHAR     (0x00FFFFFF)

/// OR'ed by conditional read functions to indicate a stop after the current character
#define UCS4_LASTCHAR   (0x80000000)

/// Codepoint mask 
#define UCS4_CODEPOINT  (0x00FFFFFF)

/// Maximum allowed UCS-4 codepoint
#define UCS4_MAX        (0x0010FFFF)

/// Surrogates: first
#define UCS4_SURROGATE_MIN  (0xD800)

/// Surrogates: last
#define UCS4_SURROGATE_MAX  (0xDFFF)

/// Maximum number of bytes to encode a character in UTF-8
#define UTF8_LEN_MAX    4

/// Code point
typedef uint32_t ucs4_t;

/// UTF-8 unit
typedef uint8_t utf8_t;

#define U(x) ((const utf8_t *)(x))
#define U_ARRAY(x) (x)

/**
    Helper function for implementing decoders: get UTF-8 encoding
    length for a code point.

    @param cp Code point (Unicode character)
    @return Length (1 or more bytes)
*/
static inline size_t
utf8_clen(ucs4_t cp)
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
        OOPS;
    }
}

/**
    Helper function for implementing decoders: store UTF-8 multibyte
    sequence at the specified pointer and advance the pointer.

    @param pp Pointer to pointer where the code point is stored
    @param cp Code point
    @return None
*/
static inline void
utf8_store(utf8_t **pp, ucs4_t cp)
{
    utf8_t *p = *pp;

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
        OOPS;
    }
    *pp = p;
}

/**
    Helper function: load a UCS-4 code point from its UTF-8 representation.
    Assumes the character is fully available in the buffer and is valid representation.

    @param pp Pointer to pointer where the codepoint is loaded from
    @return Loaded codepoint
*/
static inline ucs4_t
utf8_load(const utf8_t **pp)
{
    const utf8_t *p = *pp;
    ucs4_t rv;

    if (*p < 0x80) {
        rv = *p++;
    }
    else if (*p < 0xC0) {
        OOPS;
    }
    else if (*p < 0xE0) {
        rv = (*p++ & 0x1F) << 6;
        rv |= (*p++ & 0x3F);
    }
    else if (*p < 0xF0) {
        rv = (*p++ & 0xF) << 12;
        rv |= (*p++ & 0x3F) << 6;
        rv |= (*p++ & 0x3F);
    }
    else if (*p < 0xF5) {
        rv = (*p++ & 0x7) << 18;
        rv |= (*p++ & 0x3F) << 12;
        rv |= (*p++ & 0x3F) << 6;
        rv |= (*p++ & 0x3F);
    }
    else {
        OOPS;
    }
    *pp = p;
    return rv;
}

/**
    Compare a UTF-8 string to a local-encoded string.

    @param us Unicode string
    @param ls Local-encoded string
    @return true if strings match, false otherwise
*/
static inline bool
utf8_eq(const utf8_t *us, const char *ls)
{
    return !strcmp((const char *)us, ls);
}

/**
    Compare a part of a UTF-8 string to a part of a local-encoded string.

    @param us Unicode string
    @param ls Local-encoded string
    @param n Number of bytes (in UTF-8) to compare
    @return true if strings match, false otherwise
*/
static inline bool
utf8_eqn(const utf8_t *us, const char *ls, size_t n)
{
    return !strncmp((const char *)us, ls, n);
}

/**
    Wrapper for xstrndup, in case UTF-8 needs to be converted to local
    encoding.

    @param us Unicode string
    @param sz Size of the unicode string, in bytes
    @return Copied string in local encoding
*/
static inline char *
utf8_ndup(const utf8_t *us, size_t sz)
{
    return xstrndup((const char *)us, sz);
}

/**
    Wrapper for strlen.

    @param us Unicode string
    @return Length of the string
*/
static inline size_t
utf8_len(const utf8_t *us)
{
    return strlen((const char *)us);
}

/**
    Check if a UCS-4 code point is equal to locally-encoded character.

    @param uc UCS-4 character
    @param lc Locally-encoded character
    @return true if characters are equal
*/
static inline bool
ucs4_cheq(ucs4_t uc, char lc)
{
    return uc == (unsigned char)lc;
}

/**
    Check if a UCS-4 character is in range defined by locally-encoded
    characters. Note that the range order is in UCS-4 ordering!

    @param uc UCS-4 character
    @param lb Range start, locally-encoded
    @param le Range end, locally-encoded
    @return true if in range
*/
static inline bool
ucs4_chin(ucs4_t uc, char lb, char le)
{
    return uc >= (unsigned char)lb && uc <= (unsigned char)le;
}

/**
    Get a UCS-4 representation of a locally encoded character.

    @param lc Locally encoded character
    @return UCS-4 codepoint for @a lc
*/
static inline ucs4_t
ucs4_fromlocal(char lc)
{
    return (unsigned char)lc;
}

/**
    Get a temporary locally-encoded string from a UTF-8 string.

    @param us UTF-8 string
    @return locally encoded string
*/
static inline const char *
utf8_strtolocal(const utf8_t *us)
{
    return (const char *)us;
}

/**
    Free any allocations made by utf8_strtolocal().

    @param ls Local temporary string
    @return Nothing
*/
static inline void
utf8_strfreelocal(const char *ls)
{
    // No-op
}

#if defined(OOPS_COVERAGE)
void ucs4_assert_does_not_compose(ucs4_t cp);
void ucs4_assert_does_not_compose_with_preceding(ucs4_t cp);

#define UCS4_ASSERT(a, ...) \
    static void __constructor \
    concat(ucs4_assert__, __LINE__)(void) \
    { \
        ucs4_assert_##a(__VA_ARGS__); \
    }

#else
#define UCS4_ASSERT(...)
#endif

#include "ucs4data.h"

#endif
