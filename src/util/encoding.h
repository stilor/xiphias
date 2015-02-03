/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Encoding implementation interface and registry.
*/

#ifndef __util_encoding_h_
#define __util_encoding_h_

#include "defs.h"
#include "queue.h"
#include "strbuf.h"

/// Types of encoding compatibility
enum encoding_compat_e {
    ENCODING_T_UNKNOWN,             ///< Unknown compatibility (always incompatible)
    ENCODING_T_UTF8,                ///< UTF-8 or other byte encoding with ASCII for 00..7e chars
    ENCODING_T_EBCDIC,              ///< Byte encodings compatible with EBCDIC
    ENCODING_T_UTF16,               ///< UTF-16
    ENCODING_T_UTF32,               ///< UTF-32
};

/// Endianness of the encoding
enum encoding_endian_e {
    ENCODING_E_ANY,                 ///< Don't care (or describing any flavor, for meta-encodings)
    ENCODING_E_LE,                  ///< Little-endian
    ENCODING_E_BE,                  ///< Big-endian
    ENCODING_E_2143,                ///< Unusual byte order (2143)
    ENCODING_E_3412,                ///< Unusual byte order (3412)
};

/// Encoding structure
typedef struct encoding_s {
    STAILQ_ENTRY(encoding_s) link;  ///< Linked list pointers
    const char *name;               ///< Encoding name
    enum encoding_compat_e enctype; ///< Encoding type
    enum encoding_endian_e endian;  ///< Endianness
    const void *data;               ///< Encoding-specific data (e.g. equivalence chart)


    // TBD: need a set of functions for output, too

    /**
        Initialize a translator.

        @param data Encoding-specific data
        @return Baton (argument passed to xlate/destroy methods)
    */
    void *(*init)(const void *data);

    /**
        Destroy a translator.

        @param baton Pointer returned by initializer
        @return None
    */
    void (*destroy)(void *baton);

    /**
        Perform the translation of some more content (up to the end of current
        block in the outbut buffer).

        @param buf Buffer to read from
        @param baton Pointer returned by initializer
        @param out Output UCS-4 buffer (adjusted to the next unused character)
        @param end_out Pointer at the next byte past the end of output buffer
        @return None
    */
    void (*xlate)(strbuf_t *buf, void *baton, uint32_t **pout, uint32_t *end_out);
} encoding_t;

void encoding_register(encoding_t *enc);
const encoding_t *encoding_search(const char *name);
bool encoding_compatible(const encoding_t *enc1, const encoding_t *enc2);
const char *encoding_detect_byte_order(strbuf_t *buf, bool *had_bom);

void *encoding_codepage_init(const void *data);
void encoding_codepage_destroy(void *baton);
void encoding_codepage_xlate(strbuf_t *buf, void *baton, uint32_t **pout, uint32_t *end_out);

/// Maximum number of bytes to encode a character in UTF-8
#define MAX_UTF8_LEN    4


/**
    Helper function for implementing decoders: get UTF-8 encoding
    length for a code point.

    @param cp Code point (Unicode character)
    @return Length (1 or more bytes)
*/
static inline size_t
encoding_utf8_len(uint32_t cp)
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
    else if (cp < 0x110000) { // Unicode limit
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
encoding_utf8_store(uint8_t **pp, uint32_t cp)
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
}

/// Character indicating an error or unrecognized byte in the stream
#define UNICODE_REPLACEMENT_CHARACTER   0xFFFD

#endif
