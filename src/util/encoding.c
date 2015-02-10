/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    String buffer implementation.
*/
#include <string.h>

#include "util/defs.h"
#include "util/xutil.h"
#include "util/strbuf.h"

#include "util/encoding.h"

/// List of all encodings
typedef STAILQ_HEAD(encoding_list_s, encoding_s) encoding_list_t;

// FIXME: this is not thread-safe. Protect registration/search with a mutex? Or require
// that registration be done before using anything else in multithreaded context?
static encoding_list_t encodings = STAILQ_HEAD_INITIALIZER(encodings);

/**
    Search for an encoding by name

    @param name Encoding name
    @return Encoding pointer, or NULL if not found
*/
const encoding_t *
encoding_search(const char *name)
{
    const encoding_t *enc;

    STAILQ_FOREACH(enc, &encodings, link) {
        // "XML processors SHOULD match character encoding names in a case-insensitive way"
        if (!strcasecmp(name, enc->name)) {
            return enc;
        }
    }
    return NULL;
}

/**
    Register an encoding.

    @param enc Encoding being registered
    @return None
*/
void
encoding_register(encoding_t *enc)
{
    if (!encoding_search(enc->name)) {
        // TBD insert at head to give later registrations higher precedence?
        STAILQ_INSERT_TAIL(&encodings, enc, link);
    }
}

/**
    Check if two encodings are compatible.

    @param enc1 First encoding
    @param enc2 Second encoding
    @return true if encodings are compatible, false otherwise
*/
bool
encoding_compatible(const encoding_t *enc1, const encoding_t *enc2)
{
    if (enc1->enctype == ENCODING_T_UNKNOWN
            || enc2->enctype != enc1->enctype) {
        return false;
    }
    if (enc1->endian != ENCODING_E_ANY
            && enc2->endian != ENCODING_E_ANY
            && enc1->endian != enc2->endian) {
        return false;
    }
    return true;
}

// Byte order detection, per XML1.1 App.E ("Autodetection of Character Encodings"; non-normative)

// BOM-based encodings. Note the order: UTF32 must be checked first, or UTF-32LE becomes
// indistinguishable from UTF-16LE (and UTF32-3412 indistinguishable from UTF-16BE).

/// BOM encoding description
typedef struct {
    const char *encname;    ///< Detected encoding name
    uint8_t sig[4];         ///< Signature in the first 1..4 bytes
    uint32_t siglen;        ///< Length of the signature
    bool is_bom;            ///< Consume the signature
} bom_encdesc_t;

/// List of "signatures"
static const bom_encdesc_t bom_encodings[] = {
    // Most reliable: have BOM symbol
    { "UTF-32BE",       { 0x00, 0x00, 0xFE, 0xFF }, 4, true, },
    { "UTF-32LE",       { 0xFF, 0xFE, 0x00, 0x00 }, 4, true, },
    { "UTF-32-2143",    { 0x00, 0x00, 0xFF, 0xFE }, 4, true, },
    { "UTF-32-3412",    { 0xFE, 0xFF, 0x00, 0x00 }, 4, true, },
    { "UTF-16BE",       { 0xFE, 0xFF },             2, true, },
    { "UTF-16LE",       { 0xFF, 0xFE },             2, true, },
    { "UTF-8",          { 0xEF, 0xBB, 0xBF },       3, true, },

    // Less reliable: assume '<' as the 1st character
    { "UTF-32BE",       { 0x00, 0x00, 0x00, 0x3C }, 4, false, },
    { "UTF-32LE",       { 0x3C, 0x00, 0x00, 0x00 }, 4, false, },
    { "UTF-32-2143",    { 0x00, 0x00, 0x3C, 0x00 }, 4, false, },
    { "UTF-32-3412",    { 0x00, 0x3C, 0x00, 0x00 }, 4, false, },
    { "UTF-16BE",       { 0x00, 0x3C, },            2, false, },
    { "UTF-16LE",       { 0x3C, 0x00, },            2, false, },
    { "UTF-8",          { 0x3C, },                  1, false, },
    { "IBM500",         { 0x4C, },                  1, false, },    // One of EBCDIC Latin-1 encodings

    // TBD: Try looking for whitespace? #x20/#x9/#xD/#xA/#x85/#x2028 as first character?
};

/**
    Check for byte order (via either byte order mark presence, or how
    the characters from a known start string are arranged). Assumes
    an XML document (which, aside from a possible byte order mark,
    must start with a "<?xml" string).

    @param buf Buffer; must contain at least 4 characters
    @param had_bom Set to true if encoding detected via byte-order mark,
        false otherwise
    @return Encoding name; or NULL if cannot be detected
*/
const char *
encoding_detect_byte_order(strbuf_t *buf, bool *had_bom)
{
    uint8_t first4[4] = { 0, 0, 0, 0 };
    const bom_encdesc_t *b;
    uint32_t i;

    // Lookahead: if there's no BOM, we must leave the content alone
    strbuf_read(buf, first4, sizeof(first4), true);
    for (i = 0, b = bom_encodings; i < sizeofarray(bom_encodings); i++, b++) {
        if (!memcmp(first4, b->sig, b->siglen)) {
            // Match! Consume the BOM, if any
            *had_bom = b->is_bom;
            if (b->is_bom) {
                strbuf_read(buf, first4, b->siglen, false);
            }
            return b->encname;
        }
    }
    return NULL;
}

/*
    Below, basic 1-, 2- and 4-byte encodings.
*/

/**
    Dummy initialization for encoding.

    @param data Unused
    @return Always NULL
*/
static void *
init_dummy(const void *data)
{
    return NULL;
}

/**
    Dummy destructor for encoding.

    @param baton Unused
    @return Nothing.
*/
static void
destroy_dummy(void *baton)
{
}

// --- Common functions for codepage-based encodings

/**
    Constructor for codepage encoding. Just return the codepage mapping table:
    these encodings are stateless, so we do not need to modify it at runtime.

    @param data Pointer to mapping table
    @return Same as @a data
*/
void *
encoding_codepage_init(const void *data)
{
    return DECONST(data);
}

/**
    Destructor for codepage encoding. Nothing to do - these encodings do
    not allocate any resources.
*/
void
encoding_codepage_destroy(void *baton)
{
    // no-op
}

/**
    Translation function for codepage encoding. Advance byte by byte and
    use the mapping table to obtain UCS-4 codepoints.

    @param buf Input string buffer
    @param baton Pointer to mapping table
    @param pout Pointer to beginning of the output buffer; advanced as it's filled
    @param end_out End of the output buffer
    @return Nothing
*/
void
encoding_codepage_xlate(strbuf_t *buf, void *baton, uint32_t **pout, uint32_t *end_out)
{
    const uint32_t *cp = baton;
    uint32_t *out = *pout;
    const uint8_t *ptr;
    const void *begin, *end;

    do {
        if (!strbuf_getptr(buf, &begin, &end)) {
            // No more input available.
            break;
        }
        ptr = begin;
        while (ptr < (const uint8_t *)end && out < end_out) {
            *out++ = cp[*ptr++];
        }
        // Mark the number of bytes we consumed as read
        strbuf_read(buf, NULL, ptr - (const uint8_t *)begin, false);
    } while (out < end_out);
    *pout = out;
}


// --- UTF-8 encoding: dummy functions, this library operates in UTF8 ---

/// Length of the multibyte sequence (0: invalid starting char)
static const uint8_t utf8_len[256] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x00 - ASCII
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x10 - ASCII
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x20 - ASCII
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x30 - ASCII
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x40 - ASCII
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x50 - ASCII
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x60 - ASCII
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x70 - ASCII
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x80 - (continuation)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x90 - (continuation)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xA0 - (continuation)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xB0 - (continuation)
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 0xC0 - 2-byte chars
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 0xD0 - 2-byte chars
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 0xE0 - 3-byte chars
    4, 4, 4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xF0 - 4-byte chars up to 0x10FFFF
};

/**
    Perform translation of UTF-8 encoding to UCS-4 code points.

    @param buf Input string buffer
    @param baton Unused
    @param pout Pointer to beginning of the output buffer; advanced as it's filled
    @param end_out End of the output buffer
    @return Nothing
*/
static void
xlate_UTF8(strbuf_t *buf, void *baton, uint32_t **pout, uint32_t *end_out)
{
    uint32_t *out = *pout;
    uint32_t val;
    const void *begin, *end;
    const uint8_t *ptr;
    uint8_t tmp;
    size_t len;

    len = 0;
    do {
        if (!strbuf_getptr(buf, &begin, &end)) {
            // No more input available. Check if we're in the middle of the sequence
            if (len) {
                // TBD need to pass this to higher level - how?
                OOPS_ASSERT(0);
            }
            break;
        }
        ptr = begin;
        while (out < end_out && ptr < (const uint8_t *)end) {
            if (!len) {
                // New character
                val = *ptr++;
                if ((len = utf8_len[val]) == 0) {
                    // TBD need to pass this to higher level - how?
                    OOPS_ASSERT(0);   // Bad byte sequence
                }
                else if (len > 1) {
                    // Multibyte, mask out length encoding
                    val &= 0x7F >> len;
                }
                len--;  // One byte has been read
            }
            else {
                // Continuing a previous character
                val <<= 6;
                tmp = *ptr++;
                if (tmp < 0x80 || tmp > 0xBF) {
                    // TBD not a valid continuation character - signal an error
                    // TBD per Unicode 5.22 (best substitution practices), FFFD should be
                    // substituted for invalid part (seen so far) and byte that broken
                    // the sequence should start a new sequence.
                }
                val |= tmp & 0x3F; // Continuation: 6 LS bits
                len--;
            }
            if (!len) {
                // Character complete
                *out++ = val;
            }
        }
        // Mark the number of bytes we consumed as read
        strbuf_read(buf, NULL, ptr - (const uint8_t *)begin, false);
    } while (out < end_out);

    *pout = out;
}

static encoding_t enc_UTF8 = {
    .name = "UTF-8",
    .enctype = ENCODING_T_UTF8,
    .init = init_dummy,
    .destroy = destroy_dummy,
    .xlate = xlate_UTF8,
};

// --- UTF-16LE encoding: replace 16-bit encoding with UTF-8 multibytes

// TBD: implement optimized versions if byte order matches host?
// TBD: move to <util/defs.h> or new <util/byteorder.h>

/**
    Translate next two bytes to 16-bit value; little-endian way.

    @param p Input byte stream
    @return 16-bit value
*/
static inline uint16_t
le16tohost(const uint8_t *p)
{
    return (p[1] << 8) | p[0];
}

#define FUNC xlate_UTF16LE
#define TOHOST le16tohost
#include "encoding-utf16.c"

static encoding_t enc_UTF16LE = {
    .name = "UTF-16LE",
    .enctype = ENCODING_T_UTF16,
    .endian = ENCODING_E_LE,
    .init = init_dummy,
    .destroy = destroy_dummy,
    .xlate = xlate_UTF16LE,
};


/**
    Translate next two bytes to 16-bit value; big-endian way.

    @param p Input byte stream
    @return 16-bit value
*/
static inline uint16_t
be16tohost(const uint8_t *p)
{
    return (p[0] << 8) | p[1];
}

#define FUNC xlate_UTF16BE
#define TOHOST be16tohost
#include "encoding-utf16.c"

static encoding_t enc_UTF16BE = {
    .name = "UTF-16BE",
    .enctype = ENCODING_T_UTF16,
    .endian = ENCODING_E_BE,
    .init = init_dummy,
    .destroy = destroy_dummy,
    .xlate = xlate_UTF16BE,
};

/// Meta-encoding: UTF-16 with any endianness, as detected
static encoding_t enc_UTF16 = {
    .name = "UTF-16",
    .enctype = ENCODING_T_UTF16,
    .endian = ENCODING_E_ANY,
};

/**
    Register built-in encodings.

    @return Nothing
*/
static void __constructor
encodings_autoinit(void)
{
    encoding_register(&enc_UTF8);
    encoding_register(&enc_UTF16LE);
    encoding_register(&enc_UTF16BE);
    encoding_register(&enc_UTF16);
}
