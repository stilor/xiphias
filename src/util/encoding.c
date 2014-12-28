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

// FIXME: this is not thread-safe. Protect registration/search with a mutex? Or require
// that registration be done before using anything else in multithreaded context?
static STAILQ_HEAD(, encoding_s) encodings = STAILQ_HEAD_INITIALIZER(encodings);

void
encoding_register(encoding_t *enc)
{
    if (encoding_search(enc->name)) {
        OOPS;
    }
    STAILQ_INSERT_TAIL(&encodings, enc, link);
}

const encoding_t *
encoding_search(const char *name)
{
    const encoding_t *enc;

    STAILQ_FOREACH(enc, &encodings, link) {
        if (!strcasecmp(name, enc->name)) {
            return enc;
        }
    }
    return NULL;
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
    {
        .encname = "UTF-32BE",
        .sig = { 0x00, 0x00, 0xFE, 0xFF },
        .siglen = 4,
        .is_bom = true,
    },
    {
        .encname = "UTF-32LE",
        .sig = { 0xFF, 0xFE, 0x00, 0x00 },
        .siglen = 4,
        .is_bom = true,
    },
    {
        .encname = "UTF-32-2143",
        .sig = { 0x00, 0x00, 0xFF, 0xFE },
        .siglen = 4,
        .is_bom = true,
    },
    {
        .encname = "UTF-32-3412",
        .sig = { 0xFE, 0xFF, 0x00, 0x00 },
        .siglen = 4,
        .is_bom = true,
    },
    {
        .encname = "UTF-16BE",
        .sig = { 0xFE, 0xFF },
        .siglen = 2,
        .is_bom = true,
    },
    {
        .encname = "UTF-16LE",
        .sig = { 0xFF, 0xFE },
        .siglen = 2,
        .is_bom = true,
    },
    {
        .encname = "UTF-8",
        .sig = { 0xEF, 0xBB, 0xBF },
        .siglen = 3,
        .is_bom = true,
    },
    {
        .encname = "UTF-32BE",
        .sig = { 0x00, 0x00, 0x00, 0x3C },
        .siglen = 4,
        .is_bom = false,
    },
    {
        .encname = "UTF-32LE",
        .sig = { 0x3C, 0x00, 0x00, 0x00 },
        .siglen = 4,
        .is_bom = false,
    },
    {
        .encname = "UTF-32-2143",
        .sig = { 0x00, 0x00, 0x3C, 0x00 },
        .siglen = 4,
        .is_bom = false,
    },
    {
        .encname = "UTF-32-3412",
        .sig = { 0x00, 0x3C, 0x00, 0x00 },
        .siglen = 4,
        .is_bom = false,
    },
    {
        .encname = "UTF-16BE",
        .sig = { 0x00, 0x3C, 0x00, 0x3F },
        .siglen = 4,
        .is_bom = false,
    },
    {
        .encname = "UTF-16LE",
        .sig = { 0x3C, 0x00, 0x3F, 0x00 },
        .siglen = 4,
        .is_bom = false,
    },
    {
        .encname = "UTF-8",
        .sig = { 0x3C, 0x3F, 0x78, 0x6D },
        .siglen = 4,
        .is_bom = false,
    },
    {
        .encname = "EBCDIC",
        .sig = { 0x4C, 0x6F, 0xA7, 0x94 },
        .siglen = 4,
        .is_bom = false,
    },
};

bool
encoding_compatible(const encoding_t *enc1, const encoding_t *enc2)
{
    // If either of them has compatibility check method, use it
    if (enc1->compatible) {
        return enc1->compatible(enc2);
    }
    if (enc2->compatible) {
        return enc2->compatible(enc1);
    }
    // Otherwise, check if they have the same compatibility tag,
    // and neither is 'unknown'.
    return enc1->enctype != ENCODING_T_UNKNOWN
            && enc1->enctype == enc2->enctype;
}

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


static void *
init_dummy(const void *data)
{
    return NULL;
}

static void
destroy_dummy(void *baton)
{
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

static void
xlate_UTF8(strbuf_t *buf, void *baton, uint32_t **pout, uint32_t *end_out)
{
    uint32_t *out = *pout;
    uint32_t val;
    uint8_t *ptr, *begin, *end;
    size_t len;

    len = 0;
    do {
        strbuf_getptr(buf, (void **)&begin, (void **)&end);
        if (begin == end) {
            // No more input available. Check if we're in the middle of the sequence
            if (len) {
                OOPS;
            }
            break;
        }
        ptr = begin;
        while (out < end_out && ptr < end) {
            if (!len) {
                // New character
                val = *ptr++;
                if ((len = utf8_len[val]) == 0) {
                    OOPS;   // Bad byte sequence
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
                val |= (*ptr++) & 0x3F; // Continuation: 6 LS bits
                len--;
            }
            if (!len) {
                // Character complete
                *out++ = val;
            }
        }
        // Mark the number of bytes we consumed as read
        strbuf_read(buf, NULL, ptr - begin, false);
    } while (out < end_out);

    *pout = out;
}

///
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
    .enctype = ENCODING_T_UTF16LE,
    .init = init_dummy,
    .destroy = destroy_dummy,
    .xlate = xlate_UTF16LE,
};


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
    .enctype = ENCODING_T_UTF16BE,
    .init = init_dummy,
    .destroy = destroy_dummy,
    .xlate = xlate_UTF16BE,
};


static bool
compat_UTF16(const encoding_t *other)
{
    // UTF-16 is a compatible declaration for either big- or little-endian flavor
    return other->enctype == ENCODING_T_UTF16LE
            || other->enctype == ENCODING_T_UTF16BE;
}

static encoding_t enc_UTF16 = {
    .name = "UTF-16",
    .compatible = compat_UTF16,
};

// --- Register known encodings
static void __constructor
encodings_autoinit(void)
{
    encoding_register(&enc_UTF8);
    encoding_register(&enc_UTF16LE);
    encoding_register(&enc_UTF16BE);
    encoding_register(&enc_UTF16);
}
