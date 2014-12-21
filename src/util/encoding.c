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
    // Have the same compatibility tag, and neither is 'unknown'.
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


// --- UTF-8 encoding: dummy functions, this library operates in UTF8 ---

static void *
init_utf8(const void *data)
{
    return NULL;
}

static void
destroy_utf8(void *baton)
{
}

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

static size_t
xlate_utf8(strbuf_t *buf, void *baton, uint32_t *out, size_t nchars)
{
    uint32_t *orig_out = out;
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
        while (nchars && ptr < end) {
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
                nchars--;
            }
        }
        // Mark the number of bytes we consumed as read
        strbuf_read(buf, NULL, ptr - begin, false);
    } while (nchars);

    return out - orig_out;
}

///
static encoding_t enc_utf8 = {
    .name = "UTF-8",
    .enctype = ENCODING_T_UTF8,
    .init = init_utf8,
    .destroy = destroy_utf8,
    .xlate = xlate_utf8,
};


// --- UTF-16BE encoding: replace 16-bit encoding with UTF-8 multibytes


// --- Register known encodings
static void __constructor
encodings_autoinit(void)
{
    encoding_register(&enc_utf8);
}
