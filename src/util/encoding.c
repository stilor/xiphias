/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    String buffer implementation.
*/
#include <string.h>

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
    bool consume;           ///< Consume the signature
} bom_encdesc_t;

static const bom_encdesc_t bom_encodings[] = {
    {
        .encname = "UTF-32BE",
        .sig = { 0x00, 0x00, 0xFE, 0xFF },
        .siglen = 4,
        .consume = true,
    },
    {
        .encname = "UTF-32LE",
        .sig = { 0xFF, 0xFE, 0x00, 0x00 },
        .siglen = 4,
        .consume = true,
    },
    {
        .encname = "UTF-32-2143",
        .sig = { 0x00, 0x00, 0xFF, 0xFE },
        .siglen = 4,
        .consume = true,
    },
    {
        .encname = "UTF-32-3412",
        .sig = { 0xFE, 0xFF, 0x00, 0x00 },
        .siglen = 4,
        .consume = true,
    },
    {
        .encname = "UTF-16BE",
        .sig = { 0xFE, 0xFF },
        .siglen = 2,
        .consume = true,
    },
    {
        .encname = "UTF-16LE",
        .sig = { 0xFF, 0xFE },
        .siglen = 2,
        .consume = true,
    },
    {
        .encname = "UTF-8",
        .sig = { 0xEF, 0xBB, 0xBF },
        .siglen = 3,
        .consume = true,
    },
    {
        .encname = "UTF-32BE",
        .sig = { 0x00, 0x00, 0x00, 0x3C },
        .siglen = 4,
        .consume = false,
    },
    {
        .encname = "UTF-32LE",
        .sig = { 0x3C, 0x00, 0x00, 0x00 },
        .siglen = 4,
        .consume = false,
    },
    {
        .encname = "UTF-32-2143",
        .sig = { 0x00, 0x00, 0x3C, 0x00 },
        .siglen = 4,
        .consume = false,
    },
    {
        .encname = "UTF-32-3412",
        .sig = { 0x00, 0x3C, 0x00, 0x00 },
        .siglen = 4,
        .consume = false,
    },
    {
        .encname = "UTF-16BE",
        .sig = { 0x00, 0x3C, 0x00, 0x3F },
        .siglen = 4,
        .consume = false,
    },
    {
        .encname = "UTF-16LE",
        .sig = { 0x3C, 0x00, 0x3F, 0x00 },
        .siglen = 4,
        .consume = false,
    },
    {
        .encname = "UTF-8",
        .sig = { 0x3C, 0x3F, 0x78, 0x6D },
        .siglen = 4,
        .consume = false,
    },
    {
        .encname = "EBCDIC",
        .sig = { 0x4C, 0x6F, 0xA7, 0x94 },
        .siglen = 4,
        .consume = false,
    },
};

const char *
encoding_detect_byte_order(strbuf_t *buf)
{
    uint8_t first4[4] = { 0, 0, 0, 0 };
    const bom_encdesc_t *b;
    uint32_t i;

    // Lookahead: if there's no BOM, we must leave the content alone
    strbuf_read(buf, first4, sizeof(first4), true);
    for (i = 0, b = bom_encodings; i < sizeofarray(bom_encodings); i++, b++) {
        if (!memcmp(first4, b->sig, b->siglen)) {
            // Match! Consume the BOM, if any
            if (b->consume) {
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
init_utf8(strbuf_t **pbuf, const void *data)
{
    return NULL;
}

static void
destroy_utf8(strbuf_t **pbuf, void *baton)
{
}

///
static encoding_t enc_utf8 = {
    .name = "UTF-8",
    .codeunit = 1,
    .init = init_utf8,
    .destroy = destroy_utf8,
};

static void __constructor
encodings_autoinit(void)
{
    encoding_register(&enc_utf8);
}
