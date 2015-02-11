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
typedef STAILQ_HEAD(encoding_list_s, encoding_link_s) encoding_list_t;

// FIXME: this is not thread-safe. Protect registration/search with a mutex? Or require
// that registration be done before using anything else in multithreaded context?
static encoding_list_t encodings = STAILQ_HEAD_INITIALIZER(encodings);

/// Opaque structure for encoding handle
struct encoding_handle_s {
    const encoding_t *enc;      /// Encoding being used
    void *baton;                /// Baton (structure with encoding's runtime data)
};

/**
    Search for a registered encoding by name.

    @param name Encoding name
    @return Encoding pointer, or NULL if not found
*/
static const encoding_t *
encoding_search(const char *name)
{
    const encoding_link_t *lnk;

    STAILQ_FOREACH(lnk, &encodings, link) {
        // "XML processors SHOULD match character encoding names in a case-insensitive way"
        if (!strcasecmp(name, lnk->enc->name)) {
            return lnk->enc;
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
encoding__register(encoding_link_t *lnk)
{
    size_t i, j;
    encoding_link_t *lnkx;
    const encoding_t *enc, *encx;
    const encoding_sig_t *sig, *sigx;

    enc = lnk->enc;
    if (encoding_search(enc->name)) {
        OOPS_ASSERT(0); // Already registered
    }

    // Search for same detection signatures if there's a conflict
    for (i = 0, sig = enc->sigs; i < enc->nsigs; i++, sig++) {
        STAILQ_FOREACH(lnkx, &encodings, link) {
            encx = lnkx->enc;
            for (j = 0, sigx = encx->sigs; j < encx->nsigs; j++, sigx++) {
                OOPS_ASSERT(sig->len != sigx->len
                        || memcmp(sig->sig, sigx->sig, sig->len));
            }
        }
    }

    // Meta-encodings (those without transcoding method) cannot have
    // signature strings; real encodings must preset the signatures
    OOPS_ASSERT(enc->in || !enc->sigs);

    // Non-zero size must be accompanied by non-NULL buffer
    OOPS_ASSERT(!enc->nsigs || enc->sigs);

    STAILQ_INSERT_HEAD(&encodings, lnk, link);
}

/**
    Byte order detection, loosely based on XML1.1 App.E ("Autodetection
    of Character Encodings"; non-normative).

    Check for byte order (via either byte order mark presence, or how
    the characters from a known start string are arranged). Assumes
    an XML document (which, aside from a possible byte order mark,
    must start with a "<?xml" string).

    The difference from spec is that failing to determine BOM-based encoding,
    we do not look for full XML declaration. Instead, look for any valid
    character that can start an XML stream: < (which may open XMLDecl,
    Comment, PI, doctypedecl or element); or any allowed whitespace.

    @param buf Buffer to use for autodetection
    @param bufsz Size of the data in @a buf
    @param bom_len If encoding detected successfully, length of the BOM
        is returned here
    @return Encoding name; or NULL if cannot be detected
*/
const char *
encoding_detect(const uint8_t *buf, size_t bufsz, size_t *bom_len)
{
    encoding_link_t *lnk;
    const encoding_t *enc;
    const encoding_sig_t *sig;
    size_t i, chklen;

    // Check longest signatures first
    for (chklen = bufsz; chklen; chklen--) {
        STAILQ_FOREACH(lnk, &encodings, link) {
            enc = lnk->enc;
            for (i = 0, sig = enc->sigs; i < enc->nsigs; i++, sig++) {
                // On the first cycle, check all signatures at least as
                // long as the autodetect buffer
                if ((chklen == sig->len || (chklen == bufsz && sig->len > chklen))
                        && !memcmp(buf, sig->sig, chklen)) {
                    *bom_len = sig->bom ? sig->len : 0;
                    return enc->name;
                }
            }
        }
    }
    *bom_len = 0;
    return NULL;
}

// --- Encoding handle operations ---

/**
    Prepare for transcoding from a particular encoding.

    @param name Name of the input encoding
    @return Transcoder handle, or NULL if the encoding is not found
*/
encoding_handle_t *
encoding_open(const char *name)
{
    const encoding_t *enc;
    encoding_handle_t *hnd;

    if ((enc = encoding_search(name)) == NULL) {
        return NULL;
    }
    hnd = xmalloc(sizeof(encoding_handle_t));
    hnd->enc = enc;
    hnd->baton = NULL;
    if (enc->baton_sz) {
        hnd->baton = xmalloc(enc->baton_sz);
        memset(hnd->baton, 0, enc->baton_sz);
        if (enc->init) {
            enc->init(hnd->baton, enc->data);
        }
    }
    return hnd;
}

/**
    Return a name of the encoding from a handle.

    @param hnd Transcoder handle
    @return Nmae of the encoding
*/
const char *
encoding_name(encoding_handle_t *hnd)
{
    return hnd->enc->name;
}

/**
    Check if the new encoding is compatible with current encoding.
    If it is, close current and replace with new. If it is not, close new
    and keep current.

    @param phnd Pointer to current transcoder handle
    @param hndnew New transcoder handle
    @return true if switched successfully, false if encoding is
        incompatible or current encoding has incomplete data in its
        state or the new encoding is unknown.
*/
bool
encoding_switch(encoding_handle_t **phnd, encoding_handle_t *hndnew)
{
    encoding_handle_t *hnd = *phnd;

    if (hndnew->enc == hnd->enc) {
        // Same encoding, nothing to do - even runtime data remains
        encoding_close(hndnew);
        return true;
    }
    if (hndnew->enc->enctype == ENCODING_T_UNKNOWN
            || hnd->enc->enctype == ENCODING_T_UNKNOWN
            || hndnew->enc->enctype != hnd->enc->enctype) {
        encoding_close(hndnew);
        return false; // Incompatible character order or size
    }
    if (hndnew->enc->endian != ENCODING_E_ANY
            && hnd->enc->endian != ENCODING_E_ANY
            && hndnew->enc->endian != hnd->enc->endian) {
        encoding_close(hndnew);
        return false; // Incompatible endianness
    }
    if (!hndnew->enc->in) {
        // New encoding is a compatible meta-encoding (does not provide
        // the actual transcoding method). Keep the old one, return success.
        encoding_close(hndnew);
        return true;
    }
    if (!encoding_clean(hnd)) {
        // Not a good time: we're in a middle of a character
        encoding_close(hndnew);
        return false;
    }

    // Ok, switch.
    encoding_close(hnd);
    *phnd = hndnew;
    return true;
}

/**
    Free a transcoder handle.

    @param hnd Transcoder handle
    @return Nothing
*/
void
encoding_close(encoding_handle_t *hnd)
{
    if (hnd->enc->destroy) {
        hnd->enc->destroy(hnd->baton);
    }
    xfree(hnd->baton);
    xfree(hnd);
}

/**
    Transcode an input buffer (@a begin, @a end) to output buffer (@a pout,
    @a end_out).

    @param hnd Transcoder handle
    @param begin Pointer to the start of the input buffer
    @param end Pointer to the end of the input buffer
    @param pout Start of the output buffer (updated to point to next unused dword)
    @param end_out Pointer to the end of the output buffer
    @return Number of bytes consumed from the input buffer
*/
size_t
encoding_in(encoding_handle_t *hnd, const uint8_t *begin, const uint8_t *end,
        uint32_t **pout, uint32_t *end_out)
{
    return hnd->enc->in(hnd->baton, begin, end, pout, end_out);
}

/**
    Transcode from a string buffer, until either end of string buffer or
    exhaustion of the output buffer space.

    @param hnd Transcoder handle
    @param buf Input string buffer
    @param pout Start of the output buffer (updated to point to next unused dword)
    @param end_out Pointer to the end of the output buffer
    @return Number of bytes consumed from the input buffer
*/
size_t
encoding_in_from_strbuf(encoding_handle_t *hnd, strbuf_t *buf,
        uint32_t **pout, uint32_t *end_out)
{
    size_t len, total;
    const void *begin, *end;

    total = 0;
    do {
        if (!strbuf_getptr(buf, &begin, &end)) {
            break; // No more input
        }
        len = encoding_in(hnd, begin, end, pout, end_out);
        OOPS_ASSERT(len); // There's input data and output space
        total += len;
        strbuf_read(buf, NULL, len, false);
    } while (*pout < end_out);

    return total;
}

/**
    Check if the encoding handle is in "clean" state - not in the middle
    of a multibyte character.

    @param hnd Transcoder handle
    @return true if the handle is clean, false otherwise
*/
bool
encoding_clean(encoding_handle_t *hnd)
{
    return hnd->enc->in_clean ? hnd->enc->in_clean(hnd->baton) : true;
}



/*
    Below, basic 1-, 2- and 4-byte encodings.
*/

// --- Common functions for codepage-based encodings

/**
    Constructor for codepage encoding.

    @param baton Runtime data pointer
    @param data Pointer to mapping table
    @return Nothing
*/
void
encoding_codepage_init(void *baton, const void *data)
{
    encoding_codepage_baton_t *cpb = baton;

    cpb->map = data;
}

/**
    Translation function for codepage encoding. Advance byte by byte and
    use the mapping table to obtain UCS-4 codepoints.

    @param baton Pointer to structure with mapping table
    @param begin Pointer to the start of the input buffer
    @param end Pointer to the end of the input buffer
    @param pout Start of the output buffer (updated to point to next unused dword)
    @param end_out Pointer to the end of the output buffer
    @return Number of bytes consumed from the input buffer
*/
size_t
encoding_codepage_in(void *baton, const uint8_t *begin, const uint8_t *end,
        uint32_t **pout, uint32_t *end_out)
{
    encoding_codepage_baton_t *cpb = baton;
    uint32_t *out = *pout;
    const uint8_t *ptr = begin;

    while (ptr < end && out < end_out) {
        *out++ = cpb->map[*ptr++];
    }
    *pout = out;
    return ptr - begin;
}


// --- UTF-8 encoding ---

/// Runtime data for UTF-8 encoding
typedef struct baton_utf8_s {
    uint32_t val;           ///< Accumulated value
    size_t len;             ///< Number of trailing characters expected
    uint8_t mintrail;       ///< Minimum expected trailer byte
    uint8_t maxtrail;       ///< Maximum expected trailer byte
} baton_utf8_t;

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
    0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 0xC0 - 2-byte chars
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 0xD0 - 2-byte chars
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 0xE0 - 3-byte chars
    4, 4, 4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xF0 - 4-byte chars up to 0x10FFFF
};

/**
    Minimal next trailing byte (see Unicode table 3-7, Well-Formed
    UTF-8 Byte Sequences). These values stem from the requirement that
    the shortest UTF-8 sequence is used to represent a code point.
*/
static const uint8_t utf8_mintrail[256] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0xA0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x90, 0x80, 0x80, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/**
    Maximal next trailing byte (see Unicode table 3-7, Well-Formed
    UTF-8 Byte Sequences). These values stem from the requirement that
    the shortest UTF-8 sequence is used to represent a code point.
*/
static const uint8_t utf8_maxtrail[256] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF,
    0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF,
    0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0x9F, 0xBF, 0xBF,
    0xBF, 0xBF, 0xBF, 0xBF, 0x8F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/**
    Perform translation of UTF-8 encoding to UCS-4 code points.

    @param baton Pointer to structure with mapping table
    @param begin Pointer to the start of the input buffer
    @param end Pointer to the end of the input buffer
    @param pout Start of the output buffer (updated to point to next unused dword)
    @param end_out Pointer to the end of the output buffer
    @return Number of bytes consumed from the input buffer
*/
static size_t
in_UTF8(void *baton, const uint8_t *begin, const uint8_t *end,
        uint32_t **pout, uint32_t *end_out)
{
    baton_utf8_t utf8b; // Local copy to avoid accessing via pointer
    uint32_t *out = *pout;
    const uint8_t *ptr = begin;
    uint8_t tmp;

    // TBD add encoding tests.

    // Unicode sections 3.9 and 5.22 describe best practices when substituting
    // with Unicode replacement character, U+FFFD. In brief, advance read pointer
    // to the first byte where the byte sequence becomes invalid, but at least
    // advance by one byte. I.e. C0 AF -> FFFD FFFD, but F4 80 80 41 -> FFFD 0041.
    memcpy(&utf8b, baton, sizeof(baton_utf8_t));
    while (ptr < end && out < end_out) {
        if (!utf8b.len) {
            // New character
            utf8b.val = *ptr++; // .. always advanced ("at least by 1 byte")
            if ((utf8b.len = utf8_len[utf8b.val]) == 0) {
                // Invalid starter byte
                *out++ = UNICODE_REPLACEMENT_CHARACTER;
                continue;
            }
            else if (utf8b.len > 1) {
                // Multibyte, mask out length encoding
                utf8b.mintrail = utf8_mintrail[utf8b.val];
                utf8b.maxtrail = utf8_maxtrail[utf8b.val];
                utf8b.val &= 0x7F >> utf8b.len;
            }
            utf8b.len--;  // One byte has been read
        }
        else {
            tmp = *ptr; // Do not advance yet
            if (tmp < utf8b.mintrail || tmp > utf8b.maxtrail) {
                // Invalid trailer byte; restart decoding at current ptr
                *out++ = UNICODE_REPLACEMENT_CHARACTER;
                continue;
            }
            // Got next 6 bits. After the first trailer, full range (80..BF) is allowed
            utf8b.val <<= 6;
            utf8b.val |= (tmp & 0x3F);
            utf8b.mintrail = 0x80;
            utf8b.maxtrail = 0xBF;
            utf8b.len--;
            ptr++;
        }
        if (!utf8b.len) {
            // Have a complete UCS-4 character
            *out++ = utf8b.val;
        }
    }
    memcpy(baton, &utf8b, sizeof(baton_utf8_t));
    *pout = out;
    return ptr - begin;
}

/**
    Check if UTF-8 transcoder is not in a middle of a byte sequence.

    @param baton Runtime data structure
    @return true if the state is clean (not in a middle of a sequence)
*/
static bool
clean_utf8(void *baton)
{
    baton_utf8_t *utf8b = baton;

    return !utf8b->len;
}

static const encoding_sig_t sig_UTF8[] = {
    ENCODING_SIG(true,  0xEF, 0xBB, 0xBF), // BOM
    ENCODING_SIG(false, 0x3C), // <
    ENCODING_SIG(false, 0x09), // Tab
    ENCODING_SIG(false, 0x0A), // LF
    ENCODING_SIG(false, 0x0D), // CR
    ENCODING_SIG(false, 0x20), // Space
};

static const encoding_t enc_UTF8 = {
    .name = "UTF-8",
    .enctype = ENCODING_T_UTF8,
    .baton_sz = sizeof(baton_utf8_t),
    .sigs = sig_UTF8,
    .nsigs = sizeofarray(sig_UTF8),
    .in = in_UTF8,
    .in_clean = clean_utf8,
};
ENCODING_REGISTER(enc_UTF8);

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

// --- UTF-16 encodings ---

/// Runtime data for UTF-8 encoding
typedef struct baton_utf16_s {
    uint32_t val;           ///< Accumulated value
    uint32_t surrogate;     ///< Surrogate value previously read
    uint8_t tmp[2];         ///< Temporary buffer if a unit straddles block boundary
    bool straddle;          ///< Previous block didn't end on unit boundary
    bool val_valid;         ///< On previous call, .val did not fit into a buffer
} baton_utf16_t;

/**
    Check if current UTF-16 transcoder state is not in a middle of a word, not between
    surrogates and does not have a cached value (that was held back due to invalid
    surrogate in the previous call).

    @param baton UTF-16 runtime data
    @return true if transcoder is in clean state.
*/
static bool
clean_utf16(void *baton)
{
    baton_utf16_t *utf16b = baton;

    return !utf16b->straddle && !utf16b->surrogate && !utf16b->val_valid;
}

#define FUNC in_UTF16LE
#define TOHOST le16tohost
#include "encoding-utf16.c"

static const encoding_sig_t sig_UTF16LE[] = {
    ENCODING_SIG(true,  0xFF, 0xFE), // BOM
    ENCODING_SIG(false, 0x3C, 0x00), // <
    ENCODING_SIG(false, 0x09, 0x00), // Tab
    ENCODING_SIG(false, 0x0A, 0x00), // LF
    ENCODING_SIG(false, 0x0D, 0x00), // CR
    ENCODING_SIG(false, 0x20, 0x00), // Space
};

static const encoding_t enc_UTF16LE = {
    .name = "UTF-16LE",
    .enctype = ENCODING_T_UTF16,
    .endian = ENCODING_E_LE,
    .baton_sz = sizeof(baton_utf16_t),
    .sigs = sig_UTF16LE,
    .nsigs = sizeofarray(sig_UTF16LE),
    .in = in_UTF16LE,
    .in_clean = clean_utf16,
};
ENCODING_REGISTER(enc_UTF16LE);


#define FUNC in_UTF16BE
#define TOHOST be16tohost
#include "encoding-utf16.c"

static const encoding_sig_t sig_UTF16BE[] = {
    ENCODING_SIG(true,  0xFE, 0xFF), // BOM
    ENCODING_SIG(false, 0x00, 0x3C), // <
    ENCODING_SIG(false, 0x00, 0x09), // Tab
    ENCODING_SIG(false, 0x00, 0x0A), // LF
    ENCODING_SIG(false, 0x00, 0x0D), // CR
    ENCODING_SIG(false, 0x00, 0x20), // Space
};

static const encoding_t enc_UTF16BE = {
    .name = "UTF-16BE",
    .enctype = ENCODING_T_UTF16,
    .endian = ENCODING_E_BE,
    .baton_sz = sizeof(baton_utf16_t),
    .sigs = sig_UTF16BE,
    .nsigs = sizeofarray(sig_UTF16BE),
    .in = in_UTF16BE,
    .in_clean = clean_utf16,
};
ENCODING_REGISTER(enc_UTF16BE);

/// Meta-encoding: UTF-16 with any endianness, as detected
static const encoding_t enc_UTF16 = {
    .name = "UTF-16",
    .enctype = ENCODING_T_UTF16,
    .endian = ENCODING_E_ANY,
};
ENCODING_REGISTER(enc_UTF16);

static size_t
utf32_in(void *baton, const uint8_t *begin, const uint8_t *end,
        uint32_t **pout, uint32_t *end_out)
{
    // TBD: UTF-32 encodings not implemented yet
    OOPS_ASSERT(0);
    return 0;
}
static const encoding_sig_t sig_UTF32LE[] = {
    ENCODING_SIG(true,  0xFF, 0xFE, 0x00, 0x00), // BOM
    ENCODING_SIG(false, 0x3C, 0x00, 0x00, 0x00), // <
    ENCODING_SIG(false, 0x09, 0x00, 0x00, 0x00), // Tab
    ENCODING_SIG(false, 0x0A, 0x00, 0x00, 0x00), // LF
    ENCODING_SIG(false, 0x0D, 0x00, 0x00, 0x00), // CR
    ENCODING_SIG(false, 0x20, 0x00, 0x00, 0x00), // Space
};
static const encoding_t enc_UTF32LE = {
    .name = "UTF-32LE",
    .enctype = ENCODING_T_UTF32,
    .endian = ENCODING_E_LE,
    .sigs = sig_UTF32LE,
    .nsigs = sizeofarray(sig_UTF32LE),
    .in = utf32_in,
};
ENCODING_REGISTER(enc_UTF32LE);

static const encoding_sig_t sig_UTF32BE[] = {
    ENCODING_SIG(true,  0x00, 0x00, 0xFE, 0xFF), // BOM
    ENCODING_SIG(false, 0x00, 0x00, 0x00, 0x3C), // <
    ENCODING_SIG(false, 0x00, 0x00, 0x00, 0x09), // Tab
    ENCODING_SIG(false, 0x00, 0x00, 0x00, 0x0A), // LF
    ENCODING_SIG(false, 0x00, 0x00, 0x00, 0x0D), // CR
    ENCODING_SIG(false, 0x00, 0x00, 0x00, 0x20), // Space
};
static const encoding_t enc_UTF32BE = {
    .name = "UTF-32BE",
    .enctype = ENCODING_T_UTF32,
    .endian = ENCODING_E_BE,
    .sigs = sig_UTF32BE,
    .nsigs = sizeofarray(sig_UTF32BE),
    .in = utf32_in,
};
ENCODING_REGISTER(enc_UTF32BE);

static const encoding_sig_t sig_UTF32_2143[] = {
    ENCODING_SIG(true,  0x00, 0x00, 0xFF, 0xFE), // BOM
    ENCODING_SIG(false, 0x00, 0x00, 0x3C, 0x00), // <
    ENCODING_SIG(false, 0x00, 0x00, 0x09, 0x00), // Tab
    ENCODING_SIG(false, 0x00, 0x00, 0x0A, 0x00), // LF
    ENCODING_SIG(false, 0x00, 0x00, 0x0D, 0x00), // CR
    ENCODING_SIG(false, 0x00, 0x00, 0x20, 0x00), // Space
};
static const encoding_t enc_UTF32_2143 = {
    .name = "UTF-32-2143",
    .enctype = ENCODING_T_UTF32,
    .endian = ENCODING_E_2143,
    .sigs = sig_UTF32_2143,
    .nsigs = sizeofarray(sig_UTF32_2143),
    .in = utf32_in,
};
ENCODING_REGISTER(enc_UTF32_2143);

static const encoding_sig_t sig_UTF32_3412[] = {
    ENCODING_SIG(true,  0xFE, 0xFF, 0x00, 0x00), // BOM
    ENCODING_SIG(false, 0x00, 0x3C, 0x00, 0x00), // <
    ENCODING_SIG(false, 0x00, 0x09, 0x00, 0x00), // Tab
    ENCODING_SIG(false, 0x00, 0x0A, 0x00, 0x00), // LF
    ENCODING_SIG(false, 0x00, 0x0D, 0x00, 0x00), // CR
    ENCODING_SIG(false, 0x00, 0x20, 0x00, 0x00), // Space
};
static const encoding_t enc_UTF32_3412 = {
    .name = "UTF-32-3412",
    .enctype = ENCODING_T_UTF32,
    .endian = ENCODING_E_3412,
    .sigs = sig_UTF32_3412,
    .nsigs = sizeofarray(sig_UTF32_3412),
    .in = utf32_in,
};
ENCODING_REGISTER(enc_UTF32_3412);

static const encoding_t enc_UTF32 = {
    .name = "UTF-32",
    .enctype = ENCODING_T_UTF32,
    .endian = ENCODING_E_ANY,
};
ENCODING_REGISTER(enc_UTF32);
