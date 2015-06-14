/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Transcoder implementation.
*/
#include <string.h>

#include "util/defs.h"
#include "util/xutil.h"
#include "util/strbuf.h"

#include "unicode/unicode.h"
#include "unicode/encoding.h"

/// Head of encoding list
typedef STAILQ_HEAD(encoding_list_s, encoding_link_s) encoding_list_t;

/**
    List of all encodings.
    @todo This is not thread-safe. Protect registration/search with a mutex? Or require
    that registration be done before using anything else in multithreaded context?
*/
static encoding_list_t encodings = STAILQ_HEAD_INITIALIZER(encodings);

/// Opaque structure for encoding handle
struct encoding_handle_s {
    const encoding_t *enc;      ///< Encoding being used
    void *baton;                ///< Baton (structure with encoding's runtime data)
};

/**
    Search for a registered encoding by name.

    @param name Encoding name
    @param endian Desired endianness, or ENCODING_E_ANY if not known or not applicable
        (UTR#17 prescribes to use big-endian in this case if applicable)
    @return Encoding pointer, or NULL if not found
*/
const encoding_t *
encoding_search(const char *name, enum encoding_endian_e endian)
{
    const encoding_link_t *lnk;
    const encoding_t *best = NULL;

    STAILQ_FOREACH(lnk, &encodings, link) {
        // "XML processors SHOULD match character encoding names in a case-insensitive way"
        if (strcasecmp(name, lnk->enc->name)) {
            continue;
        }
        if (endian == lnk->enc->endian) { // Exact match in endianness
            return lnk->enc;
        }
        if (endian != ENCODING_E_ANY) { // Requested specific endianness
            continue;
        }
        if (lnk->enc->endian == ENCODING_E_BE) { // Best default if no specific endianness requested
            return lnk->enc;
        }
        best = lnk->enc; // If we don't find anything better
    }
    return best;
}

/**
    Register an encoding.

    @param lnk Link structure with encoding being registered
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
    if (encoding_search(enc->name, enc->endian)) {
        OOPS; // Already registered
    }

    // No purpose in encoding that cannot transcode
    OOPS_ASSERT(enc->in);

    // Non-zero size must be accompanied by non-NULL buffer
    OOPS_ASSERT(!enc->nsigs || enc->sigs);

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

    STAILQ_INSERT_HEAD(&encodings, lnk, link);
}

/**
    Character encoding form detection, loosely based on XML1.1 App.E
    ("Autodetection of Character Encodings"; non-normative).

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
    @return Encoding detected; or NULL if cannot be detected
*/
const encoding_t *
encoding_detect(const uint8_t *buf, size_t bufsz, size_t *bom_len)
{
    encoding_link_t *lnk;
    const encoding_t *enc, *best;
    const encoding_sig_t *sig;
    size_t i, chklen;

    // Check longest signatures first
    for (chklen = bufsz; chklen; chklen--) {
        best = NULL;
        STAILQ_FOREACH(lnk, &encodings, link) {
            enc = lnk->enc;
            for (i = 0, sig = enc->sigs; i < enc->nsigs; i++, sig++) {
                // Check for exact match first
                if (chklen == sig->len && !memcmp(buf, sig->sig, chklen)) {
                    *bom_len = sig->bom ? sig->len : 0;
                    return enc;
                }
                // On the first cycle, also check all signatures at least as
                // long as the autodetect buffer. Pick the first.
                if (!best && chklen == bufsz && sig->len > chklen
                        && !memcmp(buf, sig->sig, chklen)) {
                    // If we find exact match, we'll overwrite bom_len. Otherwise,
                    // we'll return best.
                    *bom_len = sig->bom ? sig->len : 0;
                    best = enc;
                }
            }
        }
        if (best) {
            return best; // Longest available string was only a part of a signature
        }
    }
    *bom_len = 0;
    return NULL;
}

// --- Encoding handle operations ---

/**
    Prepare for transcoding from a particular encoding.

    @param enc Input encoding
    @return Transcoder handle, or NULL if the encoding is not found
*/
encoding_handle_t *
encoding_open(const encoding_t *enc)
{
    encoding_handle_t *hnd;

    hnd = xmalloc(sizeof(encoding_handle_t));
    hnd->enc = enc;
    hnd->baton = NULL;
    hnd->baton = xmalloc(enc->baton_sz);
    memset(hnd->baton, 0, enc->baton_sz);
    if (enc->init) {
        enc->init(hnd->baton, enc->data);
    }
    return hnd;
}

/**
    Re-open (clear) the encoding handle. Purges any partially read characters.

    @param hnd Transcoder handle
*/
void
encoding_reopen(encoding_handle_t *hnd)
{
    if (hnd->enc->destroy) {
        hnd->enc->destroy(hnd->baton);
    }
    memset(hnd->baton, 0, hnd->enc->baton_sz);
    if (hnd->enc->init) {
        hnd->enc->init(hnd->baton, hnd->enc->data);
    }
}

/**
    Return an encoding from a handle.

    @param hnd Transcoder handle
    @return Encoding information
*/
const encoding_t *
encoding_get(encoding_handle_t *hnd)
{
    return hnd->enc;
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
    if (hndnew->enc->form == ENCODING_FORM_UNKNOWN
            || hnd->enc->form == ENCODING_FORM_UNKNOWN
            || hndnew->enc->form != hnd->enc->form) {
        encoding_close(hndnew);
        return false; // Incompatible character encoding form
    }
    if (hndnew->enc->endian != ENCODING_E_ANY
            && hnd->enc->endian != ENCODING_E_ANY
            && hndnew->enc->endian != hnd->enc->endian) {
        encoding_close(hndnew);
        return false; // Incompatible endianness
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
        ucs4_t **pout, ucs4_t *end_out)
{
    ucs4_t *out = *pout;
    size_t len;

    // TBD instead of inserting U+FFFD on error, provide a callback notification
    len = hnd->enc->in(hnd->baton, begin, end, pout, end_out);

    /*
        Make sure we advance in some way: encoding may consume some input
        (either to produce output, or store it in internal state) and/or
        produce some output (from input, or from stored internal state) -
        if we had some input and output space to begin with, of course.
    */
    OOPS_ASSERT(len || out != *pout || begin == end || out == end_out);
    return len;
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
        ucs4_t **pout, ucs4_t *end_out)
{
    size_t len, total;
    const void *begin, *end;

    total = 0;
    do {
        if (!strbuf_rptr(buf, &begin, &end)) {
            break; // No more input
        }
        len = encoding_in(hnd, begin, end, pout, end_out);

        total += len;
        strbuf_radvance(buf, len);
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
        ucs4_t **pout, ucs4_t *end_out)
{
    encoding_codepage_baton_t *cpb = baton;
    ucs4_t *out = *pout;
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
    ucs4_t val;             ///< Accumulated value
    size_t len;             ///< Number of trailing characters expected
    utf8_t mintrail;        ///< Minimum expected trailer byte
    utf8_t maxtrail;        ///< Maximum expected trailer byte
} baton_utf8_t;

/// Length of the multibyte sequence (0: invalid starting char)
static const uint8_t utf8_seqlen[256] = {
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

    @param baton Pointer to structure with UTF-8 runtime data
    @param begin Pointer to the start of the input buffer
    @param end Pointer to the end of the input buffer
    @param pout Start of the output buffer (updated to point to next unused dword)
    @param end_out Pointer to the end of the output buffer
    @return Number of bytes consumed from the input buffer
*/
static size_t
in_UTF8(void *baton, const uint8_t *begin, const uint8_t *end,
        ucs4_t **pout, ucs4_t *end_out)
{
    baton_utf8_t utf8b; // Local copy to avoid accessing via pointer
    ucs4_t *out = *pout;
    const uint8_t *ptr = begin;
    uint8_t tmp;

    // Unicode sections 3.9 and 5.22 describe best practices when substituting
    // with Unicode replacement character, U+FFFD. In brief, advance read pointer
    // to the first byte where the byte sequence becomes invalid, but at least
    // advance by one byte. I.e. C0 AF -> FFFD FFFD, but F4 80 80 41 -> FFFD 0041.
    memcpy(&utf8b, baton, sizeof(baton_utf8_t));
    while (ptr < end && out < end_out) {
        if (!utf8b.len) {
            // New character
            utf8b.val = *ptr++; // .. always advanced ("at least by 1 byte")
            if ((utf8b.len = utf8_seqlen[utf8b.val]) == 0) {
                // Invalid starter byte
                *out++ = UCS4_REPLACEMENT_CHARACTER;
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
                *out++ = UCS4_REPLACEMENT_CHARACTER;
                utf8b.len = 0;
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
    .form = ENCODING_FORM_UTF8,
    .baton_sz = sizeof(baton_utf8_t),
    .sigs = sig_UTF8,
    .nsigs = sizeofarray(sig_UTF8),
    .in = in_UTF8,
    .in_clean = clean_utf8,
};
ENCODING_REGISTER(enc_UTF8);

// --- UTF-16 encodings ---

/// Runtime data for UTF-16 encoding
typedef struct baton_utf16_s {
    ucs4_t val;             ///< Accumulated value
    ucs4_t surrogate;       ///< Surrogate value previously read
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
clean_UTF16(void *baton)
{
    baton_utf16_t *utf16b = baton;

    return !utf16b->straddle && !utf16b->surrogate && !utf16b->val_valid;
}

/**
    Helper function: store next 16-bit value in UTF16 state and/or output.

    @param b UTF-16 runtime data
    @param val Next 16-bit value from the input
    @param pout Start of writable space in output buffer
    @param end End of the output buffer
    @return Nothing
*/
static inline void
nextchar_UTF16(baton_utf16_t *b, uint16_t val, ucs4_t **pout, ucs4_t *end)
{
    uint16_t surrogate_bits = val & 0xFC00;

    if (b->surrogate) {
        /* Expecting low surrogate */
        if (surrogate_bits == 0xDC00) {
            /* Found low surrogate; store combined value */
            /* 0x360DC00 is ((0xD800 << 10) | 0xDC00) */
            *(*pout)++ = 0x010000 + ((b->surrogate << 10) ^ val ^ 0x360DC00);
            b->surrogate = 0;
            return;
        }
        else {
            /* Invalid value: store replacement, will need to re-parse value normally */
            *(*pout)++ = UCS4_REPLACEMENT_CHARACTER;
            b->surrogate = 0;
            if (*pout == end) {
                /* No more space; will reparse b->val in the next call */
                b->val_valid = true;
                b->val = val;
                return;
            }
        }
    }
    if (surrogate_bits == 0xD800) {
        /* high surrogate - store and expect low surrogate as next unit */
        b->surrogate = val;
    }
    else if (surrogate_bits == 0xDC00) {
        *(*pout)++ = UCS4_REPLACEMENT_CHARACTER;
    }
    else {
        *(*pout)++ = val;
    }
}

/**
    Helper for two flavors of UTF-16 implementation.

    @param baton Pointer to structure with UTF-16 runtime data.
    @param begin Pointer to the start of the input buffer
    @param end Pointer to the end of the input buffer
    @param pout Start of the output buffer (updated to point to next unused dword)
    @param end_out Pointer to the end of the output buffer
    @param tohost Function to convert byte sequence to 16-bit unit.
    @return Number of bytes consumed from the input buffer
*/
static inline size_t
common_UTF16(void *baton, const uint8_t *begin, const uint8_t *end,
        ucs4_t **pout, ucs4_t *end_out, uint16_t (*tohost)(const uint8_t *))
{
    baton_utf16_t utf16b; // Local copy to avoid access via pointer
    const uint8_t *ptr = begin;

    memcpy(&utf16b, baton, sizeof(baton_utf16_t));

    // Re-parse value that did not fit on last call (in case of invalid surrogate pair,
    // e.g. <D800 0400>, we need to store 2 codepoints: U+FFFD U+0400. If the output buffer
    // only had space for one, the other is kept in utf16b.val, and utf16b.surrogate is
    // cleared, so this invocation of NEXTCHAR_UTF16 stores at most one codepoint.
    if (utf16b.val_valid && *pout < end_out) {
        utf16b.val_valid = false;
        nextchar_UTF16(&utf16b, utf16b.val, pout, end_out);
    }
    // Finish incomplete unit from previous block, if needed
    if (utf16b.straddle && ptr < end && *pout < end_out) {
        utf16b.straddle = false;
        utf16b.tmp[1] = *ptr++;
        nextchar_UTF16(&utf16b, tohost(utf16b.tmp), pout, end_out);
    }
    // Reads 2 characters at a time - thus 'end - 1'
    while (ptr < end - 1 && *pout < end_out) {
        nextchar_UTF16(&utf16b, tohost(ptr), pout, end_out);
        ptr += 2;
    }
    // If stopped one byte short of end and have space - store it for the next call
    // (we may come here if we already have stored byte and we were not able to store
    // the next output character; in that case, do not store anything)
    if (ptr == end - 1 && !utf16b.straddle) {
        utf16b.tmp[0] = *ptr++;
        utf16b.straddle = true;
    }
    memcpy(baton, &utf16b, sizeof(baton_utf16_t));
    return ptr - begin;
}

/**
    Translate next two bytes to 16-bit value; little-endian way.

    @param p Input byte stream
    @return 16-bit value
*/
static inline uint16_t
le16tohost(const uint8_t *p)
{
    return ((uint16_t)0) | (p[1] << 8) | p[0];
}

/// Wrapper for little-endian version of UTF-16
static size_t
in_UTF16LE(void *baton, const uint8_t *begin, const uint8_t *end,
        ucs4_t **pout, ucs4_t *end_out)
{
    return common_UTF16(baton, begin, end, pout, end_out, le16tohost);
}

/*
    From Unicode Technical Report #17 (UTR#17):

    5 Character Encoding Scheme (CES)

    ...
    1. A simple CES uses a mapping of each code unit of a CEF into a unique
    serialized byte sequence in order.
    2. A compound CES uses two or more simple CESs, plus a mechanism to shift
    between them.
    ...
    * UTF-8, UTF-16BE, UTF-16LE, UTF-32BE and UTF32-LE are simple CESs.
    * UTF-16 and UTF-32 are compound CESs, consisting of an single, optional
    byte order mark at the start of the data followed by a simple CES.

    It follows that if we see a byte-order mark (BOM), the encoding scheme
    is to be reported as UTF-16, not UTF-16BE or UTF-16LE. Otherwise,
    these encodings are the same.
*/

static const encoding_sig_t sig_UTF16LE[] = {
    ENCODING_SIG(false, 0x3C, 0x00), // <
    ENCODING_SIG(false, 0x09, 0x00), // Tab
    ENCODING_SIG(false, 0x0A, 0x00), // LF
    ENCODING_SIG(false, 0x0D, 0x00), // CR
    ENCODING_SIG(false, 0x20, 0x00), // Space
};

static const encoding_t enc_UTF16LE = {
    .name = "UTF-16LE",
    .form = ENCODING_FORM_UTF16,
    .endian = ENCODING_E_LE,
    .baton_sz = sizeof(baton_utf16_t),
    .sigs = sig_UTF16LE,
    .nsigs = sizeofarray(sig_UTF16LE),
    .in = in_UTF16LE,
    .in_clean = clean_UTF16,
};
ENCODING_REGISTER(enc_UTF16LE);

static const encoding_sig_t sig_UTF16__LE[] = {
    ENCODING_SIG(true,  0xFF, 0xFE), // BOM
};
static const encoding_t enc_UTF16__LE = {
    .name = "UTF-16", // UTF-16 in little-endian order
    .form = ENCODING_FORM_UTF16,
    .endian = ENCODING_E_LE,
    .baton_sz = sizeof(baton_utf16_t),
    .sigs = sig_UTF16__LE,
    .nsigs = sizeofarray(sig_UTF16__LE),
    .in = in_UTF16LE,
    .in_clean = clean_UTF16,
};
ENCODING_REGISTER(enc_UTF16__LE);


/**
    Translate next two bytes to 16-bit value; big-endian way.

    @param p Input byte stream
    @return 16-bit value
*/
static inline uint16_t
be16tohost(const uint8_t *p)
{
    return ((uint16_t)0) | (p[0] << 8) | p[1];
}

/// Wrapper for big-endian version of UTF-16
static size_t
in_UTF16BE(void *baton, const uint8_t *begin, const uint8_t *end,
        ucs4_t **pout, ucs4_t *end_out)
{
    return common_UTF16(baton, begin, end, pout, end_out, be16tohost);
}

// See above for the difference between UTF-16 and UTF-16BE

static const encoding_sig_t sig_UTF16BE[] = {
    ENCODING_SIG(false, 0x00, 0x3C), // <
    ENCODING_SIG(false, 0x00, 0x09), // Tab
    ENCODING_SIG(false, 0x00, 0x0A), // LF
    ENCODING_SIG(false, 0x00, 0x0D), // CR
    ENCODING_SIG(false, 0x00, 0x20), // Space
};

static const encoding_t enc_UTF16BE = {
    .name = "UTF-16BE",
    .form = ENCODING_FORM_UTF16,
    .endian = ENCODING_E_BE,
    .baton_sz = sizeof(baton_utf16_t),
    .sigs = sig_UTF16BE,
    .nsigs = sizeofarray(sig_UTF16BE),
    .in = in_UTF16BE,
    .in_clean = clean_UTF16,
};
ENCODING_REGISTER(enc_UTF16BE);

static const encoding_sig_t sig_UTF16__BE[] = {
    ENCODING_SIG(true,  0xFE, 0xFF), // BOM
};
static const encoding_t enc_UTF16__BE = {
    .name = "UTF-16", // UTF-16 in big-endian order
    .form = ENCODING_FORM_UTF16,
    .endian = ENCODING_E_BE,
    .baton_sz = sizeof(baton_utf16_t),
    .sigs = sig_UTF16__BE,
    .nsigs = sizeofarray(sig_UTF16__BE),
    .in = in_UTF16BE,
    .in_clean = clean_UTF16,
};
ENCODING_REGISTER(enc_UTF16__BE);



/// Runtime data for UTF-32 encoding
typedef struct baton_utf32_s {
    uint8_t tmp[4];         ///< Temporary buffer if a unit straddles block boundary
    size_t nbytes;          ///< How many more bytes are stored in temporary buffer
} baton_utf32_t;

/**
    Check if we're in a middle of 4-byte sequence

    @param baton UTF-32 runtime data
    @return false if the transcoder has a partial unit read, true otherwise
*/
static bool
clean_UTF32(void *baton)
{
    baton_utf32_t *utf32b = baton;

    return !utf32b->nbytes;
}

/**
    Check code point for validity and translate to replacement character otherwise.

    @param cp Code point to check
    @return @a cp if valid, or Unicode replacement character otherwise
*/
static inline ucs4_t
valid_UTF32(ucs4_t cp)
{
    if (cp < UCS4_SURROGATE_MIN) {
        return cp;
    }
    else if (cp > UCS4_SURROGATE_MAX && cp <= UCS4_MAX) {
        return cp;
    }
    else {
        return UCS4_REPLACEMENT_CHARACTER;
    }
}

/**
    Helper for 4 flavors of UTF-32 implementation.

    @param baton Pointer to structure with mapping table
    @param begin Pointer to the start of the input buffer
    @param end Pointer to the end of the input buffer
    @param pout Start of the output buffer (updated to point to next unused dword)
    @param end_out Pointer to the end of the output buffer
    @param tohost Function to convert byte sequence to 32-bit unit.
    @return Number of bytes consumed from the input buffer
*/
static size_t
common_UTF32(void *baton, const uint8_t *begin, const uint8_t *end,
        ucs4_t **pout, ucs4_t *end_out, ucs4_t (*tohost)(const uint8_t *))
{
    baton_utf32_t *utf32b = baton;
    const uint8_t *ptr = begin;
    ucs4_t *out = *pout;
    size_t remains;

    // Finish incomplete unit if possible
    while (utf32b->nbytes && ptr < end && out < end_out) {
        utf32b->tmp[utf32b->nbytes++] = *ptr++;
        if (utf32b->nbytes == 4) {
            *out++ = valid_UTF32(tohost(utf32b->tmp));
            utf32b->nbytes = 0;
        }
    }

    // Translate as many complete units as possible
    while (ptr < end - 3 && out < end_out) {
        *out++ = valid_UTF32(tohost(ptr));
        ptr += 4;
    }

    // Store partial remaining unit in temporary buffer
    remains = end - ptr;
    if (remains && remains < 4 - utf32b->nbytes) {
        while (ptr < end) {
            utf32b->tmp[utf32b->nbytes++] = *ptr++;
        }
    }

    *pout = out;
    return ptr - begin;
}

/**
    Translate next 4 bytes to 32-bit value; little-endian way.

    @param p Input byte stream
    @return 32-bit value
*/
static inline uint32_t
le32tohost(const uint8_t *p)
{
    return ((uint32_t)0) | (p[3] << 24) | (p[2] << 16) | (p[1] << 8) | p[0];
}

/// Wrapper for little-endian version of UTF-32
static size_t
in_UTF32LE(void *baton, const uint8_t *begin, const uint8_t *end,
        ucs4_t **pout, ucs4_t *end_out)
{
    return common_UTF32(baton, begin, end, pout, end_out, le32tohost);
}

// See above for difference in UTF-32 and UTF-32LE

static const encoding_sig_t sig_UTF32LE[] = {
    ENCODING_SIG(false, 0x3C, 0x00, 0x00, 0x00), // <
    ENCODING_SIG(false, 0x09, 0x00, 0x00, 0x00), // Tab
    ENCODING_SIG(false, 0x0A, 0x00, 0x00, 0x00), // LF
    ENCODING_SIG(false, 0x0D, 0x00, 0x00, 0x00), // CR
    ENCODING_SIG(false, 0x20, 0x00, 0x00, 0x00), // Space
};
static const encoding_t enc_UTF32LE = {
    .name = "UTF-32LE",
    .form = ENCODING_FORM_UTF32,
    .endian = ENCODING_E_LE,
    .baton_sz = sizeof(baton_utf32_t),
    .sigs = sig_UTF32LE,
    .nsigs = sizeofarray(sig_UTF32LE),
    .in = in_UTF32LE,
    .in_clean = clean_UTF32,
};
ENCODING_REGISTER(enc_UTF32LE);

static const encoding_sig_t sig_UTF32__LE[] = {
    ENCODING_SIG(true,  0xFF, 0xFE, 0x00, 0x00), // BOM
};
static const encoding_t enc_UTF32__LE = {
    .name = "UTF-32", // UTF-32 in little-endian order
    .form = ENCODING_FORM_UTF32,
    .endian = ENCODING_E_LE,
    .baton_sz = sizeof(baton_utf32_t),
    .sigs = sig_UTF32__LE,
    .nsigs = sizeofarray(sig_UTF32__LE),
    .in = in_UTF32LE,
    .in_clean = clean_UTF32,
};
ENCODING_REGISTER(enc_UTF32__LE);

/**
    Translate next 4 bytes to 32-bit value; big-endian way.

    @param p Input byte stream
    @return 32-bit value
*/
static inline uint32_t
be32tohost(const uint8_t *p)
{
    return ((uint32_t)0) | (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

/// Wrapper for big-endian version of UTF-32
static size_t
in_UTF32BE(void *baton, const uint8_t *begin, const uint8_t *end,
        ucs4_t **pout, ucs4_t *end_out)
{
    return common_UTF32(baton, begin, end, pout, end_out, be32tohost);
}

// See above for difference in UTF-32 and UTF-32BE

static const encoding_sig_t sig_UTF32BE[] = {
    ENCODING_SIG(false, 0x00, 0x00, 0x00, 0x3C), // <
    ENCODING_SIG(false, 0x00, 0x00, 0x00, 0x09), // Tab
    ENCODING_SIG(false, 0x00, 0x00, 0x00, 0x0A), // LF
    ENCODING_SIG(false, 0x00, 0x00, 0x00, 0x0D), // CR
    ENCODING_SIG(false, 0x00, 0x00, 0x00, 0x20), // Space
};
static const encoding_t enc_UTF32BE = {
    .name = "UTF-32BE",
    .form = ENCODING_FORM_UTF32,
    .endian = ENCODING_E_BE,
    .baton_sz = sizeof(baton_utf32_t),
    .sigs = sig_UTF32BE,
    .nsigs = sizeofarray(sig_UTF32BE),
    .in = in_UTF32BE,
    .in_clean = clean_UTF32,
};
ENCODING_REGISTER(enc_UTF32BE);

static const encoding_sig_t sig_UTF32__BE[] = {
    ENCODING_SIG(true,  0x00, 0x00, 0xFE, 0xFF), // BOM
};
static const encoding_t enc_UTF32__BE = {
    .name = "UTF-32", // UTF-32 in big-endian order
    .form = ENCODING_FORM_UTF32,
    .endian = ENCODING_E_BE,
    .baton_sz = sizeof(baton_utf32_t),
    .sigs = sig_UTF32__BE,
    .nsigs = sizeofarray(sig_UTF32__BE),
    .in = in_UTF32BE,
    .in_clean = clean_UTF32,
};
ENCODING_REGISTER(enc_UTF32__BE);

/**
    Translate next 4 bytes to 32-bit value; 2143-endian way.

    @param p Input byte stream
    @return 32-bit value
*/
static inline uint32_t
x2143_32tohost(const uint8_t *p)
{
    return ((uint32_t)0) | (p[1] << 24) | (p[0] << 16) | (p[3] << 8) | p[2];
}

/// Wrapper for 2143-endian version of UTF-32
static size_t
in_UTF32_2143(void *baton, const uint8_t *begin, const uint8_t *end,
        ucs4_t **pout, ucs4_t *end_out)
{
    return common_UTF32(baton, begin, end, pout, end_out, x2143_32tohost);
}

// See above for difference in UTF-32 and UTF-32-2143

static const encoding_sig_t sig_UTF32_2143[] = {
    ENCODING_SIG(false, 0x00, 0x00, 0x3C, 0x00), // <
    ENCODING_SIG(false, 0x00, 0x00, 0x09, 0x00), // Tab
    ENCODING_SIG(false, 0x00, 0x00, 0x0A, 0x00), // LF
    ENCODING_SIG(false, 0x00, 0x00, 0x0D, 0x00), // CR
    ENCODING_SIG(false, 0x00, 0x00, 0x20, 0x00), // Space
};
static const encoding_t enc_UTF32_2143 = {
    .name = "UTF-32-2143",
    .form = ENCODING_FORM_UTF32,
    .endian = ENCODING_E_2143,
    .baton_sz = sizeof(baton_utf32_t),
    .sigs = sig_UTF32_2143,
    .nsigs = sizeofarray(sig_UTF32_2143),
    .in = in_UTF32_2143,
    .in_clean = clean_UTF32,
};
ENCODING_REGISTER(enc_UTF32_2143);

static const encoding_sig_t sig_UTF32__2143[] = {
    ENCODING_SIG(true,  0x00, 0x00, 0xFF, 0xFE), // BOM
};
static const encoding_t enc_UTF32__2143 = {
    .name = "UTF-32", // UTF-32 in 2143 byte order
    .form = ENCODING_FORM_UTF32,
    .endian = ENCODING_E_2143,
    .baton_sz = sizeof(baton_utf32_t),
    .sigs = sig_UTF32__2143,
    .nsigs = sizeofarray(sig_UTF32__2143),
    .in = in_UTF32_2143,
    .in_clean = clean_UTF32,
};
ENCODING_REGISTER(enc_UTF32__2143);

/**
    Translate next 4 bytes to 32-bit value; 3412-endian way.

    @param p Input byte stream
    @return 32-bit value
*/
static inline uint32_t
x3412_32tohost(const uint8_t *p)
{
    return ((uint32_t)0) | (p[2] << 24) | (p[3] << 16) | (p[0] << 8) | p[1];
}

/// Wrapper for 3412-endian version of UTF-32
static size_t
in_UTF32_3412(void *baton, const uint8_t *begin, const uint8_t *end,
        ucs4_t **pout, ucs4_t *end_out)
{
    return common_UTF32(baton, begin, end, pout, end_out, x3412_32tohost);
}

// See above for difference in UTF-32 and UTF-32-3412

static const encoding_sig_t sig_UTF32_3412[] = {
    ENCODING_SIG(false, 0x00, 0x3C, 0x00, 0x00), // <
    ENCODING_SIG(false, 0x00, 0x09, 0x00, 0x00), // Tab
    ENCODING_SIG(false, 0x00, 0x0A, 0x00, 0x00), // LF
    ENCODING_SIG(false, 0x00, 0x0D, 0x00, 0x00), // CR
    ENCODING_SIG(false, 0x00, 0x20, 0x00, 0x00), // Space
};
static const encoding_t enc_UTF32_3412 = {
    .name = "UTF-32-3412",
    .form = ENCODING_FORM_UTF32,
    .endian = ENCODING_E_3412,
    .baton_sz = sizeof(baton_utf32_t),
    .sigs = sig_UTF32_3412,
    .nsigs = sizeofarray(sig_UTF32_3412),
    .in = in_UTF32_3412,
    .in_clean = clean_UTF32,
};
ENCODING_REGISTER(enc_UTF32_3412);

static const encoding_sig_t sig_UTF32__3412[] = {
    ENCODING_SIG(true,  0xFE, 0xFF, 0x00, 0x00), // BOM
};
static const encoding_t enc_UTF32__3412 = {
    .name = "UTF-32", // UTF-32 in 3412 byte order
    .form = ENCODING_FORM_UTF32,
    .endian = ENCODING_E_3412,
    .baton_sz = sizeof(baton_utf32_t),
    .sigs = sig_UTF32__3412,
    .nsigs = sizeofarray(sig_UTF32__3412),
    .in = in_UTF32_3412,
    .in_clean = clean_UTF32,
};
ENCODING_REGISTER(enc_UTF32__3412);
