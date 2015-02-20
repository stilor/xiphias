/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/**
    @file
    Substituting string buffer. Operates in UTF-8.
    Supported substitution (S indicates escape character configured
    when creating the string buffer):
    SS - Substitute with the escape character itself
    S<newline> - Remove the newline
    SUHHHH/ - Substitute with Unicode character U+HHHH (may have up to 6
        hexadecimal digits).
*/
#include <string.h>
#include "util/defs.h"
#include "util/xutil.h"
#include "util/unicode.h"
#include "util/strbuf.h"

#include "testlib.h"

/// State of the substitution
enum subst_mode_e {
    SUBST_NONE,         ///< Normal passthrough
    SUBST_ESCAPE,       ///< Seen escape character
    SUBST_CODEPOINT,    ///< UCS-4 codepoint substitution
};

/// State structure
typedef struct subst_state_s {
    strbuf_t *input;                ///< Substituted stream
    enum subst_mode_e mode;         ///< Current mode of substitution
    uint32_t ucs4;                  ///< UCS4 code point (accumulated so far)
    uint8_t utf8_out[UTF8_LEN_MAX]; ///< UTF-8 output not yet flushed
    size_t utf8_sz;                 ///< Size of the remaining UTF-8 output
    uint8_t esc;                    ///< Escape character
} subst_state_t;

/**
    Input generator

    @param arg State structure
    @param begin Start of the destination buffer
    @param sz Size of the destination buffer
    @return Number of bytes placed into destination buffer
*/
static size_t
subst_more(void *arg, void *begin, size_t sz)
{
    subst_state_t *ss = arg;
    uint8_t *ptr = begin;
    uint8_t *end = ptr + sz;
    uint8_t *tmp;
    const void *in_tmp0, *in_tmp1;
    const uint8_t *in_ptr, *in_end;

    while (ptr < end && strbuf_rptr(ss->input, &in_tmp0, &in_tmp1)) {
        in_ptr = in_tmp0;
        in_end = in_tmp1;
        while (ptr < end && in_ptr < in_end) {
            if (ss->utf8_sz) {
                *ptr++ = ss->utf8_out[UTF8_LEN_MAX - ss->utf8_sz];
                ss->utf8_sz--;
                continue;
            }
            switch (ss->mode) {
            case SUBST_NONE:
                if (*in_ptr == ss->esc) {
                    ss->mode = SUBST_ESCAPE;
                }
                else {
                    *ptr++ = *in_ptr;
                }
                break;
            case SUBST_ESCAPE:
                if (*in_ptr == ss->esc) {
                    *ptr++ = ss->esc; // Escape character itself
                    ss->mode = SUBST_NONE;
                }
                else if (*in_ptr == '\n') {
                    ss->mode = SUBST_NONE;
                }
                else if (*in_ptr == '\r') {
                    // Skip CR and wait for LF
                }
                else if (*in_ptr == 'U') {
                    ss->ucs4 = 0; // Start of a codepoint substitution
                    ss->mode = SUBST_CODEPOINT;
                }
                else {
                    OOPS_ASSERT(0); // Unknown substitution
                }
                break;
            case SUBST_CODEPOINT:
                if (*in_ptr == '/') {
                    // End of a code point. Store from the end of the out
                    // buffer
                    ss->utf8_sz = utf8_len(ss->ucs4);
                    tmp = ss->utf8_out + UTF8_LEN_MAX - ss->utf8_sz;
                    utf8_store(&tmp, ss->ucs4);
                    ss->mode = SUBST_NONE;
                }
                else {
                    // Next digit
                    ss->ucs4 *= 16;
                    if (*in_ptr >= '0' && *in_ptr <= '9') {
                        ss->ucs4 += *in_ptr - '0';
                    }
                    else if (*in_ptr >= 'A' && *in_ptr <= 'F') {
                        ss->ucs4 += *in_ptr - 'A' + 10;
                    }
                    else if (*in_ptr >= 'a' && *in_ptr <= 'f') {
                        ss->ucs4 += *in_ptr - 'a' + 10;
                    }
                    else {
                        OOPS_ASSERT(0); // invalid hex digit
                    }
                    OOPS_ASSERT(ss->ucs4 <= UCS4_MAX); // too many digits
                }
                break;
            default:
                OOPS_ASSERT(0); // Invalid mode - should not get here
            }
            in_ptr++;
        }
        strbuf_radvance(ss->input, in_ptr - (const uint8_t *)in_tmp0);
    }
    return ptr - (uint8_t *)begin;
}

/**
    Destroy a substituting buffer.

    @param arg State structure
    @return Nothing
*/
static void
subst_destroy(void *arg)
{
    subst_state_t *ss = arg;

    strbuf_delete(ss->input);
    xfree(ss);
}

/// Substituting buffer operations
static const strbuf_ops_t subst_ops = {
    .more = subst_more,
    .destroy = subst_destroy
};

/**
    Create a substitution string buffer.

    @param input Original string buffer
    @param esc Escape character (must be single-byte UTF-8 code, i.e. 0x01..0x7F)
    @param sz Size of the internal buffer
    @return New buffer
*/
strbuf_t *
test_strbuf_subst(strbuf_t *input, uint8_t esc, size_t sz)
{
    subst_state_t *ss;
    strbuf_t *buf;

    OOPS_ASSERT(esc > 0 && esc < 0x80);
    ss = xmalloc(sizeof(subst_state_t));
    ss->input = input;
    ss->esc = esc;
    ss->mode = SUBST_NONE;
    ss->utf8_sz = 0;
    buf = strbuf_new(NULL, sz);
    strbuf_setops(buf, &subst_ops, ss);
    return buf;
}
