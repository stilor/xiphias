/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/**
    @file
    Substituting string buffer. Operates in UTF-8.
    Supported substitution (* indicates escape character configured
    when creating the string buffer):
    - ** - Substitute with the escape character itself
    - *\<newline> - Remove the newline (consumes either CRLF or just LF)
    - *UHHHH/ - Substitute with Unicode character U+HHHH (may have up to 6 digits)
    - *BHH/ - Substitute a single byte
        hexadecimal digits).
*/
#include <string.h>

#include "util/defs.h"
#include "util/xutil.h"
#include "util/strbuf.h"

#include "unicode/unicode.h"

#include "test/common/testlib.h"

/// State of the substitution
enum subst_mode_e {
    SUBST_NONE,         ///< Normal passthrough
    SUBST_ESCAPE,       ///< Seen escape character
    SUBST_CODEPOINT,    ///< UCS-4 codepoint substitution
    SUBST_BYTE,         ///< Substitute a single byte (to create invalid characters)
};

/// State structure
typedef struct subst_state_s {
    strbuf_t *input;                ///< Substituted stream
    enum subst_mode_e mode;         ///< Current mode of substitution
    uint32_t val;                   ///< Value accumulated so far
    utf8_t utf8_out[UTF8_LEN_MAX];  ///< UTF-8 output not yet flushed
    size_t utf8_sz;                 ///< Size of the remaining UTF-8 output
    utf8_t esc;                     ///< Escape character
} subst_state_t;

/**
    Convert a hexadecimal digit to a numeric value.

    @param digit Character to convert
    @return Digital value
*/
static uint32_t
fromhex(utf8_t digit)
{
    if (digit >= '0' && digit <= '9') {
        return digit - '0';
    }
    else if (digit >= 'A' && digit <= 'F') {
        return digit - 'A' + 10;
    }
    else if (digit >= 'a' && digit <= 'f') {
        return digit - 'a' + 10;
    }
    else {
        OOPS; // invalid hex digit
    }
}

/**
    Input generator. Expects input in UTF-8.

    @param arg State structure
    @param begin Start of the destination buffer
    @param sz Size of the destination buffer
    @return Number of bytes placed into destination buffer
*/
static size_t
subst_more(void *arg, void *begin, size_t sz)
{
    subst_state_t *ss = arg;
    utf8_t *ptr = begin;
    utf8_t *end = ptr + sz;
    utf8_t *tmp;
    const void *in_tmp0, *in_tmp1;
    const utf8_t *in_ptr, *in_end;

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
                    ss->val = 0; // Start of a codepoint substitution
                    ss->mode = SUBST_CODEPOINT;
                }
                else if (*in_ptr == 'B') {
                    ss->val = 0; // Start of a byte substitution
                    ss->mode = SUBST_BYTE;
                }
                else {
                    OOPS; // Unknown substitution
                }
                break;
            case SUBST_CODEPOINT:
                if (*in_ptr == '/') {
                    // End of a code point. Store from the end of the out
                    // buffer
                    ss->utf8_sz = utf8_clen(ss->val);
                    tmp = ss->utf8_out + UTF8_LEN_MAX - ss->utf8_sz;
                    utf8_store(&tmp, ss->val);
                    ss->mode = SUBST_NONE;
                }
                else {
                    // Next digit
                    ss->val *= 16;
                    ss->val += fromhex(*in_ptr);
                    OOPS_ASSERT(ss->val <= UCS4_MAX); // too many digits
                }
                break;
            case SUBST_BYTE:
                if (*in_ptr == '/') {
                    *ptr++ = ss->val;
                    ss->mode = SUBST_NONE;
                }
                else {
                    ss->val *= 16;
                    ss->val += fromhex(*in_ptr);
                    OOPS_ASSERT(ss->val <= 0xFF); // too many digits
                }
                break;
            default:
                OOPS; // Invalid mode - should not get here
            }
            in_ptr++;
        }
        strbuf_radvance(ss->input, in_ptr - (const utf8_t *)in_tmp0);
    }
    return ptr - (utf8_t *)begin;
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
test_strbuf_subst(strbuf_t *input, utf8_t esc, size_t sz)
{
    subst_state_t *ss;
    strbuf_t *buf;

    OOPS_ASSERT(esc > 0 && esc < 0x80);
    ss = xmalloc(sizeof(subst_state_t));
    ss->input = input;
    ss->esc = esc;
    ss->mode = SUBST_NONE;
    ss->utf8_sz = 0;
    buf = strbuf_new(sz);
    strbuf_setops(buf, &subst_ops, ss);
    return buf;
}
