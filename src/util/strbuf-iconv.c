/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    String buffer operations for reading from a file.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iconv.h>
#include <errno.h>

#include "util/defs.h"
#include "util/xutil.h"

#include "util/strbuf.h"

/// Private structure for iconv-based input
typedef struct iconv_arg_s {
    iconv_t cd;         ///< Conversion descriptor
    strbuf_t *buf;      ///< Input buffer
} iconv_arg_t;

/**
    Fetch more data from transcoder.

    @param arg Pointer to private structure
    @param begin Start of destination buffer
    @param sz Size of destination buffer
    @return Number of bytes stored into destination buffer
*/
static size_t
iconv_more(void *arg, void *begin, size_t sz)
{
    iconv_arg_t *ia = arg;
    const void *in_begin, *in_end;
    char *inbuf, *outbuf;
    size_t insz, outsz;

    strbuf_defrag(ia->buf);
    if (!strbuf_rptr(ia->buf, &in_begin, &in_end)) {
        return 0; // No more input
    }
    inbuf = DECONST(in_begin); // Bad, bad iconv. No qualifier.
    insz = (const char *)in_end - inbuf;
    outbuf = begin;
    outsz = sz;
    if (iconv(ia->cd, &inbuf, &insz, &outbuf, &outsz) == (size_t)-1) {
        if (errno == E2BIG) {
            // That's ok, will fetch more next time
        }
        else if (errno == EINVAL) {
            // That's ok too: next call will defrag and retry
        }
        else if (errno == EILSEQ) {
            /// @todo how to handle EILSEQ (illegal byte sequence)?
            OOPS;
        }
        else {
            OOPS; // Undocumented error in iconv
        }
    }
    // Mark a portion of input consumed and return size of output
    strbuf_radvance(ia->buf, inbuf - (const char *)in_begin);
    return outbuf - (char *)begin;
}

/**
    Destroy private structure for iconv-based input.

    @param arg Pointer to private structure
    @return Nothing
*/
static void
iconv_destroy(void *arg)
{
    iconv_arg_t *ia = arg;

    iconv_close(ia->cd);
    strbuf_delete(ia->buf);
    xfree(ia);
}

/// ICONV methods
static const strbuf_ops_t iconv_ops = {
    .more = iconv_more,
    .destroy = iconv_destroy,
};

/**
    Chain a string buffer with ICONV conversion to another string buffer.

    @param input Original string buffer
    @param from Input encoding
    @param to Output encoding
    @param sz Size of internal buffer
    @return String buffer with transcoded stream
*/
strbuf_t *
strbuf_iconv_read(strbuf_t *input, const char *from, const char *to, size_t sz)
{
    iconv_arg_t *ia;
    strbuf_t *buf;

    ia = xmalloc(sizeof(iconv_arg_t));
    if ((ia->cd = iconv_open(to, from)) == (iconv_t)-1) {
        xfree(ia);
        OOPS;
    }
    ia->buf = input;
    buf = strbuf_new(sz);
    strbuf_setops(buf, &iconv_ops, ia);
    return buf;
}

