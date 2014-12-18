/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    XML reader handle operations.
*/
#include "util/defs.h"
#include "util/xutil.h"
#include "util/strbuf.h"
#include "util/encoding.h"

#include "xml/reader.h"

/// Reader flags
enum {
    READER_STARTED = 0x0001,        ///< Reader has started the operation
};

/// XML reader structure
struct xml_reader_s {
    const char *enc_transport;      ///< Encoding reported by transport protocol
    const char *enc_detected;       ///< Encoding detected by BOM or start characters
    const char *enc_xmldecl;        ///< Encoding declared in <?xml ... ?>
    const encoding_t *encoding;     ///< Actual encoding being used
    void *encoding_baton;           ///< Encoding data
    strbuf_t *buf;                  ///< Input buffer
    uint32_t flags;                 ///< Reader flags
};

/**
    Replace encoding translator in a handle.

    @param h Reader handle
    @param enc Encoding to be set, NULL to clear current encoding processor
    @return None
*/
static void
xml_reader_set_encoding(xml_reader_t *h, const encoding_t *enc)
{
    if (h->encoding && enc && !encoding_compatible(h->encoding, enc)) {
        // Replacing with an incompatible encoding is not possible; the data
        // that has been read previously cannot be trusted then.
        OOPS;
    }
    if (h->encoding) {
        h->encoding->destroy(&h->buf, h->encoding_baton);
        h->encoding = NULL;
        h->encoding_baton = NULL;
    }
    if (enc) {
        h->encoding = enc;
        h->encoding_baton = h->encoding->init(&h->buf, enc->data);
    }
}

xml_reader_t *
xml_reader_new(strbuf_t *buf)
{
    xml_reader_t *h;

    h = xmalloc(sizeof(*h));
    h->enc_transport = NULL;
    h->enc_detected = NULL;
    h->enc_xmldecl = NULL;
    h->encoding = NULL;
    h->encoding_baton = NULL;
    h->buf = buf;
    h->flags = 0;
    return h;
}

void
xml_reader_delete(xml_reader_t *h)
{
    xml_reader_set_encoding(h, NULL);
    strbuf_delete(h->buf);
    xfree(h->enc_transport);
    xfree(h->enc_detected);
    xfree(h->enc_xmldecl);
    xfree(h);
}

void
xml_reader_set_transport_encoding(xml_reader_t *h, const char *encname)
{
    const encoding_t *enc;

    OOPS_ASSERT(!(h->flags & READER_STARTED));
    if ((enc = encoding_search(encname)) == NULL) {
        OOPS;
    }
    xml_reader_set_encoding(h, enc);
    xfree(h->enc_transport);
    h->enc_transport = xstrdup(encname);
}

void
xml_reader_start(xml_reader_t *h, const char *const *xmldeclattr)
{
    const encoding_t *enc;
    const char *encname;

    // No more setup changes
    h->flags |= READER_STARTED;

    // Check the stream for Byte Order Mark (BOM) and switch the encoding, if needed
    if ((encname = encoding_detect_byte_order(h->buf)) != NULL) {
        if ((enc = encoding_search(encname)) == NULL) {
            OOPS;
        }
        xml_reader_set_encoding(h, enc);
        xfree(h->enc_detected);
        h->enc_detected = xstrdup(encname);
    }

    // We should at least know the encoding type by now: whether it is 1/2/4-byte based,
    // and the endianness. Read and parse the XML/Text declaration, if any, and set
    // the final encoding as specified therein.

    // TBD
}
