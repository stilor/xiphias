/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    XML reader handle operations.
*/
#include <string.h>

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

    struct {
        xml_reader_cb_t func;       ///< Callback function
        void *arg;                  ///< Argument to callback function
    } callbacks[XML_READER_CB_MAX]; ///< Reader callbacks
};

/**
    XML declaration comes in two flavors, XMLDecl and TextDecl, with different
    set of allowed/mandatory/optional attributes. This structure describes an
    attribute in the expected list.
*/
struct xml_reader_xmldecl_attrdesc_s {
    const char *name;       ///< Name of the attribute
    bool mandatory;         ///< True if the attribute is mandatory
};

/// Handle TextDecl ::= '<?xml' VersionInfo? EncodingDecl S? '?>'
static const struct xml_reader_xmldecl_attrdesc_s attrlist_textdecl[] = {
    { "version", false },
    { "encoding", true },
    { NULL, false },
};

/// Handle XMLDecl  ::= '<?xml' VersionInfo EncodingDecl? SDDecl? S? '?>'
static const struct xml_reader_xmldecl_attrdesc_s attrlist_xmldecl[] = {
    { "version", true },
    { "encoding", false },
    { "standalone", false },
    { NULL, false },
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
    if (h->encoding == enc) {
        return; // Same encoding, nothing to do
    }
    if (h->encoding && enc && !encoding_compatible(h->encoding, enc)) {
        // Replacing with an incompatible encoding is not possible; the data
        // that has been read previously cannot be trusted then.
        OOPS;
    }
    // If the new encoding is "meta-encoding" (just specifying the compatibility
    // information, but not providing actual translation routine), keep the old one.
    if (enc && !enc->xlate) {
        return;
    }
    if (h->encoding) {
        h->encoding->destroy(h->encoding_baton);
        h->encoding = NULL;
        h->encoding_baton = NULL;
    }
    if (enc) {
        h->encoding = enc;
        h->encoding_baton = h->encoding->init(enc->data);
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
xml_reader_set_callback(xml_reader_t *h, enum xml_reader_cbtype_e evt,
        xml_reader_cb_t func, void *arg)
{
    OOPS_ASSERT(evt < XML_READER_CB_MAX);
    h->callbacks[evt].func = func;
    h->callbacks[evt].arg = arg;
}

/**
    Call a user-registered function for the specified event.

    @param h Reader handle
    @param evt Event for which the callback is to be invoked
    @param cbparam Parameter for the callback
    @return None
*/
static void
xml_reader_invoke_callback(xml_reader_t *h, enum xml_reader_cbtype_e evt,
        const xml_reader_cbparam_t *cbparam)
{
    OOPS_ASSERT(evt < XML_READER_CB_MAX);
    if (h->callbacks[evt].func) {
        h->callbacks[evt].func(h->callbacks[evt].arg, cbparam);
    }
}


/**
    Check if a given Unicode code point is white space per XML spec.
    XML spec says, #x20, #x9, #xA and #xD are whitespace, the rest is not.

    @param cp Code point to check
    @return true if @a cp is whitespace, false otherwise
*/
static bool
xml_is_whitespace(uint32_t cp)
{
    return xchareq(cp, 0x20) || xchareq(cp, 0x9) || xchareq(cp, 0xA)
            || xchareq(cp, 0xD);
}

/**
    Read one character from input.

    @param h Reader handle
    @return Character read
*/
static uint32_t
xml_read_1(xml_reader_t *h)
{
    uint32_t tmp, *ptr = &tmp;

    h->encoding->xlate(h->buf, h->encoding_baton, &ptr, ptr + 1);
    if (ptr == &tmp) {
        OOPS; // No input
    }
    else if (tmp >= 0x7f) {
        OOPS; // Only ASCII characters in the XML declaration
    }
    return tmp;
}

/**
    Read from the buffer until the first non-whitespace character is encountered.

    @param h Reader handle
    @return First non-whitespace character
*/
static uint32_t
xml_skip_whitespace(xml_reader_t *h)
{
    uint32_t tmp;

    do {
        tmp = xml_read_1(h);
    } while (xml_is_whitespace(tmp));
    return tmp;
}

/**
    Compare a string in host encoding to UCS-4 array.

    @param ucs UCS-4 array
    @param s String to compare
    @param sz Number of characters to compare
    @return true if strings are equal
*/
static bool
ucs4_equal(const uint32_t *ucs, const char *s, size_t sz)
{
    // We know that everything we've read at this point is ASCII (<= 0x7E) and thus
    // safe to compare as unsigned.
    while (sz--) {
        if (!xchareq(*ucs++, (uint8_t)*s++)) {
            return false;
        }
    }
    return true;
}

/**
    Parse the "attributes" in the XML declaration.

    @param h Reader handle
    @param attrlist Allowed/required "attributes"
    @param cbparam Callback parameter structure being filled
    @return None
*/
static void
xml_reader_xmldecl_getattr(xml_reader_t *h,
        const struct xml_reader_xmldecl_attrdesc_s *attrlist,
        xml_reader_cbparam_t *cbparam)
{
    uint32_t *buf;
    size_t bufsz = 32; // Initial buffer size; sufficient for all attribute names
    uint32_t eq, quote;
    size_t nread, i;
    char *encname;

    buf = xmalloc(bufsz);
    // TBD register a clean-up to free buf on OOPS
    while (true) {
        buf[0] = xml_skip_whitespace(h);
        if (xchareq(buf[0], '?')) {
            // Seems like the end of the declaration... Verify the next character,
            // verify there are no more required attributes and be done.
            buf[1] = xml_read_1(h);
            if (xchareq(buf[1], '>')) {
                while (attrlist->name) {
                    if (attrlist->mandatory) {
                        OOPS; // Required and missing
                    }
                    attrlist++;
                }
                xfree(buf);
                return;
            }
            OOPS; // Malformed declaration
        }
        if (!attrlist->name) {
            OOPS; // Another attribute? We are not expecting anything!
        }
        nread = 1; // 1 character in buffer
        // Find an attribute that matches
        do {
            // This immediately reads 2nd character. Fortunately, there are no 1-char
            // attribute names in XMLDecl/TextDecl
            buf[nread++] = xml_read_1(h);
            while (!ucs4_equal(buf, attrlist->name, nread)) {
                if (attrlist->mandatory) {
                    OOPS; // Mandatory attribute missing
                }
                // Doesn't match and is optional - advance to the next attribute
                attrlist++;
                if (!attrlist->name) {
                    OOPS; // The input is not a name of any expected attribute
                }
            }
        } while (nread != strlen(attrlist->name));

        // Found the attribute name, now look for Eq production: S* '=' S*
        eq = xml_skip_whitespace(h);
        if (!xchareq(eq, '=')) {
            OOPS; // No equal size
        }
        quote = xml_skip_whitespace(h);
        if (!xchareq(quote, '"') && !xchareq(quote, '\'')) {
            OOPS; // Attribute value does not start with a quote
        }
        // Look for a matching quote
        nread = 0;
        do {
            if (nread == bufsz) {
                // Double the buffer capacity. Should not be needed on a real document
                // with a sensible encoding name (the rest of the attributes are 3 characters
                // at most)
                bufsz *= 2;
                buf = xrealloc(buf, bufsz);
            }
        } while ((buf[nread++] = xml_read_1(h)) != quote);

        // Verify/save the attribute value. Note that 'nread' includes closing quote
        if (!strcmp(attrlist->name, "version")) {
            if (nread == 4 && ucs4_equal(buf, "1.0", 3)) {
                cbparam->xmldecl.version = XML_INFO_VERSION_1_0;
            }
            else if (nread == 4 && ucs4_equal(buf, "1.1", 3)) {
                cbparam->xmldecl.version = XML_INFO_VERSION_1_1;
            }
            else {
                OOPS; // Unsupported version
            }
        }
        else if (!strcmp(attrlist->name, "encoding")) {
            encname = xmalloc(nread);
            for (i = 0; i < nread - 1; i++) {
                encname[i] = buf[i]; // Convert to UTF-8/ASCII
            }
            encname[i] = 0;
            cbparam->xmldecl.encoding = encname;
        }
        else if (!strcmp(attrlist->name, "standalone")) {
            if (nread == 4 && ucs4_equal(buf, "yes", 3)) {
                cbparam->xmldecl.standalone = XML_INFO_STANDALONE_YES;
            }
            else if (nread == 3 && ucs4_equal(buf, "no", 2)) {
                cbparam->xmldecl.standalone = XML_INFO_STANDALONE_NO;
            }
            else {
                OOPS; // Invalid value for standalone="..."
            }
        }
        else {
            OOPS;
        }

        // Advance to the next attribute
        attrlist++;
    }
}

/**
    Perform the translation and normalization checks prescribed by the XML
    specifications.

    End-of-Line handling:

    For XML 1.0: To simplify the tasks of applications, the XML processor MUST
    behave as if it normalized all line breaks in external parsed entities
    (including the document entity) on input, before parsing, by translating
    both the two-character sequence #xD #xA and any #xD that is not followed
    by #xA to a single #xA character.

    For XML 1.1: To simplify the tasks of applications, the XML processor MUST
    behave as if it normalized all line breaks in external parsed entities
    (including the document entity) on input, before parsing, by translating
    all of the following to a single #xA character:
    1. the two-character sequence #xD #xA
    2. the two-character sequence #xD #x85
    3. the single character #x85
    4. the single character #x2028
    5. any #xD character that is not immediately followed by #xA or #x85.

    Normalization checking (XML 1.1 only):

    All XML parsed entities (including document entities) SHOULD be fully
    normalized as per the definition of B Definitions for Character
    Normalization supplemented by the following definitions of relevant
    constructs for XML:
    1. The replacement text of all parsed entities
    2. All text matching, in context, one of the following productions:
       - CData
       - CharData
       - content
       - Name
       - Nmtoken

    From this definition of normalization, it looks like the whole document
    inside the root element is expected to be fully normalized. At the top
    level, the following are expected to be normalized: PI targets,
    element names and attribute names (but not attribute values!), and parts
    of the document type definition.

    @param input Input buffer, in UCS-4
    @param nchars Number of characters in the input buffer
    @param output Output buffer, in UTF-8. Must point at least 4 times @a nchars
        bytes.
    @return Number of bytes consumed in the output buffer
*/
static size_t
xml_reader_input_filter(uint32_t *input, size_t nchars, uint8_t *output)
{
    uint8_t *ptr = output;

    // TBD EOL translation
    // TBD normalization check

    // Just pack the characters for now
    while (nchars--) {
        encoding_utf8_store(&ptr, *input++);
    }
    return ptr - output;
}

/**
    Create a transcoding string buffer that decodes the input as determined
    by the reader start.

    @param h Reader handle
    @param xlate_buf Translation buffer, either empty or with content rejected
        while looking for XML/text declaration.
    @return None
*/
static void
xml_reader_set_input(xml_reader_t *h, strbuf_t *xlate_buf)
{
    // TBD: set the buffer ops to transcoder + xml_reader_input_filter
}

/**
    Start parsing an input stream: read the XML/text declaration, determine final
    encodings (or err out).

    @param h Reader handle
    @param attrlist Allowed/required attributes on an XML/text declaration
    @return None
*/
static void
xml_reader_start(xml_reader_t *h, const struct xml_reader_xmldecl_attrdesc_s *attrlist)
{
    uint32_t xmldecl[6], *ptr = xmldecl;
    uint8_t xmldecl_utf8[sizeofarray(xmldecl) * 4]; // max 4 bytes per char
    size_t len;
    const encoding_t *enc;
    const char *encname;
    bool had_bom;
    strbuf_t *xlate_buf;
    xml_reader_cbparam_t cbparam = {
        .xmldecl = {
            .has_decl = false,
            .encoding = NULL,
            .standalone = XML_INFO_STANDALONE_NO_VALUE,
            .version = XML_INFO_VERSION_NO_VALUE,
        }
    };

    // No more setup changes
    h->flags |= READER_STARTED;

    // Check the stream for Byte Order Mark (BOM) and switch the encoding, if needed
    if ((encname = encoding_detect_byte_order(h->buf, &had_bom)) != NULL) {
        if ((enc = encoding_search(encname)) == NULL) {
            OOPS;
        }
        xml_reader_set_encoding(h, enc);
        xfree(h->enc_detected);
        h->enc_detected = xstrdup(encname);
    }

    // If no encoding passed from the transport layer, and autodetect didn't help,
    // try UTF-8.
    if (!h->encoding) {
        enc = encoding_search("UTF-8");
        OOPS_ASSERT(enc);   // UTF-8 must be built in
        xml_reader_set_encoding(h, enc);
    }

    // Entities encoded in UTF-16 MUST and entities encoded in UTF-8 MAY
    // begin with the Byte Order Mark described in ISO/IEC 10646 [ISO/IEC
    // 10646] or Unicode [Unicode] (the ZERO WIDTH NO-BREAK SPACE character, #xFEFF).
    //
    // Note that we don't know the final encoding from the XML declaration at this
    // point, but if it different - it must be compatible and thus must have the same
    // encoding type.
    if (!had_bom && h->encoding->enctype == ENCODING_T_UTF16) {
        OOPS;
    }

    // The selected encoding must not be "meta-encoding"
    if (!h->encoding->xlate) {
        OOPS;
    }

    // We should at least know the encoding type by now: whether it is 1/2/4-byte based,
    // and the endianness. Read and parse the XML/Text declaration, if any, and set
    // the final encoding as specified therein. Until then, though, we need to be careful
    // and read one character at a time; otherwise, we may assume a partially compatible
    // encoding and transcode too much.

    // We are looking for '<?xml' string, followed by XML whitespace
    h->encoding->xlate(h->buf, h->encoding_baton, &ptr, xmldecl + sizeofarray(xmldecl));
    if (ptr == xmldecl + sizeofarray(xmldecl)
            && xchareq(xmldecl[0], '<')
            && xchareq(xmldecl[1], '?')
            && xchareq(xmldecl[2], 'x')
            && xchareq(xmldecl[3], 'm')
            && xchareq(xmldecl[4], 'l')
            && xml_is_whitespace(xmldecl[5])) {
        // We have a declaration; parse the rest of arguments (if any). XML spec only
        // allows ASCII characterts in the XMLDecl/TextDecl production: "The characters
        // #x85 and #x2028 cannot be reliably recognized and translated until an entity's
        // encoding declaration (if present) has been read. Therefore, it is a fatal error
        // to use them within the XML declaration or text declaration."
        cbparam.xmldecl.has_decl = true;
        xml_reader_xmldecl_getattr(h, attrlist, &cbparam);
        xlate_buf = strbuf_new(); // Consumed the declaration; start with empty buffer
    }
    else {
        // No declaration, "unget" the characters we've read.
        len = xml_reader_input_filter(xmldecl, ptr - xmldecl, xmldecl_utf8);
        xlate_buf = strbuf_new_from_memory(xmldecl_utf8, len, true);
        strbuf_setf(xlate_buf, 0, BUF_LAST); // Ops to get the rest will be set below
    }

    // Set operations for reading in the discovered encoding
    xml_reader_set_input(h, xlate_buf);

    // TBD In the absence of external character encoding information (such as MIME
    // headers), parsed entities which are stored in an encoding other than UTF-8
    // or UTF-16 MUST begin with a text declaration (see 4.3.1 The Text Declaration)
    // containing an encoding declaration.

    // TBD Unless an encoding is determined by a higher-level protocol, it is also a fatal
    // error if an XML entity contains no encoding declaration and its content is not
    // legal UTF-8 or UTF-16.

    // Emit an event (callback) for XML declaration
    xml_reader_invoke_callback(h, XML_READER_CB_XMLDECL, &cbparam);
}

void
xml_reader_process_xml(xml_reader_t *h, bool is_document_entity)
{
    xml_reader_start(h, is_document_entity ? attrlist_xmldecl : attrlist_textdecl);
    // TBD process the rest of the content
}
