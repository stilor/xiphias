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

/**
    Initial size of the read buffer (the buffer is to accommodate the longest
    contiguous token). Each time this space is insufficient, it will be doubled.
*/
#define INITIAL_READBUF_SIZE        1024

/// Reader flags
enum {
    READER_STARTED  = 0x0001,       ///< Reader has started the operation
    READER_FATAL    = 0x0002,       ///< Reader encountered a fatal error
    READER_SAW_CR   = 0x0004,       ///< Converting CRLF: saw 0xD, ignore next 0xA/0x85
    READER_POS_RESET= 0x0008,       ///< Reset position before reading the next char
    READER_READDECL = 0x0010,       ///< Looking ahead for the declaration
};

/// Used as an indicator that no character was read
#define NOCHAR      ((uint32_t)-1)

/**
    XML declaration comes in two flavors, XMLDecl and TextDecl, with different
    set of allowed/mandatory/optional attributes. This structure describes an
    attribute in the expected list.
*/
typedef struct xml_reader_xmldecl_attrdesc_s {
    const char *name;       ///< Name of the attribute
    bool mandatory;         ///< True if the attribute is mandatory
    xmlerr_info_t errinfo;  ///< Error info used for errors in this attribute
} xml_reader_xmldecl_attrdesc_t;

/// Declaration info for XMLDecl/TextDecl:
typedef struct xml_reader_xmldecl_declinfo_s {
    const char *name;           ///< Declaration name in XML grammar
    const xmlerr_info_t generr; ///< Generic error in this production
    const xml_reader_xmldecl_attrdesc_t *attrlist; ///< Allowed/required attributes
} xml_reader_xmldecl_declinfo_t;

/// XML reader structure
struct xml_reader_s {
    const char *enc_transport;      ///< Encoding reported by transport protocol
    const char *enc_detected;       ///< Encoding detected by BOM or start characters
    const char *enc_xmldecl;        ///< Encoding declared in <?xml ... ?>
    const encoding_t *encoding;     ///< Actual encoding being used
    void *encoding_baton;           ///< Encoding data
    strbuf_t *buf_raw;              ///< Raw input buffer (in document's encoding)
    strbuf_t *buf_proc;             ///< Processed input buffer (transcoded + translated)
    uint32_t flags;                 ///< Reader flags
    xmlerr_loc_t loc;               ///< Current reader's position
    const xml_reader_xmldecl_declinfo_t *declinfo;  ///< Expected declaration

    xml_reader_cb_t func;           ///< Callback function
    void *arg;                      ///< Argument to callback function

    uint32_t *readbuf;              ///< Read buffer
    size_t readbuf_sz;              ///< Current size of the read buffer
};

/// Handle TextDecl ::= '<?xml' VersionInfo? EncodingDecl S? '?>'
static const struct xml_reader_xmldecl_declinfo_s declinfo_textdecl = {
    .name = "TextDecl",
    .generr = XMLERR(ERROR, XML, P_TextDecl),
    .attrlist = (const xml_reader_xmldecl_attrdesc_t[]){
        { "version", false, XMLERR(ERROR, XML, P_VersionInfo) },
        { "encoding", true, XMLERR(ERROR, XML, P_EncodingDecl) },
        { NULL, false, XMLERR_NOTE },
    },
};

/// Handle XMLDecl  ::= '<?xml' VersionInfo EncodingDecl? SDDecl? S? '?>'
static const struct xml_reader_xmldecl_declinfo_s declinfo_xmldecl = {
    .name = "XMLDecl",
    .generr = XMLERR(ERROR, XML, P_XMLDecl),
    .attrlist = (const struct xml_reader_xmldecl_attrdesc_s[]){
        { "version", true, XMLERR(ERROR, XML, P_VersionInfo) },
        { "encoding", false, XMLERR(ERROR, XML, P_EncodingDecl) },
        { "standalone", false, XMLERR(ERROR, XML, P_SDDecl) },
        { NULL, false, XMLERR_NOTE },
    },
};

/**
    Determine if a character is a restricted character. Restricted characters are
    completely illegal in XML1.0 (directly inserted and inserted as character reference).
    They are allowed in character references in XML1.1 documents.

    @param cp Codepoint
    @return true if @a cp is a restricted character
*/
static inline bool
xml_is_restricted(uint32_t cp)
{
    static const bool restricted_chars[] = {
#define R(x)    [x] = true
        R(0x01), R(0x02), R(0x03), R(0x04), R(0x05), R(0x06), R(0x07), R(0x08), R(0x0B), R(0x0C),
        R(0x0E), R(0x0F), R(0x10), R(0x11), R(0x12), R(0x13), R(0x14), R(0x15), R(0x16), R(0x17),
        R(0x18), R(0x19), R(0x1A), R(0x1B), R(0x1C), R(0x1D), R(0x1E), R(0x1F), R(0x7F), R(0x80),
        R(0x81), R(0x82), R(0x83), R(0x84), R(0x86), R(0x87), R(0x88), R(0x89), R(0x8A), R(0x8B),
        R(0x8C), R(0x8D), R(0x8E), R(0x8F), R(0x90), R(0x91), R(0x92), R(0x93), R(0x94), R(0x95),
        R(0x96), R(0x97), R(0x98), R(0x99), R(0x9A), R(0x9B), R(0x9C), R(0x9D), R(0x9E), R(0x9F),
#undef R
    };

    return cp < sizeofarray(restricted_chars) ? restricted_chars[cp] : false;
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
    Replace encoding translator in a handle.

    @param h Reader handle
    @param enc Encoding to be set, NULL to clear current encoding processor
    @return true if successful, false otherwise
*/
static bool
xml_reader_set_encoding(xml_reader_t *h, const char *encname)
{
    const encoding_t *enc = NULL;

    if (encname != NULL) {
        if ((enc = encoding_search(encname)) == NULL) {
            xml_reader_message(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                    "Unsupported encoding '%s'", encname);
            return false;
        }
    }

    if (h->encoding == enc) {
        return true; // Same encoding, nothing to do
    }
    if (h->encoding && enc && !encoding_compatible(h->encoding, enc)) {
        // Replacing with an incompatible encoding is not possible; the data
        // that has been read previously cannot be trusted then.
        xml_reader_message(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                "Incompatible encodings: '%s' and '%s'", h->encoding->name, enc->name);
        return false;
    }
    // If the new encoding is "meta-encoding" (just specifying the compatibility
    // information, but not providing actual translation routine), keep the old one.
    if (enc && !enc->xlate) {
        return true;
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
    return true;
}

/**
    Create an XML reading handle.

    @param buf String buffer to read the input from; will be destroyed along with
          the handle returned by this function.
    @param location Location that will be used for reporting errors
    @return Handle
*/
xml_reader_t *
xml_reader_new(strbuf_t *buf, const char *location)
{
    xml_reader_t *h;

    h = xmalloc(sizeof(*h));
    h->enc_transport = NULL;
    h->enc_detected = NULL;
    h->enc_xmldecl = NULL;
    h->encoding = NULL;
    h->encoding_baton = NULL;
    h->buf_raw = buf;
    h->buf_proc = NULL;
    h->flags = 0;
    h->loc.src = xstrdup(location);
    h->loc.line = 1;
    h->loc.pos = 0;
    h->readbuf_sz = INITIAL_READBUF_SIZE;
    h->readbuf = xmalloc(h->readbuf_sz * sizeof(uint32_t));
    return h;
}

/**
    Destroy an XML reading handle.

    @param h Handle to be destroyed.
    @return None
*/
void
xml_reader_delete(xml_reader_t *h)
{
    (void)xml_reader_set_encoding(h, NULL);
    strbuf_delete(h->buf_raw);
    if (h->buf_proc) {
        strbuf_delete(h->buf_proc);
    }
    xfree(h->enc_transport);
    xfree(h->enc_detected);
    xfree(h->enc_xmldecl);
    xfree(h->loc.src);
    xfree(h->readbuf);
    xfree(h);
}

/**
    Set transport encoding.

    @param h Reader handle
    @param encname Encoding reported by higher-level protocol
               (e.g. Content-Type header in HTTP).
    @return true if encoding set successfully, false otherwise
*/
bool
xml_reader_set_transport_encoding(xml_reader_t *h, const char *encname)
{
    OOPS_ASSERT(!(h->flags & READER_STARTED));

    // Delete old encoding so that compatibility check is not performed:
    // we have not read any data yet
    (void)xml_reader_set_encoding(h, NULL);
    if (!xml_reader_set_encoding(h, encname)) {
        return false;
    }
    xfree(h->enc_transport);
    h->enc_transport = xstrdup(encname);
    return true;
}

/**
    Set callback functions for the reader.

    @param h Reader handle
    @param func Function to be called
    @param arg Argument to callback function
    @return None
*/
void
xml_reader_set_callback(xml_reader_t *h, xml_reader_cb_t func, void *arg)
{
    h->func = func;
    h->arg = arg;
}

/**
    Call a user-registered function for the specified event.

    @param h Reader handle
    @param cbparam Parameter for the callback
    @return None
*/
static void
xml_reader_invoke_callback(xml_reader_t *h, const xml_reader_cbparam_t *cbparam)
{
    if (h->func) {
        h->func(h->arg, cbparam);
    }
}

/**
    Report an error/warning/note for the current location in a handle.

    @param h Reader handle
    @param info Error code
    @param fmt Message format
    @return Nothing
*/
void
xml_reader_message(xml_reader_t *h, xmlerr_info_t info, const char *fmt, ...)
{
    xml_reader_cbparam_t cbparam = {
        .cbtype = XML_READER_CB_MESSAGE,
    };
    va_list ap;

    cbparam.message.loc = h->loc;
    cbparam.message.info = info;
    va_start(ap, fmt);
    cbparam.message.msg = xvasprintf(fmt, ap);
    va_end(ap);
    xml_reader_invoke_callback(h, &cbparam);
    xfree(cbparam.message.msg);
}


/**
    Read one character from input.

    @param h Reader handle
    @return Character read, or NOCHAR on error
*/
static uint32_t
xml_hdr_read_1(xml_reader_t *h)
{
    uint32_t tmp, *ptr = &tmp;
    bool next = false;

    if (h->flags & READER_POS_RESET) {
        h->loc.line++;
        h->loc.pos = 0;
        h->flags &= ~READER_POS_RESET;
    }

    /*
        XML processor MUST behave as if it normalized all line breaks in external
        parsed entities ...
    */
    do {
        h->encoding->xlate(h->buf_raw, h->encoding_baton, &ptr, ptr + 1);
        if (ptr == &tmp) {
            // This is only error if we know declaration is present
            if ((h->flags & READER_READDECL) == 0) {
                xml_reader_message(h, h->declinfo->generr,
                        "%s truncated", h->declinfo->name);
                h->flags |= READER_FATAL;
            }
            return NOCHAR;
        }
        if ((h->flags & READER_SAW_CR) && tmp == 0x0A) {
            next = true;
        }
        h->flags &= ~READER_SAW_CR;
    } while (next);

    h->loc.pos++;
    if (!tmp || tmp >= 0x7f || xml_is_restricted(tmp)) {
        // This is only error if we know declaration is present
        if ((h->flags & READER_READDECL) == 0) {
            xml_reader_message(h, h->declinfo->generr,
                    "%s contains non-ASCII or restricted characters", h->declinfo->name);
            h->flags |= READER_FATAL;
        }
        return NOCHAR;
    }
    if (tmp == 0x0D) {
        tmp = 0x0A;
        h->flags |= READER_SAW_CR;
    }
    if (tmp == 0x0A) {
        h->flags |= READER_POS_RESET;
    }
    return tmp;
}

/**
    Read from the buffer until the first non-whitespace character is encountered.

    @param h Reader handle
    @return First non-whitespace character
*/
static uint32_t
xml_hdr_skip_whitespace(xml_reader_t *h)
{
    uint32_t tmp;

    do {
        tmp = xml_hdr_read_1(h);
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
    Check if encoding name matches the EncName production:
    [A-Za-z] ([A-Za-z0-9._] | '-')*

    @param ucs UCS-4 array
    @param sz Number of characters to check
    @return true if matches, false otherwise
*/
static bool
check_EncName(const uint32_t *ucs, size_t sz)
{
    size_t i;

    for (i = 0; i < sz; i++, ucs++) {
        if (xcharin(*ucs, 'A', 'Z') || xcharin(*ucs, 'a', 'z')) {
            continue;
        }
        if (!i) {
            return false;
        }
        if (!xcharin(*ucs, '0', '9')
                && !xchareq(*ucs, '.')
                && !xchareq(*ucs, '_')
                && !xchareq(*ucs, '-')) {
            return false;
        }
    }
    return true;
}

/**
    Check for VersionInfo production.

    @param ucs UCS-4 array
    @param sz Number of characters to check
    @return true if matches, false otherwise
*/
static bool
check_VersionInfo(const uint32_t *ucs, size_t sz)
{
    size_t i;

    if (sz < 3 || !ucs4_equal(ucs, "1.", 2)) {
        return false;
    }
    for (i = 2, ucs += 2; i < sz; i++, ucs++) {
        if (!xcharin(*ucs, '0', '9')) {
            return false;
        }
    }
    return true;
}

/**
    Parse the "attributes" in the XML declaration (XMLDecl/TextDecl).

    @param h Reader handle
    @param cbparam Callback parameter structure being filled
    @return None
*/
static void
xml_reader_xmldecl_getattr(xml_reader_t *h,
        xml_reader_cbparam_t *cbparam)
{
    const xml_reader_xmldecl_declinfo_t *declinfo = h->declinfo;
    const xml_reader_xmldecl_attrdesc_t *attrlist = declinfo->attrlist;
    uint32_t *buf;
    size_t bufsz = 32; // Initial buffer size; sufficient for all attribute names
    uint32_t eq, quote;
    size_t nread, i;
    char *encname;

    // Lots of NOCHAR checks below: the application has been notified in xml_hdr_read_1
    buf = xmalloc(bufsz * sizeof(uint32_t));
    while (true) {
        if ((buf[0] = xml_hdr_skip_whitespace(h)) == NOCHAR) {
            goto out;
        }
        if (xchareq(buf[0], '?')) {
            // Seems like the end of the declaration... Verify the next character,
            // verify there are no more required attributes and be done.
            if ((buf[1] = xml_hdr_read_1(h)) == NOCHAR) {
                goto out;
            }
            if (xchareq(buf[1], '>')) {
                while (attrlist->name) {
                    if (attrlist->mandatory) {
                        xml_reader_message(h, declinfo->generr,
                                "Mandatory pseudo-attribute '%s' missing in %s",
                                attrlist->name, declinfo->name);
                    }
                    attrlist++;
                }
                goto out;
            }
            xml_reader_message(h, declinfo->generr, "Malformed %s", declinfo->name);
            h->flags |= READER_FATAL;
            goto out;
        }
        if (!attrlist->name) {
            // Another attribute? We are not expecting anything!
            xml_reader_message(h, declinfo->generr, "Unexpected pseudo-attribute");
            h->flags |= READER_FATAL;
            goto out;
        }
        nread = 1; // 1 character in buffer
        // Find an attribute that matches
        do {

            // This immediately reads 2nd character. Fortunately, there are no 1-char
            // pseudo-attribute names in XMLDecl/TextDecl
            if ((buf[nread++] = xml_hdr_read_1(h)) == NOCHAR) {
                goto out;
            }
            while (!ucs4_equal(buf, attrlist->name, nread)) {
                if (attrlist->mandatory) {
                    // Non-fatal: continue with next pseudo-attributes
                    xml_reader_message(h, declinfo->generr,
                            "Mandatory pseudo-attribute '%s' missing in %s",
                            attrlist->name, declinfo->name);
                }
                // Doesn't match and is optional - advance to the next attribute
                attrlist++;
                if (!attrlist->name) {
                    // TBD: make non-fatal: recover by parsing as if it were the following production:
                    //    Attribute S* Eq S* ('"' Char* '"' | "'" Char* "'")
                    xml_reader_message(h, declinfo->generr,
                            "Unexpected pseudo-attribute");
                    h->flags |= READER_FATAL;
                    goto out;
                }
            }
        } while (nread != strlen(attrlist->name));

        // Found the attribute name, now look for Eq production: S* '=' S*
        eq = xml_hdr_skip_whitespace(h);
        if (!xchareq(eq, '=')) {
            xml_reader_message(h, attrlist->errinfo, "No equal sign in pseudo-attribute");
            h->flags |= READER_FATAL;
            goto out;
        }
        quote = xml_hdr_skip_whitespace(h);
        if (!xchareq(quote, '"') && !xchareq(quote, '\'')) {
            xml_reader_message(h, attrlist->errinfo,
                    "Pseudo-attribute value does not start with a quote");
            h->flags |= READER_FATAL;
            goto out;
        }
        // Look for a matching quote
        nread = 0;
        do {
            if (nread == bufsz) {
                // Double the buffer capacity. Should not be needed on a real document
                // with a sensible encoding name (the rest of the attributes are 3 characters
                // at most)
                bufsz *= 2;
                buf = xrealloc(buf, bufsz * sizeof(uint32_t));
            }
            if ((buf[nread] = xml_hdr_read_1(h)) == NOCHAR) {
                goto out;
            }
        } while (buf[nread++] != quote);

        // Verify/save the attribute value. Note that 'nread' includes closing quote
        if (!strcmp(attrlist->name, "version")) {
            // For efficiency, first check "known good" versions explicitly.
            if (nread == 4 && ucs4_equal(buf, "1.0", 3)) {
                cbparam->xmldecl.version = XML_INFO_VERSION_1_0;
            }
            else if (nread == 4 && ucs4_equal(buf, "1.1", 3)) {
                cbparam->xmldecl.version = XML_INFO_VERSION_1_1;
            }
            else if (nread >= 4 && check_VersionInfo(buf, nread - 1)) {
                /*
                    Even though the VersionNum production matches any version number of
                    the form '1.x', XML 1.0 documents SHOULD NOT specify a version number
                    other than '1.0'.

                    Note: When an XML 1.0 processor encounters a document that specifies
                    a 1.x version number other than '1.0', it will process it as a 1.0
                    document. This means that an XML 1.0 processor will accept 1.x
                    documents provided they do not use any non-1.0 features.
                */
                cbparam->xmldecl.version = XML_INFO_VERSION_1_0;
                xml_reader_message(h, XMLERR(WARN, XML, FUTURE_VERSION),
                        "Document specifies unknown 1.x XML version");
            }
            else {
                // Non-fatal: recover by assuming version was missing
                xml_reader_message(h, attrlist->errinfo, "Unsupported XML version");
            }
        }
        else if (!strcmp(attrlist->name, "encoding")) {
            if (check_EncName(buf, nread - 1)) {
                encname = xmalloc(nread);
                for (i = 0; i < nread - 1; i++) {
                    encname[i] = buf[i]; // Convert to UTF-8/ASCII
                }
                encname[i] = 0;
                if (!xml_reader_set_encoding(h, encname)) {
                    // Non-fatal: recover by assuming the encoding currently used
                    xml_reader_message(h, XMLERR_NOTE, "(encoding from XML declaration)");
                }
                cbparam->xmldecl.encoding = encname;
                xfree(h->enc_xmldecl);
                h->enc_xmldecl = encname;
            }
            else {
                // Non-fatal: recover by assuming no encoding specification
                xml_reader_message(h, attrlist->errinfo, "Invalid encoding name");
            }
        }
        else if (!strcmp(attrlist->name, "standalone")) {
            if (nread == 4 && ucs4_equal(buf, "yes", 3)) {
                cbparam->xmldecl.standalone = XML_INFO_STANDALONE_YES;
            }
            else if (nread == 3 && ucs4_equal(buf, "no", 2)) {
                cbparam->xmldecl.standalone = XML_INFO_STANDALONE_NO;
            }
            else {
                // Non-fatal: recover by assuming standalone was not specified
                xml_reader_message(h, attrlist->errinfo, "Unsupported standalone status");
            }
        }
        else {
            // attrlist contained some unknown attribute name
            xml_reader_message(h, XMLERR_INTERNAL, "Unexpected attribute name in %s()",
                    __func__);
            h->flags |= READER_FATAL;
            goto out;
        }

        // Advance to the next attribute
        attrlist++;
    }

out:
    // TBD register a clean-up to free buf on OOPS
    xfree(buf);
}

/**
    Fetch more data from the transcoder, perform the translation and normalization
    checks prescribed by the XML specifications.

    TBD probably normalizations are not going to be performed here - move the comment

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
    of the document type definition. For now, though, we'll do simpler thing:
    just signal to the application that a normalization error was detected,
    regardless of its location.

    @param buf Destination string buffer 
    @param arg Reader handle
    @return None
*/
static void
xml_reader_op_input(strbuf_t *buf, void *arg)
{
#define READ_BLOCK_CHARS   4096    // TBD increase?
    xml_reader_t *h = arg;
    uint32_t *bptr, *cptr, *eptr;
    strblk_t *blk;

    blk = strblk_new(READ_BLOCK_CHARS * sizeof(uint32_t));
    cptr = bptr = strblk_getptr(blk);
    eptr = bptr + READ_BLOCK_CHARS;
    h->encoding->xlate(h->buf_raw, h->encoding_baton, &cptr, eptr);
    if (cptr != eptr) {
        strbuf_setf(buf, BUF_LAST, BUF_LAST); // This input, if any, is final
    }
    if (cptr != bptr) {
        // Fetched something
        strblk_trim(blk, (cptr - bptr) * sizeof(uint32_t));
        strbuf_append_block(buf, blk);
    }
    else {
        // EOF before we fetched anything
        strblk_delete(blk);
    }
}

/**
    Clean up no longer used XML input buffer.

    @param buf Destination string buffer 
    @param arg Reader handle, converted to void pointer
    @return None
*/
static void
xml_reader_op_destroy(strbuf_t *buf, void *arg)
{
    // No-op
}

static const strbuf_ops_t xml_reader_translation_ops = {
    .input = xml_reader_op_input,
    .destroy = xml_reader_op_destroy,
};

/**
    Start parsing an input stream: read the XML/text declaration, determine final
    encodings (or err out).

    @param h Reader handle
    @return None
*/
static void
xml_reader_start(xml_reader_t *h)
{
    uint32_t xmldecl[6];
    size_t i;
    const char *encname;
    bool had_bom;
    xml_reader_cbparam_t cbparam = {
        .cbtype = XML_READER_CB_XMLDECL,
        .xmldecl = {
            .has_decl = false,
            .encoding = NULL,
            .standalone = XML_INFO_STANDALONE_NO_VALUE,
            .version = XML_INFO_VERSION_NO_VALUE,
            .initial_encoding = NULL,
        },
    };

    // No more setup changes
    h->flags |= READER_STARTED;

    // Check the stream for Byte Order Mark (BOM) and switch the encoding, if needed
    if ((encname = encoding_detect_byte_order(h->buf_raw, &had_bom)) != NULL) {
        if (!xml_reader_set_encoding(h, encname)) {
            xml_reader_message(h, XMLERR_NOTE, "(autodetected from %s)",
                    had_bom ? "Byte-order Mark" : "content");
            h->flags |= READER_FATAL;
            return;
        }
        xfree(h->enc_detected);
        h->enc_detected = xstrdup(encname);
    }

    // If no encoding passed from the transport layer, and autodetect didn't help,
    // try UTF-8. UTF-8 is built-in, so it should always work.
    if (!h->encoding) {
        if (!xml_reader_set_encoding(h, "UTF-8")) {
            OOPS_ASSERT(0);
        }
    }

    // Entities encoded in UTF-16 MUST and entities encoded in UTF-8 MAY
    // begin with the Byte Order Mark described in ISO/IEC 10646 [ISO/IEC
    // 10646] or Unicode [Unicode] (the ZERO WIDTH NO-BREAK SPACE character, #xFEFF).
    //
    // Note that we don't know the final encoding from the XML declaration at this
    // point, but if it different - it must be compatible and thus must have the same
    // encoding type.
    if (!had_bom && h->encoding->enctype == ENCODING_T_UTF16) {
        // Non-fatal: managed to detect the encoding somehow
        xml_reader_message(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                "UTF-16 encoding without byte-order mark");
    }

    // The selected encoding must not be "meta-encoding". If autodetect determined
    // such encoding, it's a bug.
    OOPS_ASSERT(h->encoding->xlate);

    // Record the encoding we've used initially
    cbparam.xmldecl.initial_encoding = h->encoding->name;

    // We should at least know the encoding type by now: whether it is 1/2/4-byte based,
    // and the endianness. Read and parse the XML/Text declaration, if any, and set
    // the final encoding as specified therein. Until then, though, we need to be careful
    // and read one character at a time; otherwise, we may assume a partially compatible
    // encoding and transcode too much.

    // We are looking for '<?xml' string, followed by XML whitespace
    h->flags |= READER_READDECL;
    for (i = 0; i < sizeofarray(xmldecl); i++) {
        if ((xmldecl[i] = xml_hdr_read_1(h)) == NOCHAR) {
            // We'll unget and retry with what we got as if it were regular XML content
            break;
        }
    }
    h->flags &= ~READER_READDECL;

    if (i == sizeofarray(xmldecl)
            && ucs4_equal(xmldecl, "<?xml", 5)
            && xml_is_whitespace(xmldecl[5])) {
        // We have a declaration; parse the rest of arguments (if any). XML spec only
        // allows ASCII characterts in the XMLDecl/TextDecl production: "The characters
        // #x85 and #x2028 cannot be reliably recognized and translated until an entity's
        // encoding declaration (if present) has been read. Therefore, it is a fatal error
        // to use them within the XML declaration or text declaration."
        cbparam.xmldecl.has_decl = true;
        xml_reader_xmldecl_getattr(h, &cbparam);
        h->buf_proc = strbuf_new(); // Consumed the declaration; start with empty buffer
    }
    else {
        // No declaration, "unget" the characters we've read.
        h->buf_proc = strbuf_new_from_memory(xmldecl, i * sizeof(uint32_t), true);
        strbuf_setf(h->buf_proc, 0, BUF_LAST); // Ops to get the rest will be set below
        h->loc.line = 1;
        h->loc.pos = 0;
    }

    // In the absence of external character encoding information (such as MIME
    // headers), parsed entities which are stored in an encoding other than UTF-8
    // or UTF-16 MUST begin with a text declaration (see 4.3.1 The Text Declaration)
    // containing an encoding declaration.
    if (!cbparam.xmldecl.encoding && !h->enc_transport
            && h->encoding->enctype != ENCODING_T_UTF16
            && h->encoding->enctype != ENCODING_T_UTF8) {
        // Non-fatal: recover by using whatever encoding we detected
        xml_reader_message(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                "No external encoding information, no encoding in %s, content in %s encoding",
                h->declinfo->name, h->encoding->name);
    }

    // If everything was alright so far, notify the application of the XML declaration
    // (either real or implied) and prepare for parsing the content after it.
    if ((h->flags & READER_FATAL) == 0) {

        // Emit an event (callback) for XML declaration
        xml_reader_invoke_callback(h, &cbparam);

        // Set operations for reading in the discovered encoding
        strbuf_setops(h->buf_proc, &xml_reader_translation_ops, h);
    }
}

/**
    Update the location information in the reader handle.

    @param h Reader handle
    @param nchars Number of characters in the readbuf
    @return Nothing
*/
static void
xml_update_location(xml_reader_t *h, size_t nchars)
{
}

/**
    Read until the specified condition; reallocate the buffer to accommodate
    the token being read as necessary.

    @param h Reader handle
    @param func Function to call to check for the condition
    @param arg Argument to @a func
    @return Number of bytes read (token length)
*/
static size_t
xml_read_until(xml_reader_t *h, strbuf_condread_func_t func, void *arg)
{
    size_t offs;

    offs = 0;
    while (true) {
        offs += strbuf_read_until(h->buf_proc, (uint8_t *)h->readbuf + offs,
                h->readbuf_sz - offs, false, func, arg);
        if (offs < h->readbuf_sz) {
            break; // Fits into current read buffer
        }
        // Reallocate bigger buffer and continue
        h->readbuf_sz *= 2;
        h->readbuf = xrealloc(h->readbuf, h->readbuf_sz);
    }
    // TBD copy to uint8_t * buffer
    // TBD normalization check
    // TBD EOL handling
    xml_update_location(h, offs / sizeof(uint32_t));
    return offs;
}

/**
    Closure for xml_read_until: read until first non-whitespace.

    @param arg Argument (unused)
    @param cp Codepoint
    @return True if byte is not XML whitespace
*/
static bool
xml_cb_not_whitespace(void *arg, uint32_t cp)
{
    return !xml_is_whitespace(cp);
}

/**
    Skip whitespace, if any, and check for the end-of-file (EOF) condition.

    @param h Reader handle
    @param true if after skipping whitespace, EOF is reached
*/
static bool
xml_eof_after_whitespace(xml_reader_t *h)
{
    (void)xml_read_until(h, xml_cb_not_whitespace, NULL);
    return strbuf_eof(h->buf_proc);
}

/**
    Read in the XML content from the document entity and emit the callbacks as necessary.

    @param h Reader handle
    @return None
*/
void
xml_reader_process_document_entity(xml_reader_t *h)
{
    /*
        Document entity matches the following productions per XML spec (1.1).
          document  ::= ( prolog element Misc* ) - ( Char* RestrictedChar Char* )
          prolog    ::= XMLDecl Misc* (doctypedecl Misc*)?
          Misc      ::= Comment | PI | S
        In XML spec 1.0, XMLDecl is optional. So, first get XMLDecl out of the way;
        this also sets the encoding and allows us to use auto-fill string buffer.
        We cannot use auto-fill buffer as it may look ahead in transcoding the input
        stream, and final encoding may not be known before parsing the XMLDecl.
    */
    h->declinfo = &declinfo_xmldecl;
    xml_reader_start(h);
    if (h->flags & READER_FATAL) {
        return; // TBD signal error somehow? or XMLERR(ERROR, ...) is enough?
    }

    /*
        Expanding the productions for the document (above), we get (for 1.0 or 1.1):
          document  ::= XMLDecl? (Comment|PI|S)* doctypedecl? (Comment|PI|S)* element
                        (Comment|PI|S)*
        We've handle XMLDecl, if there was any, above.
    */
    while (!xml_eof_after_whitespace(h)) { // TBD signal EOF from strbuf
        break; // TBD
    }

    // TBD process the rest of the content
}

/**
    Read in the XML content from an external parsed entity and emit the callbacks as necessary.

    @param h Reader handle
    @return None
*/
void
xml_reader_process_external_entity(xml_reader_t *h)
{
    h->declinfo = &declinfo_textdecl;
    xml_reader_start(h);
    if (h->flags & READER_FATAL) {
        return; // TBD signal error somehow? or XMLERR(ERROR, ...) is enough?
    }
    // TBD process the rest of the content
}

/**
    Process a DTD (external subset).

    @param h Reader handle
    @return None
*/
void
xml_reader_process_external_subset(xml_reader_t *h)
{
    h->declinfo = &declinfo_textdecl;
    xml_reader_start(h);
    if (h->flags & READER_FATAL) {
        return; // TBD signal error somehow? or XMLERR(ERROR, ...) is enough?
    }
    // TBD process the rest of the content
}
