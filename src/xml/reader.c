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
#define INITIAL_TOKENBUF_SIZE       1024

/**
    Size of storage for all element names, in hierarchical order as we descend into the
    document. Each time it is insufficient, it is doubled.
*/
#define INITIAL_NAMESTACK_SIZE      1024

/// Maximum number of characters to look ahead
#define MAX_LOOKAHEAD_SIZE          16

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

/// Tracking of element nesting
typedef struct xml_reader_nesting_s {
    /// Link for stack of nested elements
    SLIST_ENTRY(xml_reader_nesting_s) link;
    size_t offs;                    ///< Offset into name storage buffer
    size_t len;                     ///< Length of the element type
    void *baton;                    ///< Callback's baton associated with this element
    xmlerr_loc_t loc;               ///< Location of the element in the document
} xml_reader_nesting_t;

/// XML reader structure
struct xml_reader_s {
    const char *enc_transport;      ///< Encoding reported by transport protocol
    const char *enc_detected;       ///< Encoding detected by BOM or start characters
    const char *enc_xmldecl;        ///< Encoding declared in <?xml ... ?>
    encoding_handle_t *enc;         ///< Encoding used to transcode input
    strbuf_t *buf_raw;              ///< Raw input buffer (in document's encoding)
    strbuf_t *buf_proc;             ///< Processed input buffer (transcoded + translated)
    uint32_t flags;                 ///< Reader flags
    xmlerr_loc_t loc;               ///< Current reader's position
    const xml_reader_xmldecl_declinfo_t *declinfo;  ///< Expected declaration

    xml_reader_cb_t func;           ///< Callback function
    void *arg;                      ///< Argument to callback function

    uint8_t *tokenbuf;              ///< Token buffer
    uint8_t *tokenbuf_end;          ///< End of the token buffer
    uint8_t *tokenbuf_ptr;          ///< Write pointer in token buffer

    uint8_t *namestorage;           ///< Buffer for storing element types
    size_t namestorage_size;        ///< Size of the name storage buffer
    size_t namestorage_offs;        ///< Current offset into namestorage

    /// Stack of currently nested elements
    SLIST_HEAD(,xml_reader_nesting_s) elem_nested;

    /// List of free nesting tracker structures
    SLIST_HEAD(,xml_reader_nesting_s) elem_free;
};

/// Function for conditional read termination: returns true if the character is rejected
typedef bool (*xml_condread_func_t)(void *arg, uint32_t cp);

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
    encoding_handle_t *hndnew;

    if (encname != NULL) {
        if ((hndnew = encoding_open(encname)) == NULL) {
            xml_reader_message(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                    "Unsupported encoding '%s'", encname);
            return false;
        }
        if (!h->enc) {
            h->enc = hndnew;
            return true;
        }
        if (!encoding_switch(&h->enc, hndnew)) {
            // Replacing with an incompatible encoding is not possible;
            // the data that has been read previously cannot be trusted.
            xml_reader_message(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                    "Incompatible encodings: '%s' and '%s'",
                    encoding_name(h->enc), encname);
            return false;
        }
        return true;
    }
    else if (h->enc) {
        encoding_close(h->enc);
        h->enc = NULL;
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
    h->enc = NULL;
    h->buf_raw = buf;
    h->buf_proc = NULL;
    h->flags = 0;
    h->loc.src = xstrdup(location);
    h->loc.line = 1;
    h->loc.pos = 0;
    h->tokenbuf = xmalloc(INITIAL_TOKENBUF_SIZE);
    h->tokenbuf_end = h->tokenbuf + INITIAL_TOKENBUF_SIZE;
    h->tokenbuf_ptr = h->tokenbuf;
    h->namestorage_size = INITIAL_NAMESTACK_SIZE;
    h->namestorage_offs = 0;
    h->namestorage = xmalloc(INITIAL_NAMESTACK_SIZE);
    SLIST_INIT(&h->elem_nested);
    SLIST_INIT(&h->elem_free);
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
    xml_reader_nesting_t *n;

    (void)xml_reader_set_encoding(h, NULL);
    strbuf_delete(h->buf_raw);
    if (h->buf_proc) {
        strbuf_delete(h->buf_proc);
    }
    while ((n = SLIST_FIRST(&h->elem_nested)) != NULL) {
        SLIST_REMOVE_HEAD(&h->elem_nested, link);
        xfree(n);
    }
    while ((n = SLIST_FIRST(&h->elem_free)) != NULL) {
        SLIST_REMOVE_HEAD(&h->elem_free, link);
        xfree(n);
    }
    xfree(h->enc_transport);
    xfree(h->enc_detected);
    xfree(h->enc_xmldecl);
    xfree(h->loc.src);
    xfree(h->tokenbuf);
    xfree(h->namestorage);
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
    Report an error/warning/note for an arbitrary location in a handle.

    @param h Reader handle
    @param loc Location in the document
    @param info Error code
    @param fmt Message format
    @return Nothing
*/
void
xml_reader_message_loc(xml_reader_t *h, xmlerr_loc_t *loc, xmlerr_info_t info,
        const char *fmt, ...)
{
    xml_reader_cbparam_t cbparam = {
        .cbtype = XML_READER_CB_MESSAGE,
    };
    va_list ap;

    cbparam.message.loc = *loc;
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

    do {
        encoding_in_from_strbuf(h->enc, h->buf_raw, &ptr, ptr + 1);
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
    if (!tmp || tmp >= 0x7F || xml_is_restricted(tmp)) {
        // This is only error if we know declaration is present
        if ((h->flags & READER_READDECL) == 0) {
            xml_reader_message(h, h->declinfo->generr,
                    "%s contains non-ASCII or restricted characters", h->declinfo->name);
            h->flags |= READER_FATAL;
        }
        return NOCHAR;
    }

    /*
        XML processor MUST behave as if it normalized all line breaks in external
        parsed entities ...
    */
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
    Temporary transcoding operation: use lookahead instead of read on the
    input buffer, abort on non-ASCII characters. This mode is used during
    parsing of the XML declaration: until then, the actual encoding is not
    known yet.

    @param buf Input string buffer
    @param arg Pointer to state structure with 
    @return None
*/
//TBD

/**
    Fetch more data from the transcoder.

    @param buf Input string buffer 
    @param arg Reader handle (cast to void pointer)
    @return None
*/
static void
xml_reader_transcode_op_input(strbuf_t *buf, void *arg)
{
#define READ_BLOCK_CHARS   4096    // TBD increase?
    xml_reader_t *h = arg;
    uint32_t *bptr, *cptr, *eptr;
    strblk_t *blk;

    blk = strblk_new(READ_BLOCK_CHARS * sizeof(uint32_t));
    cptr = bptr = strblk_getptr(blk);
    eptr = bptr + READ_BLOCK_CHARS;
    encoding_in_from_strbuf(h->enc, h->buf_raw, &cptr, eptr);
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
xml_reader_transcode_op_destroy(strbuf_t *buf, void *arg)
{
    // No-op
}

static const strbuf_ops_t xml_reader_transcode_ops = {
    .input = xml_reader_transcode_op_input,
    .destroy = xml_reader_transcode_op_destroy,
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
    uint8_t adbuf[4];       // 4 bytes for encoding detection, per XML spec suggestion
    uint32_t xmldecl[6];
    size_t i, bom_len, adsz;
    const char *encname;
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

    // Try to get the encoding from stream and check for BOM
    adsz = strbuf_read(h->buf_raw, adbuf, sizeof(adbuf), true);
    if ((encname = encoding_detect(adbuf, adsz, &bom_len)) != NULL) {
        if (!xml_reader_set_encoding(h, encname)) {
            xml_reader_message(h, XMLERR_NOTE, "(autodetected from %s)",
                    bom_len ? "Byte-order Mark" : "content");
            h->flags |= READER_FATAL;
            return;
        }
        xfree(h->enc_detected);
        h->enc_detected = xstrdup(encname);
    }

    // If byte order mark (BOM) was detected, consume it
    if (bom_len) {
        // TBD check if any strbuf_read calls remain with dest!=NULL && lookahead==false
        // TBD if not, maybe have a simple strbuf_advance() instead?
        strbuf_read(h->buf_raw, NULL, bom_len, false);
    }

    // If no encoding passed from the transport layer, and autodetect didn't help,
    // try UTF-8. UTF-8 is built-in, so it should always work.
    if (!h->enc && !xml_reader_set_encoding(h, "UTF-8")) {
        OOPS_ASSERT(0);
    }

    // Record the encoding we've used initially
    cbparam.xmldecl.initial_encoding = encoding_name(h->enc);

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

    // Entities encoded in UTF-16 MUST and entities encoded in UTF-8 MAY
    // begin with the Byte Order Mark described in ISO/IEC 10646 [ISO/IEC
    // 10646] or Unicode [Unicode] (the ZERO WIDTH NO-BREAK SPACE character, #xFEFF).
    //
    // Errata: The terms "UTF-8" and "UTF-16" in this specification do not apply to
    // related character encodings, including but not limited to UTF-16BE, UTF-16LE,
    // or CESU-8.
    //
    // Note that we don't know the final encoding from the XML declaration at this
    // point, but if it different - it must be compatible and thus must have the same
    // encoding type.
    if (!bom_len && h->enc_xmldecl
            && !strcmp(h->enc_xmldecl, "UTF-16")) {
        // Non-fatal: managed to detect the encoding somehow
        xml_reader_message(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                "UTF-16 encoding without byte-order mark");
    }

    // In the absence of external character encoding information (such as MIME
    // headers), parsed entities which are stored in an encoding other than UTF-8
    // or UTF-16 MUST begin with a text declaration (see 4.3.1 The Text Declaration)
    // containing an encoding declaration.
    //
    // Errata: The terms "UTF-8" and "UTF-16" in this specification do not apply to
    // related character encodings, including but not limited to UTF-16BE, UTF-16LE,
    // or CESU-8.
    if (!cbparam.xmldecl.encoding && !h->enc_transport
            && strcmp(encoding_name(h->enc), "UTF-16")
            && strcmp(encoding_name(h->enc), "UTF-8")) {
        // Non-fatal: recover by using whatever encoding we detected
        xml_reader_message(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                "No external encoding information, no encoding in %s, content in %s encoding",
                h->declinfo->name, encoding_name(h->enc));
    }

    // If everything was alright so far, notify the application of the XML declaration
    // (either real or implied) and prepare for parsing the content after it.
    if ((h->flags & READER_FATAL) == 0) {

        // Emit an event (callback) for XML declaration
        xml_reader_invoke_callback(h, &cbparam);

        // Set operations for reading in the discovered encoding
        strbuf_setops(h->buf_proc, &xml_reader_transcode_ops, h);
    }
}

/**
    Look ahead in the parsed stream without advancing the current read location.
    Stops on a non-ASCII character; all mark-up (that requires look-ahead) is
    using ASCII characters.

    @param h Reader handle
    @param buf Buffer to read into
    @param bufsz Buffer size
    @return Number of characters read
*/
static size_t
xml_lookahead(xml_reader_t *h, uint8_t *buf, size_t bufsz)
{
    uint32_t tmp[MAX_LOOKAHEAD_SIZE];
    const uint32_t *ptr = tmp;
    size_t i, nread;

    OOPS_ASSERT(bufsz <= MAX_LOOKAHEAD_SIZE);
    nread = strbuf_read(h->buf_proc, tmp, bufsz * sizeof(uint32_t), true);
    OOPS_ASSERT((nread & 3) == 0); // h->buf_proc must have an integral number of characters
    nread /= 4;
    for (i = 0; i < nread; i++) {
        if (*ptr >= 0x7F) {
            break; // Non-ASCII
        }
        *buf++ = *ptr++;
    }

    return i;
}

/**
    Read until the specified condition; reallocate the buffer to accommodate
    the token being read as necessary. Perform whitespace/EOL handling prescribed
    by the XML spec; check normalization if needed.

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

    @param h Reader handle
    @param func Function to call to check for the condition
    @param arg Argument to @a func
    @return Number of bytes read (token length)
*/
static size_t
xml_read_until(xml_reader_t *h, xml_condread_func_t func, void *arg)
{
    const void *begin, *end;
    const uint32_t *ptr;
    uint32_t cp;
    size_t total, clen, offs, bufsz;

    total = 0;
    h->tokenbuf_ptr = h->tokenbuf;
    while (strbuf_getptr(h->buf_proc, &begin, &end)) {
        for (ptr = begin; ptr < (const uint32_t *)end; ptr++) {
            cp = *ptr;
            if (func(arg, cp)) {
                strbuf_read(h->buf_proc, NULL,
                        (ptr - (const uint32_t *)begin) * sizeof(uint32_t), false);
                return total; // Early return: next character is rejected
            }
            // TBD normalization check
            // TBD EOL handling
            // TBD update location
            // TBD check for whitespace and set a flag in reader for later detection of ignorable
            // (via the argument - when reading chardata, point to a structure that has such flag)
            // TBD if in DTD, and not parsing a literal/comment/PI - recognize parameter entities
            clen = encoding_utf8_len(cp);
            if (h->tokenbuf_ptr + clen > h->tokenbuf_end) {
                // Double token storage
                offs = h->tokenbuf_ptr - h->tokenbuf;
                bufsz = 2 * (h->tokenbuf_end - h->tokenbuf);
                h->tokenbuf = xrealloc(h->tokenbuf, bufsz);
                h->tokenbuf_end = h->tokenbuf + bufsz;
                h->tokenbuf_ptr = h->tokenbuf + offs;
            }
            encoding_utf8_store(&h->tokenbuf_ptr, cp);
            total += clen;
        }
        // Consumed this block
        strbuf_read(h->buf_proc, NULL, (const uint8_t *)end - (const uint8_t *)begin, false);
    }
    return total; // Consumed all input
}

/**
    Closure for xml_read_until: read until first non-whitespace.

    @param arg Argument (unused)
    @param cp Codepoint
    @return True if @a cp is not XML whitespace
*/
static bool
xml_cb_not_whitespace(void *arg, uint32_t cp)
{
    return !xml_is_whitespace(cp);
}

/**
    Closure for xml_read_until: read until < (left angle bracket)

    @param arg Argument (unused)
    @param cp Codepoint
    @return True if @a cp is left angle bracket
*/
static bool
xml_cb_lt(void *arg, uint32_t cp)
{
    return xchareq(cp, '<');
}

/**
    Closure for xml_read_until: read until > (right angle bracket); consume the
    bracket as well.

    @param arg Argument (unused)
    @param cp Codepoint
    @return True if @a cp is left angle bracket
*/
static bool
xml_cb_gt(void *arg, uint32_t cp)
{
    bool *saw_gt = arg;

    if (*saw_gt) {
        return true;
    }
    else if (xchareq(cp, '>')) {
        *saw_gt = true;
    }
    return false;
}

/**
    Recovery function: read until (and including) the next right angle bracket.

    @param h Reader handle
    @return Nothing
*/
static void
xml_read_until_gt(xml_reader_t *h)
{
    bool saw_gt = false;

    (void)xml_read_until(h, xml_cb_gt, &saw_gt);
}

/**
    Closure for xml_read_until: read a Name production.

    NameStartChar ::= ":" | [A-Z] | "_" | [a-z] | [#xC0-#xD6] | [#xD8-#xF6] |
                       [#xF8-#x2FF] | [#x370-#x37D] | [#x37F-#x1FFF] |
                       [#x200C-#x200D] | [#x2070-#x218F] | [#x2C00-#x2FEF] |
                       [#x3001-#xD7FF] | [#xF900-#xFDCF] | [#xFDF0-#xFFFD] |
                       [#x10000-#xEFFFF]
    NameChar ::= NameStartChar | "-" | "." | [0-9] | #xB7 | [#x0300-#x036F] |
                 [#x203F-#x2040]
    Name ::= NameStartChar (NameChar)*

    @param arg Pointer to a boolean: true if first character.
    @return True if the next character does not belong to Name production
*/
static bool
xml_cb_not_name(void *arg, uint32_t cp)
{
    bool startchar;

    startchar = *(bool *)arg;
    *(bool *)arg = false; // Next character will not be starting

    // Most XML documents use ASCII for element types. So, check ASCII
    // characters first.
    if (xcharin(cp, 'A', 'Z') || xcharin(cp, 'a', 'z') || xchareq(cp, '_') || xchareq(cp, ':')
            || (!startchar && (xchareq(cp, '-') || xchareq(cp, '.') || xcharin(cp, '0', '9')))) {
        return false; // Good, keep on reading
    }

    // The rest of valid start characters
    if ((xcharin(cp, 0xC0, 0x2FF) && !xchareq(cp, 0xD7) && !xchareq(cp, 0xF7))
            || (xcharin(cp, 0x370, 0x1FFF) && !xchareq(cp, 0x37E))
            || xcharin(cp, 0x200C, 0x200D)
            || xcharin(cp, 0x2070, 0x218F)
            || xcharin(cp, 0x2C00, 0x2FEF)
            || xcharin(cp, 0x3001, 0xD7FF)
            || xcharin(cp, 0xF900, 0xFDCF)
            || xcharin(cp, 0xFDF0, 0xFFFD)
            || xcharin(cp, 0x10000, 0xEFFFF)) {
        return false; // Keep on
    }
    if (startchar) {
        return true; // Stop: this is not a valid start character
    }
    if (xchareq(cp, 0xB7)
            || xcharin(cp, 0x0300, 0x036F)
            || xcharin(cp, 0x203F, 0x2040)) {
        return false; // Keep on, this is valid continuation char
    }
    return true; // Stop: not valid even as continuation
}

/**
    Read a Name production.

    @param h Reader handle
    @return Length of the token read (token is placed in h->tokenbuf)
*/
static size_t
xml_read_Name(xml_reader_t *h)
{
    bool startchar = true;

    return xml_read_until(h, xml_cb_not_name, &startchar);
}

/// Current state structure for xml_cb_string
typedef struct xml_cb_string_state_s {
    const char *expect;         ///< Expected string, full
    const char *cur;            ///< Currently expected character
    const char *end;            ///< End of the expected string
} xml_cb_string_state_t;

/**
    Closure for xml_read_until: read and compare to a known string. Matched string
    must contain only ASCII characters.

    @param arg Current matching state
    @param cp Codepoint
    @return True if saw the whole string (normal termination) or found a mismatch
        (abnormal termination)
*/
static bool
xml_cb_string(void *arg, uint32_t cp)
{
    xml_cb_string_state_t *state = arg;
    unsigned char tmp;

    if (state->cur == state->end
            || (tmp = *(const unsigned char *)state->cur) >= 0x7F
            || tmp != cp) {
        return true;
    }
    state->cur++;
    return false; // Matches expected character, go on
}

/**
    Read an expected string.

    @param h Reader handle
    @param s String expected in the document; must be ASCII-only
    @param errinfo Error to raise on mismatch
    @return true if matched string was read
*/
static bool
xml_read_string(xml_reader_t *h, const char *s, xmlerr_info_t errinfo)
{
    xml_cb_string_state_t state;
    size_t len;

    len = strlen(s);
    state.expect = state.cur = s;
    state.end = state.expect + len;
    if (len != xml_read_until(h, xml_cb_string, &state)) {
        xml_reader_message(h, errinfo,
                "Expected string: '%s'", s);
        return false;
    }
    return true;
}

/**
    Read and process a single XML comment, starting with <!-- and ending with -->.

    @param h Reader handle
    @return Nothing
*/
static void
xml_parse_comment(xml_reader_t *h)
{
    // TBD
    xml_read_until_gt(h);
}

/**
    Read and process a processing instruction, starting with <? and ending with ?>.

    @param h Reader handle
    @return Nothing
*/
static void
xml_parse_pi(xml_reader_t *h)
{
    // TBD
    xml_read_until_gt(h);
}

/**
    Read and process a document type declaration; the declaration may reference
    an external subset and contain an internal subset, or have both, or none.

    @param h Reader handle
    @return Nothing
*/
static void
xml_parse_doctypedecl(xml_reader_t *h)
{
    // TBD
    xml_read_until_gt(h);
}

/**
    Push a name onto a stack of nested elements.

    @param h Reader handle
    @return Nesting tracker structure for this element
*/
static xml_reader_nesting_t *
xml_elemtype_push(xml_reader_t *h)
{
    xml_reader_nesting_t *n;
    const uint8_t *name = h->tokenbuf;
    size_t len = h->tokenbuf_ptr - h->tokenbuf;

    // Allocate tracking structure
    if ((n = SLIST_FIRST(&h->elem_free)) != NULL) {
        SLIST_REMOVE_HEAD(&h->elem_free, link);
    }
    else {
        n = xmalloc(sizeof(xml_reader_nesting_t));
    }

    // Adjust buffer size if needed
    while (h->namestorage_offs + len > h->namestorage_size) {
        h->namestorage_size *= 2;
        xrealloc(h->namestorage, h->namestorage_size);
    }
    n->offs = h->namestorage_offs;
    n->len = len;
    n->loc = h->loc;
    memcpy(&h->namestorage[n->offs], name, len);
    h->namestorage_offs += len;
    SLIST_INSERT_HEAD(&h->elem_nested, n, link);
    return n;
}

/**
    Pop a name from a stack of nested elements and compare it against the name
    provided by caller.

    @param h Reader handle
    @return Baton from the nesting tracker
*/
static void *
xml_elemtype_pop(xml_reader_t *h)
{
    xml_reader_nesting_t *n;
    const uint8_t *name = h->tokenbuf;
    size_t len = h->tokenbuf_ptr - h->tokenbuf;

    n = SLIST_FIRST(&h->elem_nested);
    OOPS_ASSERT(n);
    SLIST_REMOVE_HEAD(&h->elem_nested, link);
    if (len != n->len || memcmp(&h->namestorage[n->offs], name, len)) {
        xml_reader_message(h, XMLERR(ERROR, XML, WFC_ELEMENT_TYPE_MATCH),
                "Closing element type mismatch: '%.*s'", (int)len, name);
        xml_reader_message_loc(h, &n->loc, XMLERR_NOTE,
                "Opening element: '%.*s'", (int)n->len, &h->namestorage[n->offs]);
    }
    h->namestorage_offs = n->offs;
    SLIST_INSERT_HEAD(&h->elem_free, n, link);
    return n->baton;
}

/**
    Drop a name tracker structure without checking for name match.

    @param h Reader handle
    @return Nothing
*/
static void
xml_elemtype_drop(xml_reader_t *h)
{
    xml_reader_nesting_t *n;

    n = SLIST_FIRST(&h->elem_nested);
    OOPS_ASSERT(n);
    SLIST_REMOVE_HEAD(&h->elem_nested, link);
    h->namestorage_offs = n->offs;
    SLIST_INSERT_HEAD(&h->elem_free, n, link);
}

/**
    Read and process STag/EmptyElemTag productions.
    Both productions are the same with the exception of the final part:

    STag         ::= '<' Name (S Attribute)* S? '>'
    EmptyElemTag ::= '<' Name (S Attribute)* S? '/>'
    Attribute    ::= Name Eq AttValue
    AttValue     ::= '"' ([^<&"] | Reference)* '"' | "'" ([^<&'] | Reference)* "'"
    Eq           ::= S? '=' S?

    @param h Reader handle
    @param is_empty Pointer to boolean; set to true if the production was EmptyElemTag
    @return Nothing
*/
static void
xml_parse_STag_EmptyElemTag(xml_reader_t *h, bool *is_empty)
{
    xml_reader_cbparam_t cbp;
    xml_reader_nesting_t *n;
    uint8_t la;
    size_t len;

    // For recovery, assume the element has no content in case of error return.
    *is_empty = true;

    if (!xml_read_string(h, "<", XMLERR(ERROR, XML, P_STag))) {
        OOPS_ASSERT(0); // This function should not be called unless looked ahead
    }

    if ((len = xml_read_Name(h)) == 0) {
        // No valid name - try to recover by skipping until closing bracket
        xml_reader_message(h, XMLERR(ERROR, XML, P_STag),
                "Expected element type");
        xml_read_until_gt(h);
        return;
    }

    // Notify the application that a new element has started
    n = SLIST_FIRST(&h->elem_nested);
    cbp.cbtype = XML_READER_CB_STAG;
    cbp.stag.type = (const char *)h->tokenbuf; // TBD remove cast, use xml_char_t typedef
    cbp.stag.typelen = len;
    cbp.stag.parent = n ? n->baton : NULL;
    cbp.stag.baton = NULL;
    xml_reader_invoke_callback(h, &cbp);

    // Remember the element type for wellformedness check in closing tag; save baton from callback
    n = xml_elemtype_push(h);
    n->baton = cbp.stag.baton;

    while (true) {
        len = xml_read_until(h, xml_cb_not_whitespace, NULL);
        if (xml_lookahead(h, &la, 1) != 1) {
            xml_reader_message(h, XMLERR(ERROR, XML, P_STag),
                    "Element start tag truncated");
            return;
        }
        if (xchareq(la, '/')) {
            if (!xml_read_string(h, "/>", XMLERR(ERROR, XML, P_STag))) {
                // Try to recover by reading till end of opening tag
                xml_read_until_gt(h);
            }
            cbp.cbtype = XML_READER_CB_ETAG;
            cbp.etag.type = (const char *)&h->namestorage[n->offs];
            cbp.etag.typelen = n->len;
            cbp.etag.baton = n->baton;
            cbp.etag.is_empty = true;
            xml_reader_invoke_callback(h, &cbp);
            xml_elemtype_drop(h);
            *is_empty = true;
            return;
        }
        else if (xchareq(la, '>')) {
            if (!xml_read_string(h, ">", XMLERR(ERROR, XML, P_STag))) {
                OOPS_ASSERT(0); // Cannot fail - we looked ahead
            }
            *is_empty = false;
            return;
        }
        else if (len && (len = xml_read_Name(h)) != 0) {
            // Attribute, if any, must be preceded by S (whitespace)
            // TBD: read attributes - wrap this condition in a loop
        }
        else {
            // Try to recover by reading till end of opening tag
            xml_reader_message(h, XMLERR(ERROR, XML, P_STag),
                    "Expect whitespace, or >, or />");
            xml_read_until_gt(h);
            return;
        }
    }
}

/**
    Read and process ETag production.

    ETag ::= '</' Name S? '>'

    Additionally, Name in ETag must match the element type in STag.

    @param h Reader handle
    @return Nothing
*/
static void
xml_parse_ETag(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;
    size_t len;

    if (!xml_read_string(h, "</", XMLERR(ERROR, XML, P_ETag))) {
        OOPS_ASSERT(0); // This function should not be called unless looked ahead
    }
    if ((len = xml_read_Name(h)) == 0) {
        // No valid name - try to recover by skipping until closing bracket
        xml_reader_message(h, XMLERR(ERROR, XML, P_ETag),
                "Expected element type");
        xml_read_until_gt(h);
        return;
    }
    cbp.cbtype = XML_READER_CB_ETAG;
    cbp.stag.type = (const char *)h->tokenbuf; // TBD remove cast, use xml_char_t typedef
    cbp.stag.typelen = len;
    cbp.etag.baton = xml_elemtype_pop(h);
    cbp.etag.is_empty = false;
    xml_reader_invoke_callback(h, &cbp);

    (void)xml_read_until(h, xml_cb_not_whitespace, NULL);
    if (!xml_read_string(h, ">", XMLERR(ERROR, XML, P_ETag))) {
        // No valid name - try to recover by skipping until closing bracket
        xml_read_until_gt(h);
    }
}

/**
    Read and process a content production.

    content ::= CharData? ((element | Reference | CDSect | PI | Comment) CharData?)*
    element ::= EmptyElemTag | STag content ETag

    Note that content is a recursive production: it may contain element, which in turn
    may contain content. We are processing this in a flat way (substituting loop for
    recursion); instead, we record the element types we saw in a LIFO list and only
    apply ETag if we have a matching STag.

    @param h Reader handle
    @return Nothing
*/
static void
xml_parse_content(xml_reader_t *h)
{
    // TBD
}

/**
    Read and process a single element. This is used by document entity parser;
    the other parsers should use xml_parse_content() instead.

    @param h Reader handle
    @return Nothing
*/
static void
xml_parse_element(xml_reader_t *h)
{
    bool is_empty_element;
    uint8_t labuf[2];

    xml_parse_STag_EmptyElemTag(h, &is_empty_element);
    if (!is_empty_element) {
        xml_parse_content(h);
        if (xml_lookahead(h, labuf, 2) < 2) {
            xml_reader_message(h, XMLERR(ERROR, XML, P_element),
                    "Root element end tag missing");
            return;
        }
        // xml_parse_content() should not have returned otherwise
        OOPS_ASSERT(xchareq(labuf[0], '<') && xchareq(labuf[1], '/'));
        xml_parse_ETag(h);
    }
}

/**
    Read in the XML content from the document entity and emit the callbacks as necessary.

    @param h Reader handle
    @return None
*/
void
xml_reader_process_document_entity(xml_reader_t *h)
{
    uint8_t labuf[4]; // Lookahead buffer
    bool seen_dtd = false;
    bool seen_element = false;

    /*
        Document entity matches the following productions per XML spec (1.1).
          document  ::= ( prolog element Misc* ) - ( Char* RestrictedChar Char* )
          prolog    ::= XMLDecl Misc* (doctypedecl Misc*)?
          Misc      ::= Comment | PI | S
        In XML spec 1.0, XMLDecl is optional.

        Expanding the productions for the document (above), we get (for 1.0 or 1.1):
          document  ::= XMLDecl? (Comment|PI|S)* doctypedecl? (Comment|PI|S)* element
                        (Comment|PI|S)*

        First get XMLDecl out of the way; this also sets the encoding and allows us
        to use auto-fill string buffer.  We cannot use auto-fill buffer for XMLDecl
        as it may look ahead in transcoding the input stream, and final encoding may
        not be known before parsing the XMLDecl.  After XMLDecl, aside from whitespace
        we expect:
        - Comments
        - PIs
        - Document type declaration (only one and only if we haven't seen element yet)
        - Element (only one)
        After we're done, check if we have seen an element and raise an error otherwise.
    */
    h->declinfo = &declinfo_xmldecl;
    xml_reader_start(h);
    while ((h->flags & READER_FATAL) == 0) {
        (void)xml_read_until(h, xml_cb_not_whitespace, NULL); // Skip whitespace if any
        memset(labuf, 0, sizeof(labuf));
        if (xml_lookahead(h, labuf, 4) == 0) {
            break; // No more input
        }
        if (labuf[0] == '<') {
            // Comment, PI, doctypedecl and element all start with '<'
            if (labuf[1] == '!') {
                // Comment or doctypedecl
                if (labuf[2] == '-' && labuf[3] == '-') {
                    xml_parse_comment(h);
                }
                else if (!seen_dtd && !seen_element) {
                    // DTD may not follow element.
                    xml_parse_doctypedecl(h);
                    seen_dtd = true;
                }
                else {
                    // Recover by reading up until closing angle bracket
                    xml_reader_message(h, XMLERR(ERROR, XML, P_document),
                            "Document type definition not allowed here");
                    xml_read_until_gt(h);
                }
            }
            else if (labuf[1] == '?') {
                xml_parse_pi(h);
            }
            else {
                if (seen_element) {
                    // Recover by reading the element, even if there are multiple roots
                    xml_reader_message(h, XMLERR(ERROR, XML, P_document),
                            "One root element allowed in a document");
                }
                xml_parse_element(h);
                seen_element = true;
            }
        }
        else {
            // Recover by reading up until next left angle bracket
            xml_reader_message(h, XMLERR(ERROR, XML, P_document),
                    "Invalid content at root level");
            (void)xml_read_until(h, xml_cb_lt, NULL);
        }
    }

    // Skip checking for certain errors if reading was aborted prematurely
    if ((h->flags & READER_FATAL) == 0) {
        if (!seen_element) {
            xml_reader_message(h, XMLERR(ERROR, XML, P_document),
                    "No root element");
        }
        if (!encoding_clean(h->enc)) {
            xml_reader_message(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                    "Partial characters at end of input");
        }
    }
}

/**
    Read in the XML content from an external parsed entity and emit the callbacks
    as necessary.

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
