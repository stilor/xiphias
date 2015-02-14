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

/**
    Initial lookahead buffer size for parsing XML declaration. Each time it is
    insufficient, it is doubled.
*/
#define INITIAL_DECL_LOOKAHEAD_SIZE 64

/// Maximum number of characters to look ahead
#define MAX_LOOKAHEAD_SIZE          16

/// Reader flags
enum {
    READER_STARTED  = 0x0001,       ///< Reader has started the operation
    READER_FATAL    = 0x0002,       ///< Reader encountered a fatal error
    READER_SAW_CR   = 0x0004,       ///< Converting CRLF: saw 0xD, ignore next 0xA/0x85
    READER_POS_RESET= 0x0008,       ///< Reset position before reading the next char
    READER_ASCII    = 0x0010,       ///< Only ASCII characters allowed while reading declaration
};

/// Used as an indicator that no character was read
#define NOCHAR      ((uint32_t)-1)

/// Used as a sentinel code
#define STOPCHAR    ((uint32_t)-2)

/// OR'ed by conditional read functions to indicate a stop after the current character
#define LASTCHAR    (0x80000000)

/**
    XML declaration comes in two flavors, XMLDecl and TextDecl, with different
    set of allowed/mandatory/optional attributes. This structure describes an
    attribute in the expected list.
*/
typedef struct xml_reader_xmldecl_attrdesc_s {
    const char *name;       ///< Name of the attribute
    bool mandatory;         ///< True if the attribute is mandatory

    /// Value validation function
    void (*check)(xml_reader_t *h, xml_reader_cbparam_t *cbp);
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
    enum xml_info_version_e parser_version;         ///< Version assumed when parsing

    xml_reader_cb_t func;           ///< Callback function
    void *arg;                      ///< Argument to callback function

    uint8_t *tokenbuf;              ///< Token buffer
    uint8_t *tokenbuf_end;          ///< End of the token buffer
    size_t tokenbuf_len;            ///< Length of the token in the buffer

    uint8_t *namestorage;           ///< Buffer for storing element types
    size_t namestorage_size;        ///< Size of the name storage buffer
    size_t namestorage_offs;        ///< Current offset into namestorage

    /// Stack of currently nested elements
    SLIST_HEAD(,xml_reader_nesting_s) elem_nested;

    /// List of free nesting tracker structures
    SLIST_HEAD(,xml_reader_nesting_s) elem_free;
};

/// Function for conditional read termination: returns true if the character is rejected
typedef uint32_t (*xml_condread_func_t)(void *arg, uint32_t cp);

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
    return xuchareq(cp, 0x20) || xuchareq(cp, 0x9) || xuchareq(cp, 0xA)
            || xuchareq(cp, 0xD);
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
    h->tokenbuf_len = 0;
    h->namestorage_size = INITIAL_NAMESTACK_SIZE;
    h->namestorage_offs = 0;
    h->namestorage = xmalloc(INITIAL_NAMESTACK_SIZE);
    h->parser_version = XML_INFO_VERSION_1_0; // Until we read a different version
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

/// State structure for input ops while parsing the declaration
typedef struct xml_reader_initial_xcode_s {
    xml_reader_t *h;            ///< Reader handle
    uint8_t *la_start;          ///< Start of the lookahead buffer
    size_t la_size;             ///< Size of the lookahead buffer
    size_t la_avail;            ///< Size of data available in buffer
    size_t la_offs;             ///< Current lookahead offset

    /// First attempt to have the buffer on the stack
    uint8_t initial[INITIAL_DECL_LOOKAHEAD_SIZE];
} xml_reader_initial_xcode_t;

/**
    Temporary transcoding operation: use lookahead instead of read on the
    input buffer, abort on non-ASCII characters. This mode is used during
    parsing of the XML declaration: until then, the actual encoding is not
    known yet.

    @param buf Input string buffer
    @param arg Pointer to state structure with 
    @return None
*/
static size_t
xml_reader_initial_op_more(void *arg, void *begin, size_t sz)
{
    xml_reader_initial_xcode_t *xc = arg;
    xml_reader_t *h = xc->h;
    uint32_t *cptr, *bptr;

    OOPS_ASSERT(sz >= 4 && (sz & 3) == 0); // Reading in 32-bit blocks
    bptr = cptr = begin;
    do {
        if (xc->la_offs == xc->la_avail) {
            // Need to read more data into the buffer ...
            if (xc->la_avail == xc->la_size) {
                // ... but need to grow the buffer first
                if (xc->la_start != xc->initial) {
                    // Don't bother with realloc: we're going to read from start anyway
                    xfree(xc->la_start);
                }
                xc->la_size *= 2;
                xc->la_start = xmalloc(xc->la_size);
            }
            xc->la_avail = strbuf_lookahead(h->buf_raw, xc->la_start, xc->la_size);
            if (xc->la_offs == xc->la_avail) {
                return 0; // Despite our best efforts... got no new data
            }
        }
        // Transcode a single UCS-4 code point
        xc->la_offs += encoding_in(h->enc, xc->la_start + xc->la_offs,
                xc->la_start + xc->la_avail, &cptr, bptr + 1);

        // If reading did not produce a character (was absorbed by encoding
        // state), repeat - possibly reading more
    } while (cptr == bptr);

    OOPS_ASSERT(cptr == bptr + 1); // Must have 1 character
    return sizeof(uint32_t);
}

/// Operations for transcoding XMLDecl/TextDecl
static const strbuf_ops_t xml_reader_initial_ops = {
    .more = xml_reader_initial_op_more,
};

/**
    Fetch more data from the transcoder.

    @param arg Reader handle (cast to void pointer)
    @return None
*/
static size_t
xml_reader_transcode_op_more(void *arg, void *begin, size_t sz)
{
    xml_reader_t *h = arg;
    uint32_t *bptr, *cptr, *eptr;

    bptr = cptr = begin;
    eptr = bptr + sz / sizeof(uint32_t);
    encoding_in_from_strbuf(h->enc, h->buf_raw, &cptr, eptr);
    return (cptr - bptr) * sizeof(uint32_t);
}

/// Operations for transcoding after parsing the XMLDecl/TextDecl
static const strbuf_ops_t xml_reader_transcode_ops = {
    .more = xml_reader_transcode_op_more,
};

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
    nread = strbuf_lookahead(h->buf_proc, tmp, bufsz * sizeof(uint32_t));
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
    size_t clen, offs, bufsz, total;
    uint8_t *bufptr;
    bool stop = false;

    bufptr = h->tokenbuf;
    total = 0;
    while (!stop && strbuf_rptr(h->buf_proc, &begin, &end)) {
        for (ptr = begin; !stop && ptr < (const uint32_t *)end; ptr++) {
            cp = *ptr;
            if (!cp) {
                // Non-fatal: recover by skipping the character
                xml_reader_message(h, XMLERR(ERROR, XML, P_Char),
                        "NUL character encountered");
                continue;
            }
            if (cp >= 0x7F && (h->flags & READER_ASCII) != 0) {
                // Only complain once
                h->flags &= ~READER_ASCII;
                xml_reader_message(h, h->declinfo->generr,
                        "Non-ASCII characters in %s", h->declinfo->name);
            }
            if (xml_is_restricted(cp)) {
                // Non-fatal: just let the app figure what to do with it
                xml_reader_message(h, XMLERR(ERROR, XML, P_Char),
                        "Restricted character");
            }
            // TBD substitute character references if requested - need to happen before normcheck
            // TBD normalization check
            // TBD EOL handling
            // TBD update location
            // TBD check for whitespace and set a flag in reader for later detection of ignorable
            // (via the argument - when reading chardata, point to a structure that has such flag)
            // TBD if in DTD, and not parsing a literal/comment/PI - recognize parameter entities
            if ((cp = func(arg, *ptr)) == STOPCHAR) {
                stop = true;
                break; // This character is rejected
            }
            if (cp == NOCHAR) {
                continue; // Ignored
            }
            if (cp & LASTCHAR) {
                stop = true; // This character is accepted but is known to be the last
                cp &= ~LASTCHAR;
            }
            clen = encoding_utf8_len(cp);
            if (bufptr + clen > h->tokenbuf_end) {
                // Double token storage
                offs = bufptr - h->tokenbuf;
                bufsz = 2 * (h->tokenbuf_end - h->tokenbuf);
                h->tokenbuf = xrealloc(h->tokenbuf, bufsz);
                h->tokenbuf_end = h->tokenbuf + bufsz;
                bufptr = h->tokenbuf + offs;
            }
            encoding_utf8_store(&bufptr, cp);
            total += clen;
        }
        // Consumed this block
        strbuf_radvance(h->buf_proc, (const uint8_t *)ptr - (const uint8_t *)begin);
    }
    h->tokenbuf_len = total;
    return total; // Consumed all input
}

/**
    Closure for xml_read_until: read until first non-whitespace.

    @param arg Argument (unused)
    @param cp Codepoint
    @return STOPCHAR if @a cp is whitespace, @a cp otherwise
*/
static uint32_t
xml_cb_not_whitespace(void *arg, uint32_t cp)
{
    return !xml_is_whitespace(cp) ? STOPCHAR : cp;
}

/// Consume whitespace
#define xml_read_whitespace(h) xml_read_until(h, xml_cb_not_whitespace, NULL)

/**
    Closure for xml_read_until: read until < (left angle bracket)

    @param arg Argument (unused)
    @param cp Codepoint
    @return STOPCHAR if @a cp is left angle bracket, @a cp otherwise
*/
static uint32_t
xml_cb_lt(void *arg, uint32_t cp)
{
    return xuchareq(cp, '<') ? STOPCHAR : cp;
}

/// Consume until next opening bracket
#define xml_read_until_lt(h) xml_read_until(h, xml_cb_lt, NULL)

/**
    Closure for xml_read_until: read until > (right angle bracket); consume the
    bracket as well.

    @param arg Argument (unused)
    @param cp Codepoint
    @return STOPCHAR if @a cp is next char after a right angle bracket,
        @a cp otherwise
*/
static uint32_t
xml_cb_gt(void *arg, uint32_t cp)
{
    return cp | (xuchareq(cp, '>') ? LASTCHAR : 0);
}

/**
    Recovery function: read until (and including) the next right angle bracket.

    @param h Reader handle
    @return Nothing
*/
#define xml_read_until_gt(h) xml_read_until(h, xml_cb_gt, NULL)

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
    @return STOPCHAR if the character does not belong to Name production
*/
static uint32_t
xml_cb_not_name(void *arg, uint32_t cp)
{
    bool startchar;

    startchar = *(bool *)arg;
    *(bool *)arg = false; // Next character will not be starting

    // Most XML documents use ASCII for element types. So, check ASCII
    // characters first.
    if (xucharin(cp, 'A', 'Z') || xucharin(cp, 'a', 'z') || xuchareq(cp, '_') || xuchareq(cp, ':')
            || (!startchar && (xuchareq(cp, '-') || xuchareq(cp, '.') || xucharin(cp, '0', '9')))) {
        return cp; // Good, keep on reading
    }

    // TBD: replace the check in the BMP with a bitmap?
    // The rest of valid start characters
    if ((cp >= 0xC0 && cp <= 0x2FF && cp != 0xD7 && cp != 0xF7)
            || (cp >= 0x370 && cp <= 0x1FFF && cp != 0x37E)
            || (cp >= 0x200C && cp <= 0x200D)
            || (cp >= 0x2070 && cp <= 0x218F)
            || (cp >= 0x2C00 && cp <= 0x2FEF)
            || (cp >= 0x3001 && cp <= 0xD7FF)
            || (cp >= 0xF900 && cp <= 0xFDCF)
            || (cp >= 0xFDF0 && cp <= 0xFFFD)
            || (cp >= 0x10000 && cp <= 0xEFFFF)) {
        return cp; // Keep on
    }
    if (startchar) {
        return STOPCHAR; // Stop: this is not a valid start character
    }
    if (cp == 0xB7
            || (cp >= 0x0300 && cp <= 0x36F)
            || cp == 0x203F
            || cp == 0x2040) {
        return cp; // Keep on, this is valid continuation char
    }
    return STOPCHAR; // Stop: not valid even as continuation
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
static uint32_t
xml_cb_string(void *arg, uint32_t cp)
{
    xml_cb_string_state_t *state = arg;
    unsigned char tmp;

    if ((tmp = *(const unsigned char *)state->cur) >= 0x7F || tmp != cp) {
        return STOPCHAR;
    }
    state->cur++;
    return cp | (state->cur == state->end ? LASTCHAR : 0);
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
    state.cur = s;
    state.end = s + len;
    if (len != xml_read_until(h, xml_cb_string, &state)) {
        xml_reader_message(h, errinfo, "Expected string: '%s'", s);
        return false;
    }
    return true;
}


/// Callback state for literal reading
typedef struct xml_cb_literal_state_s {
    uint32_t quote;     ///< NOCHAR at start, quote seen, or STOPCHAR if saw final quote
} xml_cb_literal_state_t;

/**
    Closure for xml_read_until: expect an initial quote, then read
    up until (and including) a matching end quote.

    @param arg Current state
    @param cp Codepoint
    @return true if this character is rejected
*/
static uint32_t
xml_cb_literal(void *arg, uint32_t cp)
{
    xml_cb_literal_state_t *st = arg;

    switch (st->quote) {
    case NOCHAR: // Starting matching
        if (!xuchareq(cp, '"') && !xuchareq(cp, '\'')) {
            return STOPCHAR; // Rejected before even started
        }
        st->quote = cp;
        return NOCHAR; // Remember the quote, but do not store it
    case STOPCHAR: // Last character was final quote
        return STOPCHAR;
    default:
        if (cp != st->quote) {
            return cp; // Content
        }
        // Consume the closing quote and stop at the next character
        st->quote = STOPCHAR;
        return NOCHAR;
    }
}

/**
    Read one of the literals (EntityValue, AttValue, SystemLiteral,
    PubidLiteral). Also handles pseudo-literals used in XMLDecl and
    TextDecl - they use the same quoting mechanism.

    TBD distinguish between literal types - different entity inclusion
        rules, different allowed charsets...
    TBD perhaps, normalize attributes here to avoid extra copies

    @param h Reader handle
    @param errinfo Error code to use in case of failure
    @return true if literal was found (found start quote and matching
        end quote).
*/
static bool
xml_read_literal(xml_reader_t *h, xmlerr_info_t errinfo)
{
    xml_cb_literal_state_t st = { .quote = NOCHAR };

    // xml_read_until() may return 0 (empty literal), which is valid
    (void)xml_read_until(h, xml_cb_literal, &st);
    if (st.quote != STOPCHAR) {
        xml_reader_message(h, errinfo,
                st.quote == NOCHAR ? "Quoted literal expected" : "Unterminated literal");
        return false;
    }
    return true;
}

/**
    Check for VersionInfo production.

    VersionNum ::= '1.' [0-9]+    {{XML1.0}}
    VersionNum ::= '1.1'          {{XML1.1}}

    @param h Reader handle
    @return Nothing
*/
static void
check_VersionInfo(xml_reader_t *h, xml_reader_cbparam_t *cbp)
{
    const uint8_t *str = h->tokenbuf;
    size_t sz = h->tokenbuf_len;
    size_t i;

    if (sz == 3) {
        if (xustrneq(str, "1.0", 3)) {
            cbp->xmldecl.version = XML_INFO_VERSION_1_0;
            return;
        }
        else if (sz == 3 && xustrneq(str, "1.1", 3)) {
            h->parser_version = XML_INFO_VERSION_1_1;
            cbp->xmldecl.version = XML_INFO_VERSION_1_1;
            return;
        }
    }
    if (sz < 3 || !xustrneq(str, "1.", 2)) {
        goto bad_version;
    }
    for (i = 2, str += 2; i < sz; i++, str++) {
        if (!xucharin(*str, '0', '9')) {
            goto bad_version;
        }
    }

    /*
        Even though the VersionNum production matches any version number of
        the form '1.x', XML 1.0 documents SHOULD NOT specify a version number
        other than '1.0'.

        Note: When an XML 1.0 processor encounters a document that specifies
        a 1.x version number other than '1.0', it will process it as a 1.0
        document. This means that an XML 1.0 processor will accept 1.x
        documents provided they do not use any non-1.0 features.
    */
    cbp->xmldecl.version = XML_INFO_VERSION_1_0;
    xml_reader_message(h, XMLERR(WARN, XML, FUTURE_VERSION),
            "Document specifies unknown 1.x XML version");
    return; // Normal return

bad_version:
    // Non-fatal: recover by assuming version was missing
    xml_reader_message(h, h->declinfo->generr, "Unsupported XML version");
    return;
}

/**
    Check if encoding name matches the EncName production:
    EncName  ::= [A-Za-z] ([A-Za-z0-9._] | '-')*

    @param h Reader handle
    @return Nothing
*/
static void
check_EncName(xml_reader_t *h, xml_reader_cbparam_t *cbp)
{
    const uint8_t *str = h->tokenbuf;
    const uint8_t *s;
    size_t sz = h->tokenbuf_len;
    size_t i;

    for (i = 0, s = str; i < sz; i++, s++) {
        if (xucharin(*s, 'A', 'Z') || xucharin(*s, 'a', 'z')) {
            continue;
        }
        if (!i) {
            goto bad_encoding;
        }
        if (!xucharin(*s, '0', '9')
                && !xuchareq(*s, '.')
                && !xuchareq(*s, '_')
                && !xuchareq(*s, '-')) {
            goto bad_encoding;
        }
    }

    h->enc_xmldecl = xustrndup(str, sz);
    cbp->xmldecl.encoding = h->enc_xmldecl;
    return; // Normal return

bad_encoding:
    // Non-fatal: recover by assuming no encoding specification
    xml_reader_message(h, h->declinfo->generr, "Invalid encoding name");
    return;
}

/**
    Check for 'yes' or 'no' string. This is used as a value in SDDecl
    production, but this part has no separate production name.

       <anonymous> ::= 'yes' | 'no'

    @param h Reader handle
    @return Nothing
*/
static void
check_SD_YesNo(xml_reader_t *h, xml_reader_cbparam_t *cbp)
{
    const uint8_t *str = h->tokenbuf;
    size_t sz = h->tokenbuf_len;

    if (sz == 2 && xustrneq(str, "no", 2)) {
        cbp->xmldecl.standalone = XML_INFO_STANDALONE_NO;
    }
    else if (sz == 3 && xustrneq(str, "yes", 3)) {
        cbp->xmldecl.standalone = XML_INFO_STANDALONE_YES;
    }
    else {
        // Non-fatal: recover by assuming standalone was not specified
        xml_reader_message(h, h->declinfo->generr, "Unsupported standalone status");
    }
}

/// Handle TextDecl ::= '<?xml' VersionInfo? EncodingDecl S? '?>'
static const struct xml_reader_xmldecl_declinfo_s declinfo_textdecl = {
    .name = "TextDecl",
    .generr = XMLERR(ERROR, XML, P_TextDecl),
    .attrlist = (const xml_reader_xmldecl_attrdesc_t[]){
        { "version", false, check_VersionInfo },
        { "encoding", true, check_EncName },
        { NULL, false, NULL },
    },
};

/// Handle XMLDecl  ::= '<?xml' VersionInfo EncodingDecl? SDDecl? S? '?>'
static const struct xml_reader_xmldecl_declinfo_s declinfo_xmldecl = {
    .name = "XMLDecl",
    .generr = XMLERR(ERROR, XML, P_XMLDecl),
    .attrlist = (const struct xml_reader_xmldecl_attrdesc_s[]){
        { "version", true, check_VersionInfo },
        { "encoding", false, check_EncName },
        { "standalone", false, check_SD_YesNo },
        { NULL, false, NULL },
    },
};

/**
    Read XMLDecl/TextDecl if one is present. The set of expected attributes
    and their optionality is passed in the handle.

    XMLDecl      ::= '<?xml' VersionInfo EncodingDecl? SDDecl? S? '?>'
    TextDecl     ::= '<?xml' VersionInfo? EncodingDecl S? '?>'
    VersionInfo  ::= S 'version' Eq ("'" VersionNum "'" | '"' VersionNum '"')
    Eq           ::= S? '=' S?
    VersionNum   ::= '1.' [0-9]+    {{XML1.0}}
    VersionNum   ::= '1.1'          {{XML1.1}}
    EncodingDecl ::= S 'encoding' Eq ('"' EncName '"' | "'" EncName "'" )
    EncName      ::= [A-Za-z] ([A-Za-z0-9._] | '-')*
    SDDecl       ::= S 'standalone' Eq
                     (("'" ('yes' | 'no') "'") | ('"' ('yes' | 'no') '"'))

    @param h Reader handle
    @param cbp Callback parameter
    @return Nothing
*/
static void
xml_parse_XMLDecl_TextDecl(xml_reader_t *h, xml_reader_cbparam_t *cbp)
{
    const xml_reader_xmldecl_declinfo_t *declinfo = h->declinfo;
    const xml_reader_xmldecl_attrdesc_t *attrlist = declinfo->attrlist;
    uint8_t labuf[6]; // ['<?xml' + whitespace] or [?>]
    size_t len;

    if (6 != xml_lookahead(h, labuf, 6)
            || !xustrneq(labuf, "<?xml", 5)
            || !xml_is_whitespace(labuf[5])) {
        return; // Does not start with a declaration
    }

    // We have something resembling a declaration
    cbp->xmldecl.has_decl = true;

    // We know it's there, checked above
    (void)xml_read_string(h, "<?xml", declinfo->generr);

    while (true) {
        len = xml_read_whitespace(h);

        // From the productions above, we expect either closing ?> or Name=Literal.
        // If it was a Name, it is further checked against the expected
        // attribute list and Literal is then verified for begin a valid value
        // for Name.
        if (2 == xml_lookahead(h, labuf, 2) && xustrneq(labuf, "?>", 2)) {
            xml_read_string(h, "?>", declinfo->generr);
            break;
        }
        // We may have no whitespace before final ?>, but must get some before
        // pseudo-attributes.
        if (len == 0 || (len = xml_read_Name(h)) == 0) {
            goto malformed;
        }
        // Go through the remaining attributes and see if this one is known
        // (and if we skipped any mandatory attributes while advancing).
        while (attrlist->name) {
            if (h->tokenbuf_len == strlen(attrlist->name)
                    && xustrneq(h->tokenbuf, attrlist->name, h->tokenbuf_len)) {
                break; // Yes, that is what we expect
            }
            if (attrlist->mandatory) {
                // Non-fatal: continue with next pseudo-attributes
                xml_reader_message(h, declinfo->generr,
                        "Mandatory pseudo-attribute '%s' missing in %s",
                        attrlist->name, declinfo->name);
            }
            attrlist++;
        }

        // Parse Eq ::= S* '=' S*
        (void)xml_read_whitespace(h);
        if (xml_read_string(h, "=", declinfo->generr) != 1) {
            goto malformed;
        }
        (void)xml_read_whitespace(h);
        if (!xml_read_literal(h, declinfo->generr)) {
            goto malformed;
        }

        if (attrlist->name) {
            // Check/get value and advance to the next attribute
            attrlist->check(h, cbp);
            attrlist++;
        }
        else {
            // Non-fatal: continue parsing as if matching the following production
            //   Name Eq ('"' (Char - '"')* '"' | "'" (Char - "'")* "'")
            xml_reader_message(h, declinfo->generr,
                    "Unexpected pseudo-attribute");
        }
    }

    // Check if any mandatory attributes were omitted
    while (attrlist->name) {
        if (attrlist->mandatory) {
            // Non-fatal: just assume the default
            xml_reader_message(h, declinfo->generr,
                    "Mandatory pseudo-attribute '%s' missing in %s",
                    attrlist->name, declinfo->name);
        }
        attrlist++;
    }

    return; // Normal return

malformed: // Any fatal malformedness
    h->flags |= READER_FATAL;
    xml_reader_message(h, declinfo->generr, "Malformed %s", declinfo->name);
    return;
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
    size_t len = h->tokenbuf_len;

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
    size_t len = h->tokenbuf_len;

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
        len = xml_read_whitespace(h);
        if (xml_lookahead(h, &la, 1) != 1) {
            xml_reader_message(h, XMLERR(ERROR, XML, P_STag),
                    "Element start tag truncated");
            return;
        }
        if (xuchareq(la, '/')) {
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
        else if (xuchareq(la, '>')) {
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

    (void)xml_read_whitespace(h);
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
        OOPS_ASSERT(xuchareq(labuf[0], '<') && xuchareq(labuf[1], '/'));
        xml_parse_ETag(h);
    }
}

/**
    Start parsing an input stream: detect initial encoding, read
    the XML/text declaration, determine final encodings (or err out).

    @param h Reader handle
    @return None
*/
static void
xml_reader_start(xml_reader_t *h)
{
    xml_reader_initial_xcode_t xc;
    uint8_t adbuf[4];       // 4 bytes for encoding detection, per XML spec suggestion
    size_t bom_len, adsz;
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
    memset(adbuf, 0, sizeof(adbuf));
    adsz = strbuf_lookahead(h->buf_raw, adbuf, sizeof(adbuf));
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
        strbuf_radvance(h->buf_raw, bom_len);
    }

    // If no encoding passed from the transport layer, and autodetect didn't help,
    // try UTF-8. UTF-8 is built-in, so it should always work.
    if (!h->enc && !xml_reader_set_encoding(h, "UTF-8")) {
        OOPS_ASSERT(0);
    }

    // Record the encoding we've used initially
    cbparam.xmldecl.initial_encoding = encoding_name(h->enc);

    // Create a temporary reader buffer
    xc.h = h;
    xc.la_start = xc.initial;
    xc.la_size = sizeof(xc.initial);
    xc.la_avail = 0;
    xc.la_offs = 0;
    h->buf_proc = strbuf_new(NULL, 32 * sizeof(uint32_t));
    strbuf_setops(h->buf_proc, &xml_reader_initial_ops, &xc);

    // Parse the declaration; expect only ASCII
    h->flags |= READER_ASCII;
    xml_parse_XMLDecl_TextDecl(h, &cbparam);
    h->flags &= ~READER_ASCII;

    // Done with the temporary buffer: free the memory buffer if it was reallocated;
    // advance the raw buffer by the amount used by XML declaration.
    if (xc.la_start != xc.initial) {
        xfree(xc.la_start);
    }

    // Set up permanent transcoder (we do it always, but the caller probably won't
    // proceed with further decoding if READER_FATAL is reported). Only advance if
    // there was a declaration - otherwise, la_offs is just a look-ahead that was
    // used to determine the absense of the declaration.
    if (cbparam.xmldecl.has_decl) {
        strbuf_radvance(h->buf_raw, xc.la_offs);
    }
    strbuf_delete(h->buf_proc);
    h->buf_proc = strbuf_new(NULL, 1024 * sizeof(uint32_t));
    strbuf_setops(h->buf_proc, &xml_reader_transcode_ops, h);

    if (h->enc_xmldecl) {
        // Encoding should be in clean state - if not, need to fix encoding to not consume
        // excess data. If this fails, the error is already reported - try to recover by
        // keeping the old encoding.
        if (!xml_reader_set_encoding(h, h->enc_xmldecl)) {
            xml_reader_message(h, XMLERR_NOTE, "(encoding from XML declaration)");
        }
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
        (void)xml_read_whitespace(h); // Skip whitespace if any
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
            (void)xml_read_until_lt(h);
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
