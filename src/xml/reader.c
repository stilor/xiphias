/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    XML reader handle operations.
*/
#include <string.h>

#include "util/defs.h"
#include "util/xutil.h"
#include "util/strbuf.h"
#include "util/strhash.h"
#include "util/encoding.h"
#include "util/unicode.h"

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

/// Order (log2) of the hashes for entities
#define ENTITY_HASH_ORDER           5

/// Maximum number of characters to look ahead
#define MAX_LOOKAHEAD_SIZE          16

/**
    Longest terminating sequence we're looking for is comment terminator, -->
    (3 charactes). If we fail to see the closing angle bracket, first dash is
    returned immediately and two characters (second dash and whatever we saw
    instead of angle bracket) are stored in the backtrack buffer.
*/
#define MAX_BACKTRACK               2

/**
    Special value for backtrack count: a trivial backtrack, just don't advance
    the current read pointer (nothing is stored in the backtrack buffer).
*/
#define BACKTRACK_NOADVANCE         ((size_t)-1)

/// Reader flags
enum {
    /// @todo Instead, pass an options structure to xml_reader_new/xml_reader_subordinate?
    READER_STARTED  = 0x0001,       ///< Reader has started the operation
    /// @todo Get rid of READER_FATAL in favor of PR_FAIL?
    READER_FATAL    = 0x0002,       ///< Reader encountered a fatal error
    /// @todo Change to RECOGNIZE_ASCII, pass from XMLDecl parser?
    READER_ASCII    = 0x0004,       ///< Only ASCII characters allowed while reading declaration
    READER_LOCTRACK = 0x0008,       ///< Track the current position for error reporting
};

/// Reference recognition
enum {
    RECOGNIZE_REF   = 0x0001,       ///< Reading next token will expand Reference production
    RECOGNIZE_PEREF = 0x0002,       ///< Reading next token will expand PEReference production
};

/**
    XML declaration comes in two flavors, XMLDecl and TextDecl, with different
    set of allowed/mandatory/optional attributes. This structure describes an
    attribute in the expected list.
*/
typedef struct xml_reader_xmldecl_attrdesc_s {
    const char *name;       ///< Name of the attribute
    bool mandatory;         ///< True if the attribute is mandatory

    /// Value validation function
    void (*check)(xml_reader_t *h);
} xml_reader_xmldecl_attrdesc_t;

/// Declaration info for XMLDecl/TextDecl:
typedef struct xml_reader_xmldecl_declinfo_s {
    const char *name;           ///< Declaration name in XML grammar
    const xml_reader_xmldecl_attrdesc_t *attrlist; ///< Allowed/required attributes
} xml_reader_xmldecl_declinfo_t;

/// Entity information
typedef struct xml_reader_entity_s {
    enum xml_reader_reference_e type;   ///< Entity type
    const char *system_id;              ///< System ID of the entity (NULL for internal)
    const char *location;               ///< How input from this entity will be reported
    bool being_parsed;                  ///< Recursion detection: this entity is being parsed
    union {
        // Internal entity
        struct {
            const ucs4_t *rplc;         ///< Replacement text
            size_t rplclen;             ///< Length of the replacement text
        };
        // External entity
        struct {
            const char *public_id;      ///< Public ID of the entity
            const char *notation;       ///< Notation name (unparsed entity)
        };
    };
} xml_reader_entity_t;

/// Input method: either strbuf for the main document, or diversion from a ucs4_t buffer in memory
typedef struct xml_reader_input_s {
    SLIST_ENTRY(xml_reader_input_s) link;   ///< Stack of diversions
    strbuf_t *buf;                  ///< String buffer to use
    xmlerr_loc_t saveloc;           ///< Saved location when this input is added

    /// Notification when this input is consumed
    void (*complete)(struct xml_reader_s *, void *);
    void *complete_arg;             ///< Argument to completion notification

    // Other fields
    uint32_t srcid;                 ///< Source ID to check for proper nesting
    bool inc_in_literal;            ///<'included in literal' - special handling of quotes
    bool charref;                   ///< Input originated from a character reference
    bool backtrack;                 ///< Input for backtracking (does not terminate read loop)
    xml_reader_entity_t *entity;    ///< Associated entity if any
    void *baton;                    ///< Saved user data for entity being parsed
} xml_reader_input_t;

/// Structure shared between master and subordinate documents
typedef struct xml_reader_shared_s {
    int refcnt;                     ///< Number of xml_reader_t handles referencing this

    xml_reader_cb_t func;           ///< Callback function
    void *arg;                      ///< Argument to callback function

    strhash_t *entities_param;      ///< Parameter entities
    strhash_t *entities_gen;        ///< General entities
} xml_reader_shared_t;

/// XML reader structure
struct xml_reader_s {
    xml_reader_shared_t *share;     ///< Structure shared with subordinate documents

    const char *enc_transport;      ///< Encoding reported by transport protocol
    const char *enc_detected;       ///< Encoding detected by BOM or start characters
    const char *enc_xmldecl;        ///< Encoding declared in <?xml ... ?>

    encoding_handle_t *enc;         ///< Encoding used to transcode input
    strbuf_t *buf;                  ///< Raw input buffer (in document's encoding)

    uint32_t flags;                 ///< Reader flags
    xmlerr_loc_t curloc;            ///< Current reader's position
    size_t tabsize;

    const xml_reader_xmldecl_declinfo_t *declinfo;  ///< Expected declaration
    enum xml_info_version_e version;                ///< Version assumed when parsing
    enum xml_info_standalone_e standalone;          ///< Document's standalone status
    enum xml_reader_normalization_e normalization;  ///< Desired normalization behavior

    uint32_t nestlvl;               ///< Element nesting level

    utf8_t *tokenbuf;               ///< Token buffer
    utf8_t *tokenbuf_end;           ///< End of the token buffer
    size_t tokenbuf_len;            ///< Length of the token in the buffer

    ucs4_t backtrack[MAX_BACKTRACK];///< Buffer for "ungot" characters
    size_t backtrack_cnt;           ///< Number of characters to get from backtrack buffer

    xmlerr_loc_t lastreadloc;       ///< Reader's position at the beginning of last token
    ucs4_t rejected;                ///< Next character (rejected by xml_read_until_*)
    ucs4_t charrefval;              ///< When parsing character reference: stored value

    uint32_t srcid;                 ///< Source ID, incremented for each new input
    SLIST_HEAD(,xml_reader_input_s) active_input;   ///< Currently active inputs
    SLIST_HEAD(,xml_reader_input_s) free_input;     ///< Free list of input structures

    xml_reader_t *master;           ///< Master document, if any
    SLIST_HEAD(,xml_reader_s) sub;  ///< Subordinate document list
    SLIST_ENTRY(xml_reader_s) link; ///< Link in subordinate list
};

/// Function for conditional read termination: returns true if the character is rejected
/// @todo Change the API so that this function can look at arbitrary length of ucs4_t
/// codepoints and tell how many it will consume - to avoid calling it for each character.
typedef ucs4_t (*xml_condread_func_t)(void *arg, ucs4_t cp);

/// Handler for a reference
typedef void (*xml_refhandler_t)(xml_reader_t *, xml_reader_entity_t *);

/// Methods for handling references (PEReference, EntityRef, CharRef)
typedef struct xml_reference_ops_s {
    /// Error raised if failed to parse
    xmlerr_info_t errinfo;

    /// Flags for entity recognition
    uint32_t flags;

    /// How text blocks are handled
    void (*textblock)(xml_reader_t *h);
    
    /// How different types of entities are handled
    xml_refhandler_t hnd[XML_READER_REF__MAX];
} xml_reference_ops_t;

/// How error messages are generated for references
typedef struct {
    const char *desc;           ///< How this reference is called in error messages
    uint32_t ecode;             ///< Error code associated with this type of references
} xml_reference_info_t;

/// Return status for production parser
typedef enum {
    PR_OK,                      ///< Parsed successfully or performed recovery
    PR_STOP,                    ///< Parsed successfully, exit current context
    PR_FAIL,                    ///< Parsing failed (fatal)
    PR_NOMATCH,                 ///< Production was not matched
} prodres_t;

/// Production parser function
typedef prodres_t (*prodparser_t)(xml_reader_t *);

/// Maximum number of characters we need to look ahead: '<!DOCTYPE' or '<![CDATA['
#define MAX_PATTERN     9

/// Lookahead pattern/handler pairs
typedef struct {
    const utf8_t pattern[MAX_PATTERN];  ///< Lookahead pattern to look for
    size_t patlen;                      ///< Length of the recognized pattern
    prodparser_t func;                  ///< Function to call for this pattern
} xml_reader_pattern_t;

/// Lookahead initializer
/// @todo Construct a DFA instead of an array? If so, manually or by a constructor?
#define LOOKAHEAD(s, f) \
{ \
    .pattern = U_ARRAY s, \
    .patlen = sizeof(s) - 1, \
    .func = f, \
}

/// Maximum number of lookahead pairs
#define MAX_LA_PAIRS    6

/**
    Parser settings: entity recognition settings at root level, set of lookahead
    patterns for root level, pointer to a settings for non-root level.
*/
typedef struct xml_reader_settings_s {
    /// Lookahead patterns
    const xml_reader_pattern_t lookahead[MAX_LA_PAIRS];

    /// Recovery function (if the handler for recognized pattern returns failure)
    prodparser_t nomatch;

    /// Entity recognition flags
    uint32_t flags;

    /// Settings for non-root context (if this corresponds to root context)
    const struct xml_reader_settings_s *nonroot;
} xml_reader_context_t;

/// xml_read_until_* return codes
typedef enum {
    XRU_CONTINUE,          ///< Internal value: do not return yet
    XRU_EOF,               ///< Reach end of input
    XRU_STOP,              ///< Callback indicated end of a token
    XRU_REFERENCE,         ///< Recognized entity/character reference
    XRU_INPUT_BOUNDARY,    ///< Encountered input (entity) boundary
} xru_t;

/// Convenience macro: report an error at the start of the last token
#define xml_reader_message_lastread(h, ...) \
        xml_reader_message(h, &h->lastreadloc, __VA_ARGS__)

/// Convenience macro: report an error at current location (i.e. after a lookahead)
#define xml_reader_message_current(h, ...) \
        xml_reader_message(h, &h->curloc, __VA_ARGS__)

/**
    Determine if a character is a restricted character. Restricted characters are
    completely illegal in XML1.0 (directly inserted and inserted as character reference).
    They are allowed in character references in XML1.1 documents.

    @param h Reader handle
    @param cp Codepoint
    @return true if @a cp is a restricted character
*/
static inline bool
xml_is_restricted(xml_reader_t *h, ucs4_t cp)
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
    size_t exclusion_limit;

    // Different in XML1.0 and XML1.1: XML1.0 did not exclude 0x7F..0x84 and
    // 0x85..0x9F blocks; these were valid characters.
    exclusion_limit = h->version == XML_INFO_VERSION_1_0 ? 0x20 : sizeofarray(restricted_chars);
    if (cp < exclusion_limit) {
        return restricted_chars[cp];
    }
    return false;
}

/**
    Check if a given Unicode code point is white space per XML spec.
    XML spec says, \#x20, \#x9, \#xA and \#xD are whitespace, the rest is not.

    @param cp Code point to check
    @return true if @a cp is whitespace, false otherwise
*/
static bool
xml_is_whitespace(ucs4_t cp)
{
    // COV: test for 0xD character requires parsing content and recognition of character refs
    return ucs4_cheq(cp, 0x20) || ucs4_cheq(cp, 0x9) || ucs4_cheq(cp, 0xA)
            || ucs4_cheq(cp, 0xD);
}

/**
    Check if a given Unicode code point is NameStartChar per XML spec.

    @param cp Code point to check
    @return true if @a cp matches NameStartChar, false otherwise
*/
static bool
xml_is_NameStartChar(ucs4_t cp)
{
    /// @todo Replace the check in the BMP with a bitmap
    return ucs4_chin(cp, 'A', 'Z')
            || ucs4_chin(cp, 'a', 'z')
            || ucs4_cheq(cp, '_')
            || ucs4_cheq(cp, ':')
            || (cp >= 0xC0 && cp <= 0x2FF && cp != 0xD7 && cp != 0xF7)
            || (cp >= 0x370 && cp <= 0x1FFF && cp != 0x37E)
            || (cp >= 0x200C && cp <= 0x200D)
            || (cp >= 0x2070 && cp <= 0x218F)
            || (cp >= 0x2C00 && cp <= 0x2FEF)
            || (cp >= 0x3001 && cp <= 0xD7FF)
            || (cp >= 0xF900 && cp <= 0xFDCF)
            || (cp >= 0xFDF0 && cp <= 0xFFFD)
            || (cp >= 0x10000 && cp <= 0xEFFFF);
}

/**
    Check if a given Unicode code point is NameChar per XML spec.

    @param cp Code point to check
    @return true if @a cp matches NameChar, false otherwise
*/
static bool
xml_is_NameChar(ucs4_t cp)
{
    return xml_is_NameStartChar(cp)
            || ucs4_cheq(cp, '-')
            || ucs4_cheq(cp, '.')
            || ucs4_chin(cp, '0', '9')
            || cp == 0xB7
            || (cp >= 0x0300 && cp <= 0x36F)
            || cp == 0x203F
            || cp == 0x2040;
}

/**
    Replace encoding translator in a handle.

    @param h Reader handle
    @param encname Encoding to be set, NULL to clear current encoding processor
    @return true if successful, false otherwise
*/
static bool
xml_reader_set_encoding(xml_reader_t *h, const char *encname)
{
    encoding_handle_t *hndnew;

    if (encname != NULL) {
        if ((hndnew = encoding_open(encname)) == NULL) {
            // XMLDecl location passed via h->lastreadloc
            xml_reader_message_lastread(h, XMLERR(ERROR, XML, ENCODING_ERROR),
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
            xml_reader_message_lastread(h, XMLERR(ERROR, XML, ENCODING_ERROR),
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
    Look ahead in the parsed stream without advancing the current read location.
    Stops on a non-ASCII character; all mark-up (that requires look-ahead) is
    using ASCII characters.

    @param h Reader handle
    @param buf Buffer to read into
    @param bufsz Buffer size
    @param peof Set to true if EOF is detected
    @return Number of characters read
*/
static size_t
xml_lookahead(xml_reader_t *h, utf8_t *buf, size_t bufsz, bool *peof)
{
    xml_reader_input_t *inp;
    ucs4_t tmp[MAX_LOOKAHEAD_SIZE];
    ucs4_t *ptr = tmp;
    size_t i, nread;

    OOPS_ASSERT(bufsz <= MAX_LOOKAHEAD_SIZE);

    if (peof) {
        *peof = true;
    }
    SLIST_FOREACH(inp, &h->active_input, link) {
        nread = strbuf_lookahead(inp->buf, ptr, bufsz * sizeof(ucs4_t));
        if (peof && nread) {
            *peof = false;
        }
        OOPS_ASSERT((nread & 3) == 0); // input buf must have an integral number of characters
        nread /= 4;
        for (i = 0; i < nread; i++) {
            if (*ptr >= 0x7F) {
                break; // Non-ASCII
            }
            *buf++ = *ptr++;
            bufsz--;
        }
        if (!bufsz) {
            break; // No need to look at the next input
        }
    }

    return ptr - tmp;
}

/**
    Get read pointers, either from a strbuf or from an input diversion.

    @param h Reader handle
    @param begin Pointer set to the beginning of the readable area
    @param end Pointer set to the end of the readable area
    @return Reason for termination (EOF or crossing the input boundary)
*/
static xru_t
xml_reader_input_rptr(xml_reader_t *h, const void **begin, const void **end)
{
    xml_reader_input_t *inp;
    xru_t rv = XRU_CONTINUE;

    while ((inp = SLIST_FIRST(&h->active_input)) != NULL) {
        OOPS_ASSERT(inp->buf);
        if (strbuf_rptr(inp->buf, begin, end) != 0) {
            return rv;
        }
        // This input is done with: dequeue, notify and try next
        SLIST_REMOVE_HEAD(&h->active_input, link);
        h->curloc = inp->saveloc;
        if (inp->complete) {
            inp->complete(h, inp->complete_arg);
        }
        if (!inp->backtrack) {
            rv = XRU_INPUT_BOUNDARY; // No longer reading from the same input
        }
        SLIST_INSERT_HEAD(&h->free_input, inp, link);
    }
    return XRU_EOF; // All inputs consumed, EOF
}

/**
    Advance read pointer, either in strbuf or in diversion.

    @param h Reader handle
    @param sz Amount to advance
    @return Nothing
*/
static void
xml_reader_input_radvance(xml_reader_t *h, size_t sz)
{
    xml_reader_input_t *inp;

    inp = SLIST_FIRST(&h->active_input);
    OOPS_ASSERT(inp && inp->buf);
    strbuf_radvance(inp->buf, sz);
}

/**
    Allocate a new input structure for reader.

    @param h Reader handle
    @param location Location string for this input
    @return Allocated input structure
*/
static xml_reader_input_t *
xml_reader_input_new(xml_reader_t *h, const char *location)
{
    xml_reader_input_t *inp;

    if ((inp = SLIST_FIRST(&h->free_input)) != NULL) {
        SLIST_REMOVE_HEAD(&h->free_input, link);
    }
    else {
        inp = xmalloc(sizeof(xml_reader_input_t));
    }

    memset(inp, 0, sizeof(xml_reader_input_t));
    inp->srcid = h->srcid++;
    inp->buf = strbuf_new(0); // Most of these buffers will use static strings
    inp->saveloc = h->curloc;
    if (location) {
        h->curloc.src = location;
        h->curloc.line = 1;
        h->curloc.pos = 1;
    }

    // To catch if this is used without initialization
    SLIST_INSERT_HEAD(&h->active_input, inp, link);

    return inp;
}

/**
    Free an entity information structure.

    @param arg Pointer to entity information structure
    @return Nothing
*/
static void
xml_entity_destroy(void *arg)
{
    xml_reader_entity_t *e = arg;

    if (e->system_id) {
        // external entity
        xfree(e->notation);
        xfree(e->public_id);
        xfree(e->system_id);
    }
    else {
        // internal entity
        xfree(e->rplc);
    }
    xfree(e->location);
    xfree(e);
}

/// Information on a pre-defined entity.
typedef struct {
    const utf8_t *name;     ///< Entity name
    const char *rplc[4];    ///< Replacement text; 1st is default.
} xml_predefined_entity_t;

/**
    Pre-defined entities.
    
    If the entities lt or amp are declared, they MUST be declared as internal entities
    whose replacement text is a character reference to the respective character
    (less-than sign or ampersand) being escaped; the double escaping is REQUIRED for
    these entities so that references to them produce a well-formed result. If the
    entities gt, apos, or quot are declared, they MUST be declared as internal
    entities whose replacement text is the single character being escaped (or
    a character reference to that character; the double escaping here is OPTIONAL
    but harmless). For example:

    <!ENTITY lt     "&#38;#60;">
    <!ENTITY gt     "&#62;">
    <!ENTITY amp    "&#38;#38;">
    <!ENTITY apos   "&#39;">
    <!ENTITY quot   "&#34;">

    The table below specifies replacement text of these entities, not literal value -
    so one level of escaping is removed.  Up to 4 replacement texts may be allowed:
    without double escaping, and 3 with double-escaping: using hex/decimal reference
    and with upper/lower case in hex character reference.
*/
static const xml_predefined_entity_t predefined_entities[] = {
    { .name = U"lt",    .rplc = { "&#60;",  "&#x3C;",   "&#x3c;",   NULL,       }, },
    { .name = U"gt",    .rplc = { ">",      "&#62;",    "&#x3E;",   "&#x3e;",   }, },
    { .name = U"amp",   .rplc = { "&#38;",  "&#x26;",   NULL,       NULL,       }, },
    { .name = U"apos",  .rplc = { "'",      "&#39;",    "&#x27;",   NULL,       }, },
    { .name = U"quot",  .rplc = { "\"",     "&#34;",    "&#x22;",   NULL,       }, },
};

/**
    Set the replacement text for pre-defined entities

    @param ehash Entity hash
    @return Nothing
*/
static void
xml_entity_populate(strhash_t *ehash)
{
    const xml_predefined_entity_t *predef;
    const char *s;
    xml_reader_entity_t *e;
    ucs4_t *rplc;
    size_t i, j, nchars;

    for (i = 0, predef = predefined_entities; i < sizeofarray(predefined_entities);
            i++, predef++) {
        s = predef->rplc[0];
        /// @todo Create xml_entity_internal() for this - to be used when we parse \<!ENTITY>
        e = xmalloc(sizeof(xml_reader_entity_t));
        e->type = XML_READER_REF_INTERNAL;
        e->being_parsed = false;
        e->system_id = NULL;    // internal entity
        nchars = strlen(s);
        e->rplclen = nchars * sizeof(ucs4_t);
        rplc = xmalloc(e->rplclen);
        for (j = 0; j < nchars; j++) {
            rplc[j] = ucs4_fromlocal(s[j]);
        }
        e->rplc = rplc;
        s = utf8_strtolocal(predef->name);
        e->location = xasprintf("entity(%s)", s);
        utf8_strfreelocal(s);
        strhash_set(ehash, predef->name, e);
    }
}

/**
    Create an XML reading handle.

    @param master Master handle (NULL if master document is created)
    @param buf String buffer to read the input from; will be destroyed along with
          the handle returned by this function.
    @param location Location that will be used for reporting errors
    @return Handle
*/
static xml_reader_t *
xml_reader_new_internal(xml_reader_t *master, strbuf_t *buf, const char *location)
{
    xml_reader_t *h;

    h = xmalloc(sizeof(xml_reader_t));
    memset(h, 0, sizeof(xml_reader_t));
    h->buf = buf;

    h->flags = READER_LOCTRACK;
    h->curloc.src = xstrdup(location);
    h->curloc.line = 1;
    h->curloc.pos = 1;
    h->tabsize = 8;

    h->version = XML_INFO_VERSION_NO_VALUE;
    h->standalone = XML_INFO_STANDALONE_NO_VALUE;
    h->normalization = XML_READER_NORM_DEFAULT;

    h->lastreadloc = h->curloc; // Shares reference to copy of location
    h->tokenbuf = xmalloc(INITIAL_TOKENBUF_SIZE);
    h->tokenbuf_end = h->tokenbuf + INITIAL_TOKENBUF_SIZE;
    h->tokenbuf_len = 0;

    SLIST_INIT(&h->active_input);
    SLIST_INIT(&h->free_input);

    SLIST_INIT(&h->sub);

    // Subordinate document inherits callback info, entity storage
    if (master) {
        h->share = master->share;
        master->share->refcnt++;
        SLIST_INSERT_HEAD(&master->sub, h, link);
        h->master = master;
    }
    else {
        h->share = xmalloc(sizeof(xml_reader_shared_t));
        memset(h->share, 0, sizeof(xml_reader_shared_t));
        h->share->refcnt = 1;
        h->share->entities_param = strhash_create(ENTITY_HASH_ORDER, xml_entity_destroy);
        h->share->entities_gen = strhash_create(ENTITY_HASH_ORDER, xml_entity_destroy);
        xml_entity_populate(h->share->entities_gen);
    }

    return h;
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
    return xml_reader_new_internal(NULL, buf, location);
}

/**
    Destroy an XML reading handle.

    @param h Handle to be destroyed.
    @return None
*/
void
xml_reader_delete(xml_reader_t *h)
{
    xml_reader_input_t *inp;
    xml_reader_t *hs;

    if (h->share->refcnt-- == 1) {
        // This is the last close
        strhash_destroy(h->share->entities_param);
        strhash_destroy(h->share->entities_gen);
        xfree(h->share);
    }
    if (h->master) {
        SLIST_REMOVE(&h->master->sub, h, xml_reader_s, link);
    }
    while ((hs = SLIST_FIRST(&h->sub)) != NULL) {
        // Destroy subordinates
        xml_reader_delete(hs);
    }
    while ((inp = SLIST_FIRST(&h->active_input)) != NULL) {
        SLIST_REMOVE_HEAD(&h->active_input, link);
        if (inp->complete) {
            inp->complete(h, inp->complete_arg);
        }
        strbuf_delete(inp->buf);
        xfree(inp);
    }
    while ((inp = SLIST_FIRST(&h->free_input)) != NULL) {
        SLIST_REMOVE_HEAD(&h->free_input, link);
        strbuf_delete(inp->buf);
        xfree(inp);
    }
    (void)xml_reader_set_encoding(h, NULL);
    strbuf_delete(h->buf);
    xfree(h->enc_transport);
    xfree(h->enc_detected);
    xfree(h->enc_xmldecl);
    xfree(h->curloc.src);
    // h->lastreadloc.src not freed - it is sharing a reference with h->curloc.src
    xfree(h->tokenbuf);
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
    if (h->flags & READER_STARTED) {
        // Will have no effect once the parsing begins
        return false;
    }

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
    Set desired normalization checking.

    @param h Reader handle
    @param norm Normalization check behavior (on/off/default)
    @return true if reader's normalization behavior was set, false if failed
*/
bool
xml_reader_set_normalization(xml_reader_t *h, enum xml_reader_normalization_e norm)
{
    if (h->flags & READER_STARTED) {
        // May have missed denormalized characters once the parsing begins
        return false;
    }

    h->normalization = norm;
    return true;
}

/**
    Turn location tracking on/off.

    @param h Reader handle
    @param onoff True if locations shall be tracked
    @param tabsz If location is tracked, size of a tabstop
        (1 to count tabs as a single character)
    @return false if parser is already active, true if location tracking is modified
*/
bool
xml_reader_set_location_tracking(xml_reader_t *h, bool onoff, size_t tabsz)
{
    if (h->flags & READER_STARTED) {
        return false;
    }

    if (onoff) {
        h->flags |= READER_LOCTRACK;
        h->tabsize = tabsz;
    }
    else {
        h->flags &= ~READER_LOCTRACK;
    }
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
    h->share->func = func;
    h->share->arg = arg;
}

/**
    Call a user-registered function for the specified event.

    @param h Reader handle
    @param cbparam Parameter for the callback
    @return None
*/
static void
xml_reader_invoke_callback(xml_reader_t *h, xml_reader_cbparam_t *cbparam)
{
    xml_reader_cb_t func;

    if ((func = h->share->func) != NULL) {
        func(h->share->arg, cbparam);
    }
}

/**
    Update reader's position when reading the specified character.

    @param h Reader handle
    @param cp Code point being read
    @return Nothing
*/
static void
xml_reader_update_position(xml_reader_t *h, ucs4_t cp)
{
    if (cp == 0x0A) {
        // Newline and it wasn't rejected - increment line number *after this character*
        h->curloc.line++;
        h->curloc.pos = 1;
    }
    else if (cp == 0x09) {
        // Round down, move to next tabstop, account for 1-based position
        h->curloc.pos = (h->curloc.pos / h->tabsize) * h->tabsize + h->tabsize + 1;
    }
    else if (ucs4_get_ccc(cp) == 0) {
        // Do not count combining marks - supposedly they're displayed with the preceding
        // character.
        /// @todo Check UAX#19 - AFAIU, this is what "Stacked boundaries" treatment implies
        h->curloc.pos++;
    }
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
xml_reader_message(xml_reader_t *h, xmlerr_loc_t *loc, xmlerr_info_t info,
        const char *fmt, ...)
{
    xml_reader_cbparam_t cbparam;
    va_list ap;

    cbparam.cbtype = XML_READER_CB_MESSAGE;
    cbparam.loc = *loc;
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
    utf8_t *la_start;           ///< Start of the lookahead buffer
    size_t la_size;             ///< Size of the lookahead buffer
    size_t la_avail;            ///< Size of data available in buffer
    size_t la_offs;             ///< Current lookahead offset

    /// First attempt to have the buffer on the stack
    utf8_t initial[INITIAL_DECL_LOOKAHEAD_SIZE];
} xml_reader_initial_xcode_t;

/**
    Temporary transcoding operation: use lookahead instead of read on the
    input buffer, abort on non-ASCII characters. This mode is used during
    parsing of the XML declaration: until then, the actual encoding is not
    known yet.

    @param arg Pointer to transcoder state
    @param begin Beginning of the destination memory block
    @param sz Size of the destination memory block
    @return None
*/
static size_t
xml_reader_initial_op_more(void *arg, void *begin, size_t sz)
{
    xml_reader_initial_xcode_t *xc = arg;
    xml_reader_t *h = xc->h;
    ucs4_t *cptr, *bptr;

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
            xc->la_avail = strbuf_lookahead(h->buf, xc->la_start, xc->la_size);
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
    return sizeof(ucs4_t);
}

/// Operations for transcoding XMLDecl/TextDecl
static const strbuf_ops_t xml_reader_initial_ops = {
    .more = xml_reader_initial_op_more,
};

/**
    Fetch more data from the transcoder.

    @param arg Reader handle (cast to void pointer)
    @param begin Beginning of the output buffer
    @param sz Size of the output buffer
    @return None
*/
static size_t
xml_reader_transcode_op_more(void *arg, void *begin, size_t sz)
{
    xml_reader_t *h = arg;
    ucs4_t *bptr, *cptr, *eptr;

    bptr = cptr = begin;
    eptr = bptr + sz / sizeof(ucs4_t);
    encoding_in_from_strbuf(h->enc, h->buf, &cptr, eptr);
    return (cptr - bptr) * sizeof(ucs4_t);
}

/// Operations for transcoding after parsing the XMLDecl/TextDecl
static const strbuf_ops_t xml_reader_transcode_ops = {
    .more = xml_reader_transcode_op_more,
};

/**
    Read until the specified condition; reallocate the buffer to accommodate
    the token being read as necessary. Perform whitespace/EOL handling prescribed
    by the XML spec; check normalization if needed.

    This function is not expanding entities. If entity expansion is requested,
    it just returns to the caller at the start of the next entity (i.e. prior
    to the actual termination condition). It is the responsibility of the caller
    to switch the input, if needed, and parse the entity content - or just skip
    over the entity and proceed further.

    End-of-Line handling:

    For XML 1.0: To simplify the tasks of applications, the XML processor MUST
    behave as if it normalized all line breaks in external parsed entities
    (including the document entity) on input, before parsing, by translating
    both the two-character sequence \#xD \#xA and any \#xD that is not followed
    by \#xA to a single \#xA character.

    For XML 1.1: To simplify the tasks of applications, the XML processor MUST
    behave as if it normalized all line breaks in external parsed entities
    (including the document entity) on input, before parsing, by translating
    all of the following to a single \#xA character:
    1. the two-character sequence \#xD \#xA
    2. the two-character sequence \#xD \#x85
    3. the single character \#x85
    4. the single character \#x2028
    5. any \#xD character that is not immediately followed by \#xA or \#x85.

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
    @param recognize Bitmask of reference types recognized while parsing
    @return Reason why the token parser returned
*/
static inline xru_t
xml_read_until(xml_reader_t *h, xml_condread_func_t func, void *arg,
        uint32_t recognize)
{
    xml_reader_input_t *inp;
    const void *begin, *end;
    const ucs4_t *ptr;
    ucs4_t cp, cp0;
    size_t clen, offs, bufsz, total;
    utf8_t *bufptr;
    xru_t rv = XRU_CONTINUE;
    bool saw_cr = false;

    bufptr = h->tokenbuf;
    total = 0;
    h->lastreadloc = h->curloc;
    h->rejected = UCS4_NOCHAR;

    while (rv == XRU_CONTINUE) { // First check the status from inner for-loop...
        // ... and only if we're not terminating yet, try to get next read pointers
        if ((rv = xml_reader_input_rptr(h, &begin, &end)) != XRU_CONTINUE) {
            break;
        }
        inp = SLIST_FIRST(&h->active_input);
        for (ptr = begin;
                rv == XRU_CONTINUE && ptr < (const ucs4_t *)end;
                ptr++) {

            cp0 = *ptr; // codepoint before possible substitution by func
            if (saw_cr && (cp0 == 0x0A || cp0 == 0x85)) {
                // EOL normalization. This is "continuation" of a previous character - so
                // is treated before positioning update.
                saw_cr = false;
                continue;
            }

            /// @todo Normalization check goes here

            // XML processor MUST behave as if it normalized all line breaks
            // in external parsed entities (including the document entity) on input,
            // before parsing, by translating all of the following to a single #xA
            // character:
            // 1. the two-character sequence #xD #xA
            // 2. the two-character sequence #xD #x85
            // 3. the single character #x85
            // 4. the single character #x2028
            // 5. any #xD character that is not immediately followed by #xA or #x85.
            // (we do slightly different but equivalent: translate #xD to #xA immediately
            // and skipping the next character if it is #xA or #x85)
            if (cp0 == 0x0D) {
                saw_cr = true;
                cp0 = 0x0A;
            }
            else if (cp0 == 0x85 || cp0 == 0x2028) {
                cp0 = 0x0A;
            }

            // Check if entity expansion is needed
            if (((ucs4_cheq(cp0, '&') && (recognize & RECOGNIZE_REF) != 0)
                        || (ucs4_cheq(cp0, '%') && (recognize & RECOGNIZE_PEREF) != 0))
                    && !inp->charref) {
                rv = XRU_REFERENCE;
                h->rejected = cp0;
                break;
            }

            /// @todo Check for whitespace and set a flag in reader for later detection of ignorable
            /// (via the argument - when reading chardata, point to a structure that has such flag)
            if ((cp = func(arg, cp0)) == UCS4_STOPCHAR) {
                rv = XRU_STOP;
                h->rejected = cp0;
                break; // This character is rejected
            }

            // Not rejected: check if original input was a disallowed character
            if (!cp0) {
                // Non-fatal: recover by skipping the character
                xml_reader_message_current(h, XMLERR(ERROR, XML, P_Char),
                        "NUL character encountered");
                continue;
            }
            else if (cp0 >= 0x7F && (h->flags & READER_ASCII) != 0) {
                // Only complain once
                h->flags &= ~READER_ASCII;
                xml_reader_message_current(h, XMLERR(ERROR, XML, P_XMLDecl),
                        "Non-ASCII characters in %s", h->declinfo->name);
            }
            else if (!inp->charref && xml_is_restricted(h, cp0)) {
                // Ignore if it came from character reference (if it is prohibited,
                // the character reference parser already complained)
                // Non-fatal: just let the app figure what to do with it
                xml_reader_message_current(h, XMLERR(ERROR, XML, P_Char),
                        "Restricted character U+%04X", cp0);
            }

            // Store the character returned by func and see if func requested a stop
            if (cp & UCS4_LASTCHAR) {
                rv = XRU_STOP; // This character is accepted but is known to be the last
                cp &= ~UCS4_LASTCHAR;
            }

            if (cp != UCS4_NOCHAR) {
                clen = utf8_clen(cp);
                if (bufptr + clen > h->tokenbuf_end) {
                    // Double token storage
                    offs = bufptr - h->tokenbuf;
                    bufsz = 2 * (h->tokenbuf_end - h->tokenbuf);
                    h->tokenbuf = xrealloc(h->tokenbuf, bufsz);
                    h->tokenbuf_end = h->tokenbuf + bufsz;
                    bufptr = h->tokenbuf + offs;
                }
                utf8_store(&bufptr, cp);
                total += clen;
            }

            // If backtracking, go to the outer loop to setup new input. Do not count this
            // character for the position update; we will re-parse it later.
            if (h->backtrack_cnt) {
                break;
            }

            // Character not rejected, update position. Note that we're checking
            // the original character - cp0 - not processed, so that we update position
            // based on actual input.
            if (h->flags & READER_LOCTRACK) {
                xml_reader_update_position(h, cp0);
            }
        }

        // Consumed this block
        xml_reader_input_radvance(h, (const uint8_t *)ptr - (const uint8_t *)begin);

        // If non-trivial backtracking, set up backtracking input and let the outer
        // loop re-read begin/end/ptr. Otherwise, the outer loop will just re-parse
        // the character at *ptr again.
        if (h->backtrack_cnt && h->backtrack_cnt != BACKTRACK_NOADVANCE) {
            OOPS_ASSERT(!inp->backtrack); // Recursive backtracking not allowed

            // 1 character counted above when we broke out of the loop;
            h->curloc.pos -= h->backtrack_cnt - 1;
            inp = xml_reader_input_new(h, NULL);
            strbuf_set_input(inp->buf, h->backtrack, h->backtrack_cnt * sizeof(ucs4_t));
            inp->backtrack = true;
        }
        h->backtrack_cnt = 0;
    }
    h->tokenbuf_len = total;
    return rv;
}

/**
    Read condition: until first non-whitespace.

    @param arg Argument (unused)
    @param cp Codepoint
    @return UCS4_STOPCHAR if @a cp is whitespace, @a cp otherwise
*/
static ucs4_t
xml_cb_not_whitespace(void *arg, ucs4_t cp)
{
    if (xml_is_whitespace(cp)) {
        *(bool *)arg = true;
        return UCS4_NOCHAR;
    }
    return UCS4_STOPCHAR;
}

/**
    Consume whitespace.

    Does not modify the token buffer.

    @param h Reader handle
    @return PR_OK if consumed any whitespace, PR_NOMATCH otherwise.
*/
static prodres_t
xml_parse_whitespace(xml_reader_t *h)
{
    xru_t stopstatus;
    bool had_ws = false;
    size_t tlen;

    // Whitespace may cross entity boundaries; repeat until we get something other
    // than whitespace
    tlen = h->tokenbuf_len;
    do {
        stopstatus = xml_read_until(h, xml_cb_not_whitespace, &had_ws, 0);
    } while (stopstatus == XRU_INPUT_BOUNDARY);
    h->tokenbuf_len = tlen;
    return had_ws ? PR_OK : PR_NOMATCH;
}

/**
    Read condition: until < (left angle bracket)

    @param arg Argument (unused)
    @param cp Codepoint
    @return UCS4_STOPCHAR if @a cp is left angle bracket, @a cp otherwise
*/
static ucs4_t
xml_cb_lt(void *arg, ucs4_t cp)
{
    return ucs4_cheq(cp, '<') ? UCS4_STOPCHAR : UCS4_NOCHAR;
}

/**
    Recovery function: read the next left angle bracket.

    @param h Reader handle
    @return Always PR_OK (either finds the left bracket or reaches EOF)
*/
static prodres_t
xml_read_until_lt(xml_reader_t *h)
{
    xml_read_until(h, xml_cb_lt, NULL, 0);
    return PR_OK;
}

/**
    Read condition: until > (right angle bracket); consume the bracket as well.

    @param arg Argument (unused)
    @param cp Codepoint
    @return UCS4_STOPCHAR if @a cp is next char after a right angle bracket,
        @a cp otherwise
*/
static ucs4_t
xml_cb_gt(void *arg, ucs4_t cp)
{
    return ucs4_cheq(cp, '>') ? UCS4_NOCHAR | UCS4_LASTCHAR : UCS4_NOCHAR;
}

/**
    Recovery function: read until (and including) the next right angle bracket.

    @param h Reader handle
    @return Always PR_OK (either finds the right bracket or reaches EOF)
*/
static prodres_t
xml_read_until_gt(xml_reader_t *h)
{
    xml_read_until(h, xml_cb_gt, NULL, 0);
    return PR_OK;
}

/**
    Read condition: matching Name production.

    @verbatim
    NameStartChar ::= ":" | [A-Z] | "_" | [a-z] | [#xC0-#xD6] | [#xD8-#xF6] |
                       [#xF8-#x2FF] | [#x370-#x37D] | [#x37F-#x1FFF] |
                       [#x200C-#x200D] | [#x2070-#x218F] | [#x2C00-#x2FEF] |
                       [#x3001-#xD7FF] | [#xF900-#xFDCF] | [#xFDF0-#xFFFD] |
                       [#x10000-#xEFFFF]
    NameChar ::= NameStartChar | "-" | "." | [0-9] | #xB7 | [#x0300-#x036F] |
                 [#x203F-#x2040]
    Name ::= NameStartChar (NameChar)*
    @endverbatim

    @param arg Pointer to a boolean: true if first character.
    @param cp Codepoint
    @return UCS4_STOPCHAR if the character does not belong to Name production
*/
static ucs4_t
xml_cb_not_name(void *arg, ucs4_t cp)
{
    bool *isstartchar = arg;
    ucs4_t rv;

    rv = (*isstartchar ? xml_is_NameStartChar(cp) : xml_is_NameChar(cp)) ?
            cp : UCS4_STOPCHAR;
    *isstartchar = false;
    return rv;
}

/**
    Read a Name production.

    @param h Reader handle
    @return PR_OK if Name production has been read, PR_NOMATCH otherwise
*/
static prodres_t
xml_read_Name(xml_reader_t *h)
{
    bool startchar = true;

    // May stop at either non-Name character, or input boundary
    (void)xml_read_until(h, xml_cb_not_name, &startchar, 0);
    if (!h->tokenbuf_len) {
        // No error: this is an auxillary function often used to differentiate between
        // Name or some alternative (e.g. entity vs char references)
        return PR_NOMATCH;
    }
    return PR_OK;
}

/// Current state structure for xml_cb_string
typedef struct xml_cb_string_state_s {
    const char *cur;            ///< Currently expected character
    const char *end;            ///< End of the expected string
} xml_cb_string_state_t;

/**
    Read condition: expect a known string. Matched string must contain
    only ASCII characters.

    @param arg Current matching state
    @param cp Codepoint
    @return Codepoint to insert in token buffer
*/
static ucs4_t
xml_cb_string(void *arg, ucs4_t cp)
{
    xml_cb_string_state_t *st = arg;
    ucs4_t tmp;

    if ((tmp = ucs4_fromlocal(*st->cur)) >= 0x7F || tmp != cp) {
        return UCS4_STOPCHAR;
    }
    // Advance; no need to save into token buffer
    st->cur++;
    return st->cur == st->end ? UCS4_NOCHAR | UCS4_LASTCHAR : UCS4_NOCHAR;
}

/**
    Read an expected string (fixed character sequence of markup).

    Does not modify the token buffer.

    @param h Reader handle
    @param s String expected in the document; must be ASCII-only
    @param errinfo Error to raise on mismatch
    @return PR_OK on success, PR_NOMATCH on failure
*/
static prodres_t
xml_read_string(xml_reader_t *h, const char *s, xmlerr_info_t errinfo)
{
    xml_cb_string_state_t state;
    size_t tlen;

    state.cur = s;
    state.end = s + strlen(s);
    tlen = h->tokenbuf_len;
    if (xml_read_until(h, xml_cb_string, &state, 0) != XRU_STOP
            || state.cur != state.end) {
        if (errinfo != XMLERR_NOERROR) {
            xml_reader_message_lastread(h, errinfo, "Expected string: '%s'", s);
        }
        h->tokenbuf_len = tlen;
        return PR_NOMATCH;
    }
    h->tokenbuf_len = tlen;
    return PR_OK;
}

/// Current state structure for xml_cb_termstring
typedef struct xml_cb_termstring_state_s {
    const char *term;               ///< Terminator string
    const char *cur;                ///< Currently expected character
    const char *end;                ///< End of the expected string
    xml_reader_t *h;                ///< Reader handle to backtrack if needed
    void *arg;                      ///< Argument to mismatch callback

    /// Function to call on mismatch
    void (*func)(void *, size_t);
} xml_cb_termstring_state_t;

/**
    Closure for xml_read_until: read anything until a terminator string is matched.

    @param arg Matching state
    @param cp Current codepoint
    @return Codepoint to insert in token buffer
*/
static ucs4_t
xml_cb_termstring(void *arg, ucs4_t cp)
{
    xml_cb_termstring_state_t *st = arg;
    const char *p;
    xml_reader_t *h;
    ucs4_t tmp;

    tmp = ucs4_fromlocal(*st->cur);
    if (tmp == cp) {
        // Matches the pattern so far, see if it concludes the terminator
        ++st->cur;
        return st->cur == st->end ? UCS4_NOCHAR | UCS4_LASTCHAR : UCS4_NOCHAR;
    }
    if (st->cur == st->term) {
        // Haven't matched anything so far, this character is part of token
        return cp;
    }

    // Notify the callback
    if (st->func) {
        st->func(st->arg, st->cur - st->term);
    }

    // Need to backtrack. Return the first *matched* character - this is not a part
    // of the terminator string. Unget the rest of *matched* characters. Current
    // (unmatched) character will be reprocessed after the backtrack buffer is consumed.
    OOPS_ASSERT(st->cur - st->term <= MAX_BACKTRACK);

    /// @todo Assert that ungot chars are neither newline nor tab nor combining char
    h = st->h;
    for (p = st->term + 1; p < st->cur; p++) {
        h->backtrack[h->backtrack_cnt++] = ucs4_fromlocal(*p);
    }
    if (!h->backtrack_cnt) {
        // We don't need to create an input diversion - just indicate that we'll
        // reparse the current character
        h->backtrack_cnt = BACKTRACK_NOADVANCE;
    }

    st->cur = st->term;
    return ucs4_fromlocal(*st->term);
}

/**
    Read a string until a terminating string is seen. Terminating string itself
    is not stored into the token buffer. Terminator string may not contain
    newlines, tabs or combining characters (location update logic for backtracking
    is very simple-minded).

    @param h Reader handle
    @param s String expected as a terminator
    @param func Function to call in case of we need to backtrack (i.e., if a part
        of the terminator string is seen, but then a mismatch is detected). The
        function shall accept one argument, the number of characters matched before
        a mismatch occurred. NULL if no notifications are requested.
    @param arg Argument to @a func callback
    @return PR_OK on success, PR_NOMATCH if terminator string was not found.
*/
static prodres_t
xml_read_termstring(xml_reader_t *h, const char *s, void (*func)(void *, size_t),
        void *arg)
{
    xml_cb_termstring_state_t st;

    st.term = s;
    st.cur = s;
    st.end = s + strlen(s);
    st.h = h;
    st.func = func;
    st.arg = arg;
    if (xml_read_until(h, xml_cb_termstring, &st, 0) != XRU_STOP || st.cur != st.end) {
        return PR_NOMATCH;
    }
    return PR_OK;
}

/// Current state structure for xml_cb_reference
typedef struct {
    uint32_t val;       ///< Value accumulated so far
    bool hasdigits;     ///< Seen any digits
    bool toobig;        ///< Exceeded the UCS-4 limits
} xml_cb_charref_state_t;


/**
    Read condition: CharRef, decimal.

    @param arg Matching state
    @param cp Next codepoint
    @return codepoint to insert, possibly OR'ed with UCS4_LASTCHAR or UCS4_NOCHAR
*/
static ucs4_t
xml_cb_charref_dec(void *arg, ucs4_t cp)
{
    xml_cb_charref_state_t *st = arg;

    if (ucs4_chin(cp, '0', '9')) {
        st->hasdigits = true;
        if ((st->val = 10 * st->val + cp - ucs4_fromlocal('0')) > UCS4_MAX) {
            st->toobig = true;
        }
        return UCS4_NOCHAR; // no need to store
    }
    return UCS4_STOPCHAR;
}

/**
    Read condition: CharRef, hexadecimal.

    @param arg Matching state
    @param cp Next codepoint
    @return codepoint to insert, possibly OR'ed with UCS4_LASTCHAR or UCS4_NOCHAR
*/
static ucs4_t
xml_cb_charref_hex(void *arg, ucs4_t cp)
{
    xml_cb_charref_state_t *st = arg;

    if (ucs4_chin(cp, '0', '9')) {
        st->hasdigits = true;
        if ((st->val = 16 * st->val + cp - ucs4_fromlocal('0')) > UCS4_MAX) {
            st->toobig = true;
        }
        return UCS4_NOCHAR; // no need to store
    }
    if (ucs4_chin(cp, 'a', 'f')) {
        st->hasdigits = true;
        if ((st->val = 16 * st->val + cp - ucs4_fromlocal('a') + 10) > UCS4_MAX) {
            st->toobig = true;
        }
        return UCS4_NOCHAR; // no need to store
    }
    if (ucs4_chin(cp, 'A', 'F')) {
        st->hasdigits = true;
        if ((st->val = 16 * st->val + cp - ucs4_fromlocal('A') + 10) > UCS4_MAX) {
            st->toobig = true;
        }
        return UCS4_NOCHAR; // no need to store
    }
    return UCS4_STOPCHAR;
}

/**
    Return entity type description for error messages.

    @param type Type of the reference
    @return Entity type information
*/
static const xml_reference_info_t *
xml_entity_type_info(enum xml_reader_reference_e type)
{
    static const xml_reference_info_t refinfo[] = {
        [XML_READER_REF_PARAMETER] = { "parameter entity", XMLERR_XML_P_PEReference },
        [XML_READER_REF_INTERNAL] = { "internal general entity", XMLERR_XML_P_EntityRef },
        [XML_READER_REF_EXTERNAL] = { "external parsed general entity", XMLERR_XML_P_EntityRef },
        [XML_READER_REF_UNPARSED] = { "external unparsed general entity", XMLERR_XML_P_EntityRef },
        [XML_READER_REF__CHAR] = { "character", XMLERR_XML_P_CharRef },
        [XML_READER_REF__MAX] = { "???", XMLERR_XML_P_EntityRef },
        [XML_READER_REF_GENERAL] = { "general entity", XMLERR_XML_P_EntityRef},
        [XML_READER_REF__UNKNOWN] = { "unknown",  XMLERR_XML_P_Reference },
    };

    return &refinfo[type < sizeofarray(refinfo) ? type : XML_READER_REF__MAX];
}

/**
    Read entity name or (for character references) the code point. Must be entered when
    the next rejected character is the start of the entity.

    @verbatim
    EntityRef   ::= '&' Name ';'
    CharRef     ::= '&#' [0-9]+ ';' | '&#x' [0-9a-fA-F]+ ';'
    PEReference ::= '%' Name ';'
    @endverbatim

    @param h Reader handle
    @param reftype Entity type determined by parsing
    @return PR_OK if parsed successfully, PR_FAIL otherwise
*/
static prodres_t
xml_parse_reference(xml_reader_t *h, enum xml_reader_reference_e *reftype)
{
    xml_cb_charref_state_t st;
    const xml_reference_info_t *ri;
    xmlerr_loc_t saveloc;           // Report reference at the start character
    xru_t rv;
    ucs4_t startchar = h->rejected;

    // We know startchar is there, it has been rejected by previous call
    if (ucs4_cheq(startchar, '&')) {
        // This may be either entity or character reference
        (void)xml_read_string(h, "&", XMLERR_NOERROR);
        saveloc = h->lastreadloc;
        if (xml_read_Name(h) == PR_OK) {
            // EntityRef
            *reftype = XML_READER_REF_GENERAL;
            goto read_content;
        }
        else if (ucs4_cheq(h->rejected, '#')) {
            // CharRef
            *reftype = XML_READER_REF__CHAR;
            (void)xml_read_string(h, "#", XMLERR_NOERROR); // Again, known to be present
            st.val = 0;
            st.hasdigits = false;
            st.toobig = false;
            if (xml_read_string(h, "x", XMLERR_NOERROR) == PR_OK) {
                // Using hexadecimal form
                rv = xml_read_until(h, xml_cb_charref_hex, &st, 0);
            }
            else {
                // Using decimal form
                rv = xml_read_until(h, xml_cb_charref_dec, &st, 0);
            }
            if (rv != XRU_STOP || !st.hasdigits) {
                goto malformed;
            }
            h->charrefval = st.toobig ? UCS4_NOCHAR : st.val;
            goto read_content;
        }
        else {
            // What the ... reference is this?
            *reftype = XML_READER_REF__UNKNOWN;
            goto malformed;
        }
    }
    else if (ucs4_cheq(startchar, '%')) {
        // PEReference
        (void)xml_read_string(h, "%", XMLERR_NOERROR);
        saveloc = h->lastreadloc;
        *reftype = XML_READER_REF_PARAMETER;
        if (xml_read_Name(h) == PR_OK) {
            goto read_content;
        }
        goto malformed;
    }
    else {
        // How did we get here?
        OOPS;
    }

read_content:
    ri = xml_entity_type_info(*reftype);
    // Reading as a whole - if fail to match string, error will be raised below
    if (xml_read_string(h, ";", XMLERR_NOERROR) != PR_OK) {
        goto malformed;
    }
    h->lastreadloc = saveloc;
    return PR_OK;

malformed:
    ri = xml_entity_type_info(*reftype);
    h->lastreadloc = saveloc;
    xml_reader_message_lastread(h, XMLERR_MK(XMLERR_ERROR, XMLERR_SPEC_XML, ri->ecode),
            "Malformed %s reference", ri->desc);
    return PR_NOMATCH;
}

/**
    Determine if a character reference to the specified code point is allowed by
    this XML version.

    @param h Reader handle
    @param cp Code point
    @return true if the character is allowed, false otherwise
*/
static bool
xml_valid_char_reference(xml_reader_t *h, ucs4_t cp)
{
    // First check if it is disallowed in any version
    if (!cp
            || (cp >= UCS4_SURROGATE_MIN && cp <= UCS4_SURROGATE_MAX)
            || cp == 0xFFFE
            || cp == 0xFFFF) {
        return false;
    }

    // The rest is allowed in XML 1.1
    if (h->version == XML_INFO_VERSION_1_1) {
        return true;
    }

    // In XML 1.0, restricted characters are prohibited even via character references
    return !xml_is_restricted(h, cp);
}

/**
    When entity finishes parsing, mark it available for other references.

    @param h Reader handle
    @param arg Entity being parsed
    @return Nothing
*/
static void
entity_input_end(xml_reader_t *h, void *arg)
{
    xml_reader_input_t *inp = arg;
    xml_reader_entity_t *e = inp->entity;
    xml_reader_cbparam_t cbp;

    cbp.cbtype = XML_READER_CB_ENTITY_END;
    cbp.loc = h->curloc;
    cbp.entity.type = e->type;
    cbp.entity.name = NULL;
    cbp.entity.namelen = 0;
    cbp.entity.system_id = e->system_id;
    cbp.entity.public_id = e->system_id ? e->public_id : NULL; // Only for external entities
    cbp.entity.baton = inp->baton;
    xml_reader_invoke_callback(h, &cbp);

    inp->entity->being_parsed = false;
}

/**
    Entity handler: 'Forbidden'

    @param h Reader handle
    @param e Entity information
    @return Nothing
*/
static void
reference_forbidden(xml_reader_t *h, xml_reader_entity_t *e)
{
    const xml_reference_info_t *ri;

    ri = xml_entity_type_info(e->type);
    xml_reader_message_lastread(h, XMLERR_MK(XMLERR_ERROR, XMLERR_SPEC_XML, ri->ecode),
            "%s reference is forbidden here", ri->desc);
}

/**
    Entity handler: 'Included in literal'

    @param h Reader handle
    @param e Entity information
    @param inc_in_literal True if 'included in literal'
    @return Nothing
*/
static void
reference_included_common(xml_reader_t *h, xml_reader_entity_t *e, bool inc_in_literal)
{
    xml_reader_input_t *inp;
    xml_reader_cbparam_t cbp;

    cbp.cbtype = XML_READER_CB_ENTITY_START;
    cbp.loc = h->lastreadloc;
    cbp.entity.type = e->type;
    cbp.entity.name = h->tokenbuf;
    cbp.entity.namelen = h->tokenbuf_len;
    cbp.entity.system_id = e->system_id;
    cbp.entity.public_id = e->system_id ? e->public_id : NULL; // Only for external entities
    cbp.entity.baton = NULL;
    xml_reader_invoke_callback(h, &cbp);

    OOPS_ASSERT(e->system_id == NULL); // Must be internal entity
    e->being_parsed = true;
    inp = xml_reader_input_new(h, e->location);
    strbuf_set_input(inp->buf, e->rplc, e->rplclen);
    inp->entity = e;
    inp->inc_in_literal = inc_in_literal;
    inp->baton = cbp.entity.baton;

    inp->complete = entity_input_end;
    inp->complete_arg = inp;
}

/**
    Entity handler: 'Included in literal'

    @param h Reader handle
    @param e Entity information
    @return Nothing
*/
static void
reference_included_in_literal(xml_reader_t *h, xml_reader_entity_t *e)
{
    reference_included_common(h, e, true);
}

/**
    Entity handler: 'Included'

    @param h Reader handle
    @param e Entity information
    @return Nothing
*/
static void
reference_included(xml_reader_t *h, xml_reader_entity_t *e)
{
    reference_included_common(h, e, false);
}

/**
    Entity handler: 'Included if validating'

    @param h Reader handle
    @param e Entity information
    @return Nothing
*/
static void
reference_included_if_validating(xml_reader_t *h, xml_reader_entity_t *e)
{
    /// @todo Implement
}

/**
    Character reference handler: 'Included' (for character references,
    the rules are slightly different).

    @param h Reader handle
    @param e Entity information, if any
    @return Nothing
*/
static void
reference_included_charref(xml_reader_t *h, xml_reader_entity_t *e)
{
    xml_reader_input_t *inp;

    inp = xml_reader_input_new(h, e->location);
    strbuf_set_input(inp->buf, e->rplc, e->rplclen);

    // Character reference behavior is close to what's described in XML spec as
    // 'Included in literal' (i.e., in literal the character reference to the quote
    // character does not terminate the literal). They also can represent references
    // to start characters which will not be recognized by xml_read_internal.
    inp->inc_in_literal = true;
    inp->charref = true;
}

/**
    Handler for text block in literals or content: invoke callback to append text.

    @param h Reader handle
    @return Nothing
*/
static void
textblock_append(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;

    if (h->tokenbuf_len) {
        cbp.cbtype = XML_READER_CB_APPEND;
        cbp.loc = h->lastreadloc;
        cbp.append.text = h->tokenbuf;
        cbp.append.textlen = h->tokenbuf_len;
        xml_reader_invoke_callback(h, &cbp);
    }
}

/**
    Wrapper around xml_read_until(): if entities are recognized and
    xml_read_until() returned due to start of an entity, issue
    a callback to expand that entity and if that callback returned
    the replacement text, divert the reader's input to that entity.
    Otherwise, skip over the entity and continue.

    @param h Reader handle
    @param func Function to call to check for the condition
    @param arg Argument to @a func
    @param refops Actions to perform when encountering an entity, or
        a contiguous text block; also a mask of recognized entities.
    @return Status why the parser terminated
*/
static xru_t
xml_read_until_parseref(xml_reader_t *h, xml_condread_func_t func, void *arg,
        const xml_reference_ops_t *refops)
{
    xru_t stopstatus;
    xml_reader_cbparam_t cbp;
    enum xml_reader_reference_e reftype;
    xml_reader_entity_t *e;
    xml_reader_entity_t fakechar;

    while (true) {
        do {
            stopstatus = xml_read_until(h, func, arg, refops->flags);
            if (refops->textblock) {
                refops->textblock(h);
            }
        } while (stopstatus == XRU_INPUT_BOUNDARY);

        if (stopstatus != XRU_REFERENCE) {
            return stopstatus; // Saw the terminating condition or EOF
        }

        // We have some kind of entity, read its name or code point
        if (xml_parse_reference(h, &reftype) != PR_OK) {
            // no recovery - interpret anything after error as plain text
            continue;
        }

        switch (reftype) {
        case XML_READER_REF__CHAR:
            /* Parse the character referenced */
            if (h->charrefval == UCS4_NOCHAR) {
                // Did not evaluate to a character; recover by skipping.
                xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_CharRef),
                        "Character reference did not evaluate to a valid "
                        "UCS-4 code point");
                continue;
            }
            if (!xml_valid_char_reference(h, h->charrefval)) {
                // Recover by skipping invalid character.
                xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_CharRef),
                        "Referenced character does not match Char production");
                continue;
            }
            fakechar.type = XML_READER_REF__CHAR;
            fakechar.system_id = NULL;
            fakechar.location = "character reference";
            fakechar.being_parsed = false;
            fakechar.rplc = &h->charrefval;
            fakechar.rplclen = sizeof(h->charrefval);
            e = &fakechar;
            break;

        case XML_READER_REF_GENERAL:
            // Clarify the type
            e = strhash_getn(h->share->entities_gen, h->tokenbuf, h->tokenbuf_len);
            break;

        case XML_READER_REF_PARAMETER:
            e = strhash_getn(h->share->entities_param, h->tokenbuf, h->tokenbuf_len);
            break;

        default:
            OOPS;
        }

        if (!e) {
            // Entity was not known. This may or may not be error; let the callback decide
            cbp.cbtype = XML_READER_CB_ENTITY_UNKNOWN;
            cbp.loc = h->lastreadloc;
            cbp.entity.type = reftype; // Our best guess
            cbp.entity.name = h->tokenbuf;
            cbp.entity.namelen = h->tokenbuf_len;
            cbp.entity.system_id = NULL;
            cbp.entity.public_id = NULL;
            cbp.entity.baton = NULL;
            xml_reader_invoke_callback(h, &cbp);
        }
        else if (refops->hnd[e->type]) {
            refops->hnd[e->type](h, e);
        }
        else {
            // Flags setting in refops should've prevented us from recognizing this reference
            OOPS;
        }
    }
}

/// Callback state for literal reading
typedef struct xml_cb_literal_state_s {
    /// UCS4_NOCHAR at start, quote seen in progress, or UCS4_STOPCHAR if saw final quote
    ucs4_t quote;
    /// Reader handle (need to check the state of the current input
    xml_reader_t *h;
} xml_cb_literal_state_t;

/**
    Closure for xml_read_until: expect an initial quote, then read
    up until (and including) a matching end quote.

    @todo Perhaps, normalize attributes here (in callback) to avoid extra copies

    @param arg Current state
    @param cp Codepoint
    @return true if this character is rejected
*/
static ucs4_t
xml_cb_literal(void *arg, ucs4_t cp)
{
    xml_cb_literal_state_t *st = arg;

    if (st->quote == UCS4_NOCHAR) {
        // Starting matching
        if (!ucs4_cheq(cp, '"') && !ucs4_cheq(cp, '\'')) {
            return UCS4_STOPCHAR; // Rejected before even started
        }
        st->quote = cp;
        return UCS4_NOCHAR; // Remember the quote, but do not store it
    }
    else {
        if (cp != st->quote || SLIST_FIRST(&st->h->active_input)->inc_in_literal) {
            return cp; // Content
        }
        // Consume the closing quote and stop at the next character
        st->quote = UCS4_STOPCHAR;
        return UCS4_NOCHAR | UCS4_LASTCHAR;
    }
}

/**
    Read a literal (EntityValue, AttValue, SystemLiteral, PubidLiteral).
    Also handles "pseudo-literals" (pseudo-attribute values defined
    in the XMLDecl/TextDecl).

    @param h Reader handle
    @param refops Literal's "virtual method table" for handling references
    @return PR_OK if parsed successfully, PR_FAIL otherwise
        end quote).
*/
static prodres_t
xml_parse_literal(xml_reader_t *h, const xml_reference_ops_t *refops)
{
    xml_cb_literal_state_t st;

    // xml_read_until() may return 0 (empty literal), which is valid
    st.quote = UCS4_NOCHAR;
    st.h = h;
    if (xml_read_until_parseref(h, xml_cb_literal, &st, refops) != XRU_STOP
            || st.quote != UCS4_STOPCHAR) {
        xml_reader_message_lastread(h, refops->errinfo,
                st.quote == UCS4_NOCHAR ?
                "Quoted literal expected" : "Unterminated literal");
        return PR_FAIL;
    }
    return PR_OK;
}

/// Virtual methods for reading "pseudo-literals" (quoted strings in XMLDecl)
static const xml_reference_ops_t reference_ops_pseudo = {
    .errinfo = XMLERR(ERROR, XML, P_XMLDecl),
    .flags = 0,
    .hnd = { /* No entities expected */ },
};

/// Virtual methods for reading "pseudo-literals" (quoted strings in XMLDecl)
static const xml_reference_ops_t reference_ops_AttValue = {
    .errinfo = XMLERR(ERROR, XML, P_Attribute),
    .flags = RECOGNIZE_REF,
    .textblock = textblock_append,
    .hnd = {
        /* Default: 'Not recognized' */
        [XML_READER_REF_INTERNAL] = reference_included_in_literal,
        [XML_READER_REF_EXTERNAL] = reference_forbidden,
        [XML_READER_REF_UNPARSED] = reference_forbidden,
        [XML_READER_REF__CHAR] = reference_included_charref,
    },
};

/// Virtual methods for reading CharData production
static const xml_reference_ops_t reference_ops_CharData = {
    .errinfo = XMLERR(ERROR, XML, P_CharData),
    .flags = RECOGNIZE_REF,
    .textblock = textblock_append,
    .hnd = {
        /* Default: 'Not recognized' */
        [XML_READER_REF_INTERNAL] = reference_included,
        [XML_READER_REF_EXTERNAL] = reference_included_if_validating,
        [XML_READER_REF_UNPARSED] = reference_forbidden,
        [XML_READER_REF__CHAR] = reference_included_charref,
    },
};

/**
    Check for VersionInfo production.

    @verbatim
    VersionNum ::= '1.' [0-9]+    {{XML1.0}}
    VersionNum ::= '1.1'          {{XML1.1}}
    @endverbatim

    @param h Reader handle
    @return Nothing
*/
static void
check_VersionInfo(xml_reader_t *h)
{
    const utf8_t *str = h->tokenbuf;
    size_t sz = h->tokenbuf_len;
    size_t i;

    if (sz == 3) {
        if (utf8_eqn(str, "1.0", 3)) {
            h->version = XML_INFO_VERSION_1_0;
            return;
        }
        else if (utf8_eqn(str, "1.1", 3)) {
            h->version = XML_INFO_VERSION_1_1;
            return;
        }
    }
    if (sz < 3 || !utf8_eqn(str, "1.", 2)) {
        goto bad_version;
    }
    for (i = 2, str += 2; i < sz; i++, str++) {
        if (!ucs4_chin(*str, '0', '9')) {
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
    h->version = XML_INFO_VERSION_1_0;
    xml_reader_message_lastread(h, XMLERR(WARN, XML, FUTURE_VERSION),
            "Document specifies unknown 1.x XML version");
    return; // Normal return

bad_version:
    // Non-fatal: recover by assuming version was missing
    xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_XMLDecl),
            "Unsupported XML version");
    return;
}

/**
    Check if encoding name matches the EncName production:

    @verbatim
    EncName  ::= [A-Za-z] ([A-Za-z0-9._] | '-')*
    @endverbatim

    @param h Reader handle
    @return Nothing
*/
static void
check_EncName(xml_reader_t *h)
{
    const utf8_t *str = h->tokenbuf;
    const utf8_t *s;
    size_t sz = h->tokenbuf_len;
    size_t i;

    for (i = 0, s = str; i < sz; i++, s++) {
        if (ucs4_chin(*s, 'A', 'Z') || ucs4_chin(*s, 'a', 'z')) {
            continue;
        }
        if (!i) {
            goto bad_encoding;
        }
        if (!ucs4_chin(*s, '0', '9')
                && !ucs4_cheq(*s, '.')
                && !ucs4_cheq(*s, '_')
                && !ucs4_cheq(*s, '-')) {
            goto bad_encoding;
        }
    }

    h->enc_xmldecl = utf8_ndup(str, sz);
    return; // Normal return

bad_encoding:
    // Non-fatal: recover by assuming no encoding specification
    xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_XMLDecl),
            "Invalid encoding name");
    return;
}

/**
    Check for 'yes' or 'no' string. This is used as a value in SDDecl
    production, but this part has no separate production name.

    @verbatim
       <anonymous> ::= 'yes' | 'no'
    @endverbatim

    @param h Reader handle
    @return Nothing
*/
static void
check_SD_YesNo(xml_reader_t *h)
{
    const utf8_t *str = h->tokenbuf;
    size_t sz = h->tokenbuf_len;

    if (sz == 2 && utf8_eqn(str, "no", 2)) {
        h->standalone = XML_INFO_STANDALONE_NO;
    }
    else if (sz == 3 && utf8_eqn(str, "yes", 3)) {
        h->standalone = XML_INFO_STANDALONE_YES;
    }
    else {
        // Non-fatal: recover by assuming standalone was not specified
        xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_XMLDecl),
                "Unsupported standalone status");
    }
}

/**
    Handler for TextDecl production.

    @verbatim
    TextDecl ::= '<?xml' VersionInfo? EncodingDecl S? '?>'
    @endverbatim
*/
static const struct xml_reader_xmldecl_declinfo_s declinfo_textdecl = {
    .name = "TextDecl",
    .attrlist = (const xml_reader_xmldecl_attrdesc_t[]){
        { "version", false, check_VersionInfo },
        { "encoding", true, check_EncName },
        { NULL, false, NULL },
    },
};

/**
    Handle for XMLDecl production.
    
    @verbatim
    XMLDecl  ::= '<?xml' VersionInfo EncodingDecl? SDDecl? S? '?>'
    @endverbatim
*/
static const struct xml_reader_xmldecl_declinfo_s declinfo_xmldecl = {
    .name = "XMLDecl",
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

    @verbatim
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
    @endverbatim

    @param h Reader handle
    @return PR_OK (this function does its own recovery)
*/
static prodres_t
xml_parse_XMLDecl_TextDecl(xml_reader_t *h)
{
    const xml_reader_xmldecl_declinfo_t *declinfo = h->declinfo;
    const xml_reader_xmldecl_attrdesc_t *attrlist = declinfo->attrlist;
    xml_reader_cbparam_t cbp;
    utf8_t labuf[6]; // ['<?xml' + whitespace] or [?>]
    bool had_ws;

    if (6 != xml_lookahead(h, labuf, 6, NULL)
            || !utf8_eqn(labuf, "<?xml", 5)
            || !xml_is_whitespace(labuf[5])) {
        return PR_NOMATCH; // Does not start with a declaration
    }

    // We know it's there, checked above
    (void)xml_read_string(h, "<?xml", XMLERR(ERROR, XML, P_XMLDecl));
    cbp.cbtype = XML_READER_CB_XMLDECL;
    cbp.loc = h->lastreadloc;

    while (true) {
        had_ws = xml_parse_whitespace(h) == PR_OK;

        // From the productions above, we expect either closing ?> or Name=Literal.
        // If it was a Name, it is further checked against the expected
        // attribute list and Literal is then verified for begin a valid value
        // for Name.
        if (ucs4_cheq(h->rejected, '?')) {
            if (xml_read_string(h, "?>", XMLERR(ERROR, XML, P_XMLDecl)) != PR_OK) {
                goto malformed;
            }
            break;
        }
        // We may have no whitespace before final ?>, but must get some before
        // pseudo-attributes.
        if (!had_ws || xml_read_Name(h) != PR_OK) {
            goto malformed;
        }

        // Go through the remaining attributes and see if this one is known
        // (and if we skipped any mandatory attributes while advancing).
        while (attrlist->name) {
            if (h->tokenbuf_len == strlen(attrlist->name)
                    && utf8_eqn(h->tokenbuf, attrlist->name, h->tokenbuf_len)) {
                break; // Yes, that is what we expect
            }
            if (attrlist->mandatory) {
                // Non-fatal: continue with next pseudo-attributes
                xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_XMLDecl),
                        "Mandatory pseudo-attribute '%s' missing in %s",
                        attrlist->name, declinfo->name);
            }
            attrlist++;
        }
        if (!attrlist->name) {
            // Non-fatal: continue parsing as if matching the following production
            //   Name Eq ('"' (Char - '"')* '"' | "'" (Char - "'")* "'")
            xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_XMLDecl),
                    "Unexpected pseudo-attribute");
        }

        // Parse Eq production
        (void)xml_parse_whitespace(h);
        if (xml_read_string(h, "=", XMLERR(ERROR, XML, P_XMLDecl)) != PR_OK) {
            goto malformed;
        }
        (void)xml_parse_whitespace(h);
        if (xml_parse_literal(h, &reference_ops_pseudo) != PR_OK) {
            goto malformed;
        }

        if (attrlist->name) {
            // Check/get value and advance to the next attribute
            attrlist->check(h);
            attrlist++;
        }
    }

    // Check if any remaining mandatory attributes were omitted
    while (attrlist->name) {
        if (attrlist->mandatory) {
            // Non-fatal: just assume the default
            xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_XMLDecl),
                    "Mandatory pseudo-attribute '%s' missing in %s",
                    attrlist->name, declinfo->name);
        }
        attrlist++;
    }

    // Secret knowledge: xml_reader_start() will do some further checks
    // that involve XMLDecl; we want them reported at the start of the
    // declaration. Pass it back via h->lastreadloc.
    h->lastreadloc = cbp.loc;

    // Emit an event (callback) for XML declaration
    cbp.xmldecl.encoding = h->enc_xmldecl;
    cbp.xmldecl.version = h->version;
    cbp.xmldecl.standalone = h->standalone;
    xml_reader_invoke_callback(h, &cbp);

    return PR_OK;

malformed: // Any fatal malformedness: report location where actual error was
    h->flags |= READER_FATAL;
    xml_reader_message_current(h, XMLERR(ERROR, XML, P_XMLDecl),
            "Malformed %s", declinfo->name);
    return PR_FAIL;
}

/**
    Callback to find the end of the character data.

    @param arg Reader handle (cast to void pointer)
    @param cp Current codepoint
    @return Nothing
*/
static ucs4_t
xml_cb_CharData(void *arg, ucs4_t cp)
{
    xml_reader_t *h = arg;

    if (!ucs4_cheq(cp, '<') || SLIST_FIRST(&h->active_input)->charref) {
        return cp;
    }
    return UCS4_STOPCHAR;
}


/**
    Read and process CharData (text "node"). Character and entity references are
    also recognized by this function, using the same common reference parser.

    @verbatim
    CharData ::= [^<&]* - ([^<&]* ']]>' [^<&]*)
    @endverbatim

    @param h Reader handle
    @return PR_OK if parsed successfully.
*/
static prodres_t
xml_parse_CharData(xml_reader_t *h)
{
    (void)xml_read_until_parseref(h, xml_cb_CharData, h, &reference_ops_CharData);
    return PR_OK;
}

/// State structure for comment backtrack handler
typedef struct {
    xml_reader_t *h;    ///< Reader handle
    bool warned;        ///< 1 error per comment
} comment_backtrack_handler_t;

/**
    If comment parser backtracks after 2 characters (--), it is an error.
    For compatibility, the string "--" (double-hyphen) MUST NOT occur within
    comments.

    @param arg State structure
    @param nch Number of characters matched before backtracking
    @return Nothing
*/
static void
comment_backtrack_handler(void *arg, size_t nch)
{
    comment_backtrack_handler_t *cbh = arg;

    if (nch == 2 && !cbh->warned) {
        xml_reader_message_current(cbh->h, XMLERR(ERROR, XML, P_Comment),
                "Double hyphen must not occur within comments");
        cbh->warned = true;
    }
}

/**
    Read and process a single XML comment, starting with <!-- and ending with -->.

    @verbatim
    Comment ::= '<!--' ((Char - '-') | ('-' (Char - '-')))* '-->'
    @endverbatim

    @param h Reader handle
    @return PR_OK if parsed successfully.
*/
static prodres_t
xml_parse_Comment(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;
    comment_backtrack_handler_t cbh;

    if (xml_read_string(h, "<!--", XMLERR(ERROR, XML, P_Comment)) != PR_OK) {
        return PR_NOMATCH; // Shouldn't have been called in this case
    }

    cbp.cbtype = XML_READER_CB_COMMENT;
    cbp.loc = h->lastreadloc;

    cbh.h = h;
    cbh.warned = false;
    if (xml_read_termstring(h, "-->", comment_backtrack_handler, &cbh) != PR_OK) {
        // no need to recover (EOF)
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_Comment),
                "Unterminated comment");
        return PR_STOP;
    }
    cbp.comment.content = h->tokenbuf;
    cbp.comment.contentlen = h->tokenbuf_len;
    xml_reader_invoke_callback(h, &cbp);
    return PR_OK;
}

/**
    Read and process a processing instruction, starting with <? and ending with ?>.

    @verbatim
    PI       ::= '<?' PITarget (S (Char* - (Char* '?>' Char*)))? '?>'
    PITarget ::= Name - (('X' | 'x') ('M' | 'm') ('L' | 'l'))
    @endverbatim

    @todo Have a registry of known PI targets and how to handle them (xml-model,
    xml-stylesheet, anything else?)

    @todo Implement <?xml ... ?> as a PI target with pseudo-attributes? Note that the
    pseudo-attributes in <?xml ... ?> do not allow reference substitutions, and the
    order of pseudo-attributes in xml-{model,stylesheet} is not fixed

    @param h Reader handle
    @return PR_OK if parsed successfully.
*/
static prodres_t
xml_parse_PI(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;

    if (xml_read_string(h, "<?", XMLERR(ERROR, XML, P_PI)) != PR_OK) {
        return PR_NOMATCH; // Shouldn't have been called in this case
    }

    cbp.cbtype = XML_READER_CB_PI_TARGET;
    cbp.loc = h->lastreadloc;
    if (xml_read_Name(h) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_PI),
                "Expected PI target here");
        return xml_read_until_gt(h);
    }
    /// @todo Check for XML-reserved names ([Xx][Mm][Ll]*)

    cbp.pi_target.name = h->tokenbuf;
    cbp.pi_target.namelen = h->tokenbuf_len;
    xml_reader_invoke_callback(h, &cbp);

    // Content, if any, must be separated by a whitespace
    if (xml_parse_whitespace(h) == PR_OK) {
        // Whitespace; everything up to closing ?> is the content
        if (xml_read_termstring(h, "?>", NULL, NULL) == PR_OK) {
            cbp.cbtype = XML_READER_CB_PI_CONTENT;
            cbp.pi_content.content = h->tokenbuf;
            cbp.pi_content.contentlen = h->tokenbuf_len;
            xml_reader_invoke_callback(h, &cbp);
            return PR_OK;
        }
        else {
            // no need to recover (EOF)
            xml_reader_message_current(h, XMLERR(ERROR, XML, P_PI),
                    "Unterminated processing instruction");
            return PR_STOP;
        }
    }
    else if (xml_read_string(h, "?>", XMLERR(ERROR, XML, P_PI)) == PR_OK) {
        // We could only have closing ?> if there's no whitespace after PI target.
        // There is no content in this case.
        return PR_OK;
    }

    // Recover by skipping until closing angle bracket
    return xml_read_until_gt(h);
}

/**
    Read and process a CDATA section.

    @verbatime
    CDSect      ::= CDStart CData CDEnd
    CDStart     ::= '<![CDATA['
    CData       ::= (Char* - (Char* ']]>' Char*))
    CDEnd       ::= ']]>'
    @endverbatim

    @param h Reader handle
    @return PR_OK if parsed successfully.
*/
static prodres_t
xml_parse_CDSect(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;

    if (xml_read_string(h, "<![CDATA[", XMLERR(ERROR, XML, P_CDSect)) != PR_OK) {
        return PR_NOMATCH; // Shouldn't have been called in this case
    }

    cbp.cbtype = XML_READER_CB_CDSECT;
    cbp.loc = h->lastreadloc;
    if (xml_read_termstring(h, "]]>", NULL, NULL) != PR_OK) {
        // no need to recover (EOF)
        /// @todo Test unterminated comments/PIs/CDATA in entities - is PR_STOP proper here?
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_CDSect),
                "Unterminated CDATA section");
        return PR_STOP;
    }
    cbp.append.text = h->tokenbuf;
    cbp.append.textlen = h->tokenbuf_len;
    xml_reader_invoke_callback(h, &cbp);
    return PR_OK;
}

/**
    Read and process a document type declaration; the declaration may reference
    an external subset and contain an internal subset, or have both, or none.

    @param h Reader handle
    @return PR_OK if parsed successfully.
*/
static prodres_t
xml_parse_doctypedecl(xml_reader_t *h)
{
    /// @todo Implement
    return xml_read_until_gt(h);
}

/**
    Read and process STag/EmptyElemTag productions.
    Both productions are the same with the exception of the final part:

    @verbatim
    STag         ::= '<' Name (S Attribute)* S? '>'
    EmptyElemTag ::= '<' Name (S Attribute)* S? '/>'
    Attribute    ::= Name Eq AttValue
    AttValue     ::= '"' ([^<&"] | Reference)* '"' | "'" ([^<&'] | Reference)* "'"
    Eq           ::= S? '=' S?
    @endverbatim

    @param h Reader handle
    @return PR_OK if parsed successfully or recovered, PR_NOMATCH on (unexpected) error
*/
static prodres_t
xml_parse_STag_EmptyElemTag(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;
    bool had_ws;
    bool is_empty;

    if (xml_read_string(h, "<", XMLERR(ERROR, XML, P_STag)) != PR_OK) {
        return PR_NOMATCH; // This function should not be called unless looked ahead
    }

    cbp.cbtype = XML_READER_CB_STAG;
    cbp.loc = h->lastreadloc;

    if (xml_read_Name(h) != PR_OK) {
        // No valid name - try to recover by skipping until closing bracket
        xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_STag),
                "Expected element type");
        goto malformed;
    }

    // Notify the application that a new element has started
    cbp.stag.type = h->tokenbuf;
    cbp.stag.typelen = h->tokenbuf_len;
    xml_reader_invoke_callback(h, &cbp);

    while (true) {
        had_ws = xml_parse_whitespace(h) == PR_OK;
        if (ucs4_cheq(h->rejected, '/')) {
            if (xml_read_string(h, "/>", XMLERR(ERROR, XML, P_STag)) != PR_OK) {
                goto malformed;
            }
            is_empty = true;
            break;
        }
        else if (ucs4_cheq(h->rejected, '>')) {
            if (xml_read_string(h, ">", XMLERR(ERROR, XML, P_STag)) != PR_OK) {
                OOPS; // Cannot fail - we looked ahead
            }
            is_empty = false;
            h->nestlvl++; // Opened element
            break;
        }
        else if (had_ws && xml_read_Name(h) == PR_OK) {
            // Attribute, if any, must be preceded by S (whitespace).
            cbp.cbtype = XML_READER_CB_ATTR;
            cbp.loc = h->lastreadloc;
            cbp.attr.name = h->tokenbuf;
            cbp.attr.namelen = h->tokenbuf_len;
            /// @todo Get attribute value normalization type from callback and
            /// use it for reading attribute value below
            xml_reader_invoke_callback(h, &cbp);
            (void)xml_parse_whitespace(h);
            if (xml_read_string(h, "=", XMLERR(ERROR, XML, P_Attribute)) != PR_OK) {
                goto malformed;
            }
            (void)xml_parse_whitespace(h);
            if (xml_parse_literal(h, &reference_ops_AttValue) != PR_OK) {
                goto malformed;
            }
        }
        else {
            // Try to recover by reading till end of opening tag
            xml_reader_message_current(h, XMLERR(ERROR, XML, P_STag),
                    "Expect whitespace, or >, or />");
            goto malformed;
        }
    }

    // Notify the app
    cbp.cbtype = XML_READER_CB_STAG_END;
    cbp.loc = h->lastreadloc;
    cbp.stag_end.is_empty = is_empty;
    xml_reader_invoke_callback(h, &cbp);
    return PR_OK;

malformed:
    // Try to recover by reading till end of opening tag
    return xml_read_until_gt(h);
}

/**
    Read and process ETag production.

    @verbatim
    ETag ::= '</' Name S? '>'
    @endverbatim

    Additionally, Name in ETag must match the element type in STag.

    @param h Reader handle
    @return PR_OK if parsed successfully, PR_NOMATCH
*/
static prodres_t
xml_parse_ETag(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;

    if (xml_read_string(h, "</", XMLERR(ERROR, XML, P_ETag)) != PR_OK) {
        return PR_NOMATCH; // This function should not be called unless looked ahead
    }
    cbp.cbtype = XML_READER_CB_ETAG;
    cbp.loc = h->lastreadloc;
    if (xml_read_Name(h) != PR_OK) {
        // No valid name - try to recover by skipping until closing bracket
        xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_ETag),
                "Expected element type");
        return xml_read_until_gt(h);
    }

    cbp.stag.type = h->tokenbuf;
    cbp.stag.typelen = h->tokenbuf_len;
    xml_reader_invoke_callback(h, &cbp);

    (void)xml_parse_whitespace(h); // optional whitespace
    if (xml_read_string(h, ">", XMLERR(ERROR, XML, P_ETag)) != PR_OK) {
        // No valid name - try to recover by skipping until closing bracket
        return xml_read_until_gt(h);
    }

    // Do not decrement nest level if already at the root level. This document
    // is already malformed, so an error message should already be raised.
    if (h->nestlvl) {
        h->nestlvl--;
    }
    return PR_OK;
}

/**
    Expected tokens/handlers for parsing content production.
    Can be used either as non-root context, or as a root context for external
    parsed entities.

    @verbatim
    content ::= CharData? ((element | Reference | CDSect | PI | Comment) CharData?)*
    element ::= EmptyElemTag | STag content ETag
    @endverbatim

*/
static const xml_reader_context_t parser_content = {
    .lookahead = {
        LOOKAHEAD("<![CDATA[", xml_parse_CDSect),
        LOOKAHEAD("<?", xml_parse_PI),
        LOOKAHEAD("<!--", xml_parse_Comment),
        LOOKAHEAD("</", xml_parse_ETag),
        LOOKAHEAD("<", xml_parse_STag_EmptyElemTag),
        LOOKAHEAD("", xml_parse_CharData), // catch-all
    },
    .flags = RECOGNIZE_REF,
    .nonroot = &parser_content,
};

/**
    Root-level recovery function.

    @param h Reader handle
    @return Always PR_OK (we've done our best, try to proceed further)
*/
static prodres_t
recover_document_entity_root(xml_reader_t *h)
{
    // Recover by reading up until next left angle bracket. Report
    // the error at failing location (not the last valid token)
    xml_reader_message_current(h, XMLERR(ERROR, XML, P_document),
            "Invalid content at root level");
    return xml_read_until_lt(h);
}

/**
    Root context for parsing document entity. We get here after XMLDecl, if any,
    is parsed.

    @verbatim
    document  ::= ( prolog element Misc* ) - ( Char* RestrictedChar Char* )
    prolog    ::= XMLDecl Misc* (doctypedecl Misc*)?
    Misc      ::= Comment | PI | S
    @endverbatim

    In XML spec 1.0, XMLDecl is optional.

    Expanding the productions for the document (above), we get (for 1.0 or 1.1):

    @verbatim
    document  ::= XMLDecl? (Comment|PI|S)* doctypedecl? (Comment|PI|S)* element
                  (Comment|PI|S)*
    @endverbatim
*/
static const xml_reader_context_t parser_document_entity = {
    .lookahead = {
        LOOKAHEAD("<!DOCTYPE", xml_parse_doctypedecl),
        LOOKAHEAD("<?", xml_parse_PI),
        LOOKAHEAD("<!--", xml_parse_Comment),
        LOOKAHEAD("</", xml_parse_ETag),
        LOOKAHEAD("<", xml_parse_STag_EmptyElemTag),
        LOOKAHEAD("", xml_parse_whitespace),
    },
    .nomatch = recover_document_entity_root,
    .nonroot = &parser_content,
};

/**
    Look ahead and parse according to the list of expected tokens.

    Note that content is a recursive production: it may contain element, which in turn
    may contain content. We are processing this in a flat way (substituting loop for
    recursion); instead, we just track the nesting level (to keep track if we're at
    the root level or not). The proper nesting of STag/ETag cannot be checked with
    this approach; it needs to be verified by a higher level, SAX or DOM. Higher level
    is also responsible for checking that both STag/ETag belong to the same input by
    keeping track when entity parsing started and ended.

    @param h Reader handle
    @param rootctx Root context
    @return Nothing
*/
static prodres_t
xml_parse_by_ctx(xml_reader_t *h, const xml_reader_context_t *rootctx)
{
    utf8_t labuf[MAX_PATTERN]; /// @todo Have lookahead read into tokenbuf? Do we need to use xml_lookahead() elsewhere?
    const xml_reader_context_t *ctx;
    const xml_reader_pattern_t *pat, *end;
    size_t len;
    bool eof;
    prodres_t rv;

    rv = PR_OK;
    while (rv == PR_OK && (len = xml_lookahead(h, labuf, sizeof(labuf), &eof), !eof)) {
        ctx = h->nestlvl ? rootctx->nonroot : rootctx;
        rv = PR_NOMATCH;
        for (pat = ctx->lookahead, end = pat + MAX_LA_PAIRS; pat < end; pat++) {
            if (pat->patlen <= len && !memcmp(labuf, pat->pattern, pat->patlen)) {
                rv = pat->func(h);
                break;
            }
        }
        if (rv == PR_NOMATCH && ctx->nomatch) {
            rv = ctx->nomatch(h);
        }
    }
    return eof ? PR_STOP : rv;
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
    xml_reader_input_t *inp;
    xml_reader_initial_xcode_t xc;
    utf8_t adbuf[4];       // 4 bytes for encoding detection, per XML spec suggestion
    size_t bom_len, adsz;
    const char *encname;
    bool rv;

    // No more setup changes
    h->flags |= READER_STARTED;

    // Try to get the encoding from stream and check for BOM
    memset(adbuf, 0, sizeof(adbuf));
    adsz = strbuf_lookahead(h->buf, adbuf, sizeof(adbuf));
    if ((encname = encoding_detect(adbuf, adsz, &bom_len)) != NULL) {
        if (!xml_reader_set_encoding(h, encname)) {
            xml_reader_message_current(h, XMLERR_NOTE, "(autodetected from %s)",
                    bom_len ? "Byte-order Mark" : "content");
            h->flags |= READER_FATAL;
            return;
        }
        xfree(h->enc_detected);
        h->enc_detected = xstrdup(encname);
    }

    // If byte order mark (BOM) was detected, consume it
    if (bom_len) {
        strbuf_radvance(h->buf, bom_len);
    }

    // If no encoding passed from the transport layer, and autodetect didn't help,
    // try UTF-8. UTF-8 is built-in, so it should always work.
    if (!h->enc) {
        rv = xml_reader_set_encoding(h, "UTF-8");
        OOPS_ASSERT(rv);
    }

    // Temporary reader state
    xc.h = h;
    xc.la_start = xc.initial;
    xc.la_size = sizeof(xc.initial);
    xc.la_avail = 0;
    xc.la_offs = 0;

    // Main document input: using the input strbuf. It shares the location string;
    // also, set the position to EOF - once the created input is exhausted, we're at
    // the end of the document.
    h->curloc.line = XMLERR_EOF;
    h->curloc.pos = XMLERR_EOF;
    inp = xml_reader_input_new(h, h->curloc.src);
    strbuf_realloc(inp->buf, INITIAL_TOKENBUF_SIZE * sizeof(ucs4_t));
    strbuf_setops(inp->buf, &xml_reader_initial_ops, &xc);

    // Parse the declaration; expect only ASCII
    h->flags |= READER_ASCII;
    if (xml_parse_XMLDecl_TextDecl(h) != PR_NOMATCH) {
        // Consumed declaration from the raw buffer; advance before setting
        // permanent transcoding operations
        strbuf_radvance(h->buf, xc.la_offs);
    }
    h->flags &= ~READER_ASCII;

    // If there was no XML declaration, assume 1.0 (where XMLDecl is optional)
    /// @todo For external parsed entities, need to inherit version from including document
    if (h->version == XML_INFO_VERSION_NO_VALUE) {
        h->version = XML_INFO_VERSION_1_0;
    }
    // Default normalization behavior depends on version: off in 1.0, on in 1.1
    if (h->normalization == XML_READER_NORM_DEFAULT) {
        h->normalization = (h->version == XML_INFO_VERSION_1_0) ?
                XML_READER_NORM_OFF : XML_READER_NORM_ON;
    }

    // Done with the temporary buffer: free the memory buffer if it was reallocated;
    // advance the raw buffer by the amount used by XML declaration.
    if (xc.la_start != xc.initial) {
        xfree(xc.la_start);
    }

    if (h->enc_xmldecl) {
        // Encoding should be in clean state - if not, need to fix encoding to not consume
        // excess data. If this fails, the error is already reported - try to recover by
        // keeping the old encoding.
        if (!xml_reader_set_encoding(h, h->enc_xmldecl)) {
            xml_reader_message_lastread(h, XMLERR_NOTE, "(encoding from XML declaration)");
        }
    }

    // Set up permanent transcoder (we do it always, but the caller probably won't
    // proceed with further decoding if READER_FATAL is reported). Clear any cached
    // content as new transcoding ops will re-parse the input at the offset right past
    // the XML declaration
    strbuf_clear(inp->buf);
    strbuf_setops(inp->buf, &xml_reader_transcode_ops, h);

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
        xml_reader_message_lastread(h, XMLERR(ERROR, XML, ENCODING_ERROR),
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
    if (!h->enc_xmldecl && !h->enc_transport
            && strcmp(encoding_name(h->enc), "UTF-16")
            && strcmp(encoding_name(h->enc), "UTF-8")) {
        // Non-fatal: recover by using whatever encoding we detected
        xml_reader_message_lastread(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                "No external encoding information, no encoding in %s, content in %s encoding",
                h->declinfo->name, encoding_name(h->enc));
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
    h->declinfo = &declinfo_xmldecl;

    /// @todo Return PR_FAIL from xml_reader_start for fatal errors
    xml_reader_start(h);

    // Skip checking for certain errors if reading was aborted prematurely
    if ((h->flags & READER_FATAL) == 0) {
        if (xml_parse_by_ctx(h, &parser_document_entity) != PR_FAIL) {
            if (!encoding_clean(h->enc)) {
                xml_reader_message_current(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                        "Partial characters at end of input");
            }
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
        return; /// @todo Signal error somehow? or XMLERR(ERROR, ...) is enough?
    }
    /// @todo Process the rest of the content
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
        return; /// @todo Signal error somehow? or XMLERR(ERROR, ...) is enough?
    }
    /// @todo Process the rest of the content
}
