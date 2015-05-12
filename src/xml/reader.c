/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    XML reader handle operations.
    @todo After the reader is implemented, establish naming policy.
*/
#include <string.h>

#include "util/defs.h"
#include "util/xutil.h"
#include "util/strbuf.h"
#include "util/strhash.h"

#include "unicode/unicode.h"
#include "unicode/encoding.h"
#include "unicode/nfc.h"

#include "xml/loader.h"
#include "xml/reader.h"

/**
    Initial lookahead buffer size for parsing XML declaration. Each time it is
    insufficient, it is doubled.
*/
#define INITIAL_DECL_LOOKAHEAD_SIZE 64

/// Maximum number of characters to look ahead
#define MAX_LOOKAHEAD_SIZE          16

/// Reader flags
enum {
    R_RECOGNIZE_REF     = 0x0001,       ///< Reading next token will expand Reference production
    R_RECOGNIZE_PEREF   = 0x0002,       ///< Reading next token will expand PEReference production
    R_ASCII_ONLY        = 0x0004,       ///< Only ASCII characters allowed while reading declaration
    R_LOCTRACK          = 0x0008,       ///< Track the current position for error reporting
    R_SAVE_UCS4         = 0x0010,       ///< Also save UCS-4 codepoints
    R_NO_INC_NORM       = 0x0020,       ///< No checking of include normalization
    R_HAS_ROOT          = 0x0040,       ///< Root element seen
    R_HAS_DTD           = 0x0080,       ///< Document declaration seen
    R_DOCUMENT_LOADED   = 0x0100,       ///< Document entity has been added
    R_AMBIGUOUS_PERCENT = 0x0200,       ///< '%' may either start PE reference or have literal meaning
};

/// Notation information
/// @todo Export this structure in reader.h? Unlike entities, notations are part of the infoset.
/// Or store a pointer from a callback and pass back that pointer whenever that notation is used?
/// (similar to what I planned for nested stack of elements)
typedef struct xml_reader_notation_s {
    const utf8_t *name;                     ///< Notation name
    size_t namelen;                         ///< Notation name length in bytes
    xml_loader_info_t loader_info;          ///< Loader information for this notation
} xml_reader_notation_t;

/// Information on a pre-defined entity.
typedef struct {
    const utf8_t *name;     ///< Entity name
    size_t namelen;         ///< Length of the entity name
    const char *rplc[4];    ///< Replacement text; 1st is default.
} xml_predefined_entity_t;

/// Entity information
typedef struct xml_reader_entity_s {
    const utf8_t *name;                     ///< Entity name
    size_t namelen;                         ///< Entity name length in bytes
    enum xml_reader_reference_e type;       ///< Entity type
    xml_loader_info_t loader_info;          ///< Loader information for this entity
    const char *location;                   ///< How input from this entity will be reported
    xml_reader_notation_t *notation;        ///< Associated notation
    bool being_parsed;                      ///< Recursion detection: this entity is being parsed
    bool parameter;                         ///< Parameter entity
    const ucs4_t *rplc;                     ///< Replacement text
    size_t rplclen;                         ///< Length of the replacement text in bytes
    const ucs4_t *refrplc;                  ///< Reference replacement text
    size_t refrplclen;                      ///< Length of the reference replacement text in bytes
    xmlerr_loc_t declared;                  ///< Location of the declaration
    xmlerr_loc_t included;                  ///< Where this entity has been included from
    const xml_predefined_entity_t *predef;  ///< The definition came from a predefined entity
} xml_reader_entity_t;

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

    /// Whether these options describe a relevant construct
    const char *relevant;

    /// Stop condition function
    xml_condread_func_t condread;

    /// How text blocks are handled
    void (*textblock)(void *arg);
    
    /// How different types of entities are handled
    xml_refhandler_t hnd[XML_READER_REF__MAX];
} xml_reference_ops_t;

/// How error messages are generated for references
typedef struct {
    const char *desc;           ///< How this reference is called in error messages
    uint32_t ecode;             ///< Error code associated with this type of references
} xml_reference_info_t;

/**
    External entity information (including main document entity).
*/
typedef struct xml_reader_external_s {
    STAILQ_ENTRY(xml_reader_external_s) link;   ///< List pointer
    enum xml_info_version_e version;            ///< Entity's declared version
    const char *location;           ///< Location string for messages
    const char *enc_transport;      ///< Encoding reported by transport protocol
    const char *enc_detected;       ///< Encoding detected by BOM or start characters
    const char *enc_declared;       ///< Encoding declared in <?xml ... ?>

    bool aborted;                   ///< If true, entity was not fully parsed
    xml_reader_t *h;                ///< Reader handle (for error reporting)
    encoding_handle_t *enc;         ///< Encoding used to transcode input
    strbuf_t *buf;                  ///< Raw input buffer (in document's encoding)
    nfc_t *norm_unicode;            ///< Normalization check handle for Unicode normalization

    // Saved parser context before this external input was added
    const struct xml_reader_context_s *saved_ctx;
} xml_reader_external_t;

/**
    XML declaration comes in two flavors, XMLDecl and TextDecl, with different
    set of allowed/mandatory/optional attributes. This structure describes an
    attribute in the expected list.
*/
typedef struct xml_reader_xmldecl_attrdesc_s {
    const char *name;       ///< Name of the attribute
    bool mandatory;         ///< True if the attribute is mandatory

    /// Value validation function
    void (*check)(xml_reader_external_t *ex);
} xml_reader_xmldecl_attrdesc_t;

/// Declaration info for XMLDecl/TextDecl:
typedef struct xml_reader_xmldecl_declinfo_s {
    const char *name;           ///< Declaration name in XML grammar
    const xml_reader_xmldecl_attrdesc_t *attrlist; ///< Allowed/required attributes
} xml_reader_xmldecl_declinfo_t;

/**
    Input method: either strbuf for an external entity, replacement text for an internal
    entity or internal memory buffer (for character references).
*/
typedef struct xml_reader_input_s {
    SLIST_ENTRY(xml_reader_input_s) link;  ///< Stack of diversions
    strbuf_t *buf;                  ///< String buffer to use
    xmlerr_loc_t curloc;            ///< Current location in this input

    /// Notification when this input is consumed
    void (*complete)(struct xml_reader_s *, void *);
    void *complete_arg;             ///< Argument to completion notification

    // Other fields
    uint32_t locked;                ///< Number of productions 'locking' this input
    bool inc_in_literal;            ///< 'included in literal' - special handling of quotes
    bool ignore_references;         ///< Ignore reference expansion in this input
    bool charref;                   ///< Input originated from a character reference
    xml_reader_entity_t *entity;    ///< Associated entity if any
    xml_reader_external_t *external;///< External entity information
} xml_reader_input_t;

/// Input head
typedef SLIST_HEAD(,xml_reader_input_s) xml_reader_input_head_t;

/// Return status for production parser
typedef enum {
    PR_OK,                      ///< Parsed successfully or performed recovery
    PR_STOP,                    ///< Parsed successfully, exit current context
    PR_FAIL,                    ///< Parsing failed (fatal)
    PR_NOMATCH,                 ///< Production was not matched
} prodres_t;

/// Production parser function
typedef prodres_t (*prodparser_t)(xml_reader_t *);

/// Maximum number of characters we need to look ahead: '<!NOTATION'
#define MAX_PATTERN     10

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
#define MAX_LA_PAIRS    8

/**
    Parser settings: entity recognition settings at root level, set of lookahead
    patterns for root level, pointer to a settings for non-root level.
*/
typedef struct xml_reader_context_s {
    /// Lookahead patterns
    const xml_reader_pattern_t lookahead[MAX_LA_PAIRS];

    /// Expected XMLDecl/TextDecl declaration
    const struct xml_reader_xmldecl_declinfo_s *declinfo;

    /// What is allowed in EntityValue
    const struct xml_reference_ops_s *entity_value_parser;

    xmlerr_info_t errcode;          ///< Error code when breaking the lock
    const char *production;         ///< Production this must match
    bool document_entity;           ///< Context for the document entity
    enum xml_reader_reference_e reftype;
} xml_reader_context_t;

/// Hidden argument passed through the loader
typedef struct {
    xml_reader_entity_t *entityref;     ///< Entity information, if loading a defined entity
    const xml_reader_context_t *ctx;    ///< Context associated with loaded entity, if any
    bool inc_in_literal;                ///< Whether this entity is being loaded from a literal
} xml_reader_hidden_loader_arg_t;

/// XML reader structure
struct xml_reader_s {
    xml_reader_cb_t cb_func;        ///< Callback function
    void *cb_arg;                   ///< Argument to callback function

    xml_loader_t loader;            ///< External entity loader
    void *loader_arg;               ///< Argument to loader function

    /// Argument to loader function
    xml_reader_hidden_loader_arg_t *hidden_loader_arg;

    const xml_reader_context_t *ctx;///< Current parser context

    ucs4_t *ucs4buf;                ///< Buffer for saved UCS-4 text
    size_t ucs4len;                 ///< Count of UCS-4 characters
    size_t ucs4sz;                  ///< Size of UCS-4 buffer, in characters

    uint32_t flags;                 ///< Reader flags
    const char *relevant;           ///< If not NULL, reading a relevant contruct
    size_t tabsize;                 ///< Tabulation character equal to these many spaces

    enum xml_info_standalone_e standalone;          ///< Document's standalone status
    enum xml_reader_normalization_e normalization;  ///< Desired normalization behavior

    xml_reader_external_t *current_external;        ///< External entity being parsed

    nfc_t *norm_include;            ///< Normalization check handle for include normalization

    uint32_t nestlvl;               ///< Element nesting level
    uint32_t brokenlocks;           ///< Number of locked inputs forcibly unlocked

    utf8_t *tokenbuf;               ///< Token buffer
    utf8_t *tokenbuf_end;           ///< End of the token buffer
    size_t tokenlen;                ///< Length of the token in the buffer

    xmlerr_loc_t lastreadloc;       ///< Reader's position at the beginning of last token
    ucs4_t rejected;                ///< Next character (rejected by xml_read_until_*)
    ucs4_t charrefval;              ///< When parsing character reference: stored value

    xml_loader_info_t dtd_loader_info;              ///< DTD public/system ID

    strhash_t *entities_param;      ///< Parameter entities
    strhash_t *entities_gen;        ///< General entities
    strhash_t *notations;           ///< Notations

    xml_reader_input_head_t active_input;       ///< Currently active inputs
    xml_reader_input_head_t free_input;         ///< Free list of input structures
    xml_reader_input_t *completed;              ///< Deferred completion notification

    STAILQ_HEAD(,xml_reader_external_s) external;       ///< All external entities
};

/// xml_read_until_* return codes
typedef enum {
    XRU_CONTINUE,           ///< Internal value: do not return yet
    XRU_EOF,                ///< Reach end of input
    XRU_STOP,               ///< Callback indicated end of a token
    XRU_REFERENCE,          ///< Recognized entity/character reference
    XRU_INPUT_BOUNDARY,     ///< Encountered input (entity) boundary
    XRU_INPUT_LOCKED,       ///< Some production wanted to end in this input
} xru_t;

// Known contexts
static const xml_reader_context_t parser_content;
static const xml_reader_context_t parser_document_entity;
static const xml_reader_context_t parser_internal_subset;
static const xml_reader_context_t parser_external_subset;

/// Convenience macro: report an error at the start of the last token
#define xml_reader_message_lastread(h, ...) \
        xml_reader_message(h, &h->lastreadloc, __VA_ARGS__)

/// Convenience macro: report an error at current location (i.e. after a lookahead)
#define xml_reader_message_current(h, ...) \
        xml_reader_message(h, NULL, __VA_ARGS__)

/**
    Determine if a character is a restricted character. Restricted characters are
    completely illegal in XML1.0 (directly inserted and inserted as character reference).
    They are allowed in character references in XML1.1 documents.

    @param cp Codepoint
    @param xmlv XML version
    @return true if @a cp is a restricted character
*/
static inline bool
xml_is_restricted(ucs4_t cp, enum xml_info_version_e xmlv)
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
    exclusion_limit = xmlv == XML_INFO_VERSION_1_0 ? 0x20 : sizeofarray(restricted_chars);
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
    /// @todo Replace the check in the BMP with a bitmap? Or have a full map, for all UCS-4
    /// code points, with properties like NameStart, Name, block, etc (will need them for XML
    /// regexp extensions later).
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

    @param ex External parsed entity
    @param encname Encoding to be set, NULL to clear current encoding processor
    @return true if successful, false otherwise
*/
static bool
xml_reader_set_encoding(xml_reader_external_t *ex, const char *encname)
{
    encoding_handle_t *hndnew;

    if (encname != NULL) {
        if ((hndnew = encoding_open(encname)) == NULL) {
            // XMLDecl location passed via h->lastreadloc
            xml_reader_message_lastread(ex->h, XMLERR(ERROR, XML, ENCODING_ERROR),
                    "Unsupported encoding '%s'", encname);
            return false;
        }
        if (!ex->enc) {
            ex->enc = hndnew;
            return true;
        }
        if (!encoding_switch(&ex->enc, hndnew)) {
            // Replacing with an incompatible encoding is not possible;
            // the data that has been read previously cannot be trusted.
            xml_reader_message_lastread(ex->h, XMLERR(ERROR, XML, ENCODING_ERROR),
                    "Incompatible encodings: '%s' and '%s'",
                    encoding_name(ex->enc), encname);
            return false;
        }
        return true;
    }
    else if (ex->enc) {
        encoding_close(ex->enc);
        ex->enc = NULL;
    }
    return true;
}

/**
    Reallocate token buffer.

    @param h Reader handle
    @return Nothing
*/
static void
xml_tokenbuf_realloc(xml_reader_t *h)
{
    size_t newsz = 2 * (h->tokenbuf_end - h->tokenbuf);

    h->tokenbuf = xrealloc(h->tokenbuf, newsz);
    h->tokenbuf_end = h->tokenbuf + newsz;
}

/**
    Store a UCS-4 codepoint, reallocating the storage buffer if necessary. Used
    for entities where we'd need to re-parse the replacement value (or entity
    reference) later.

    @param h Reader handle
    @param cp Codepoint
    @return Nothing
*/
static void
xml_ucs4_store(xml_reader_t *h, ucs4_t cp)
{
    if (h->ucs4len == h->ucs4sz) {
        h->ucs4sz = h->ucs4sz ? 2 * h->ucs4sz : 256;
        h->ucs4buf = xrealloc(h->ucs4buf, h->ucs4sz * sizeof(ucs4_t));
    }
    h->ucs4buf[h->ucs4len++] = cp;
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
    strbuf_t *buf;

    if ((inp = SLIST_FIRST(&h->free_input)) != NULL) {
        SLIST_REMOVE_HEAD(&h->free_input, link);
        buf = inp->buf; // Buffer retained when input is on free list
        strbuf_clear(buf);
    }
    else {
        inp = xmalloc(sizeof(xml_reader_input_t));
        buf = strbuf_new(0); // New buffer for static input
    }

    memset(inp, 0, sizeof(xml_reader_input_t));
    inp->buf = buf;
    if (location) {
        inp->curloc.src = location;
        inp->curloc.line = 1;
        inp->curloc.pos = 1;
        h->lastreadloc = inp->curloc;
    }
    else {
        inp->curloc = h->lastreadloc;
    }

    SLIST_INSERT_HEAD(&h->active_input, inp, link);
    return inp;
}

/**
    Destroy input structure.

    @param inp Input to be destroyed
    @return Nothing
*/
static void
xml_reader_input_destroy(xml_reader_input_t *inp)
{
    strbuf_delete(inp->buf);
    xfree(inp);
}

/**
    Process deferred completions.

    @param h Reader handle
    @return Nothing
*/
static void
xml_reader_input_complete_notify(xml_reader_t *h)
{
    xml_reader_input_t *inp;

    if ((inp = h->completed) != NULL) {
        h->lastreadloc = inp->curloc;
        inp->complete(h, inp->complete_arg);
        SLIST_INSERT_HEAD(&h->free_input, inp, link);
        h->completed = NULL;
    }
}

/**
    Housekeeping after input parsing is completed.

    @param h Reader handle
    @param inp Input structure; must be current active input.
    @return Nothing
*/
static void
xml_reader_input_complete(xml_reader_t *h, xml_reader_input_t *inp)
{
    xml_reader_input_t *next;

    OOPS_ASSERT(inp == SLIST_FIRST(&h->active_input));

    SLIST_REMOVE_HEAD(&h->active_input, link);
    if (inp->external) {
        h->current_external = NULL;
        SLIST_FOREACH(next, &h->active_input, link) {
            if (next->external) {
                h->current_external = next->external;
                break;
            }
        }
    }
    // Postpone notifications so that we issue them after processing the
    // last token from this input.
    if (inp->complete) {
        OOPS_ASSERT(!h->completed); // One pending notification at a time
        h->completed = inp;
    }
    else {
        SLIST_INSERT_HEAD(&h->free_input, inp, link);
    }
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
        if (inp->locked) {
            // Can't remove this input yet
            // @todo Create an error message
            return XRU_INPUT_LOCKED;
        }
        xml_reader_input_complete(h, inp);
        rv = XRU_INPUT_BOUNDARY; // No longer reading from the same input
    }
    return XRU_EOF; // All inputs consumed, EOF
}

/**
    Lock current input.

    @param h Reader handle
    @return Nothing
*/
static void
xml_reader_input_lock(xml_reader_t *h)
{
    xml_reader_input_t *inp;

    inp = SLIST_FIRST(&h->active_input);
    OOPS_ASSERT(inp);
    inp->locked++;
}

/**
    Unlock a previously locked input.

    @param h Reader handle
    @return true if unlocked successfully, false if current input is not locked
*/
static bool __warn_unused_result
xml_reader_input_unlock(xml_reader_t *h)
{
    xml_reader_input_t *inp;

    if (h->brokenlocks) {
        h->brokenlocks--;
        return true; // Already complained
    }

    /*
        Productions lock/unlock inputs in a stack-like fashion. Normally, we
        should be in the same input when unlocking as we were when locking;
        otherwise, signal an error and unlock the closest input (since execution
        will not go back to the same production).
    */
    if ((inp = SLIST_FIRST(&h->active_input)) != NULL && inp->locked) {
        // Normal case
        inp->locked--;
        return true;
    }

    // Error case: find the first one to unlock.
    SLIST_FOREACH(inp, &h->active_input, link) {
        if (inp->locked) {
            inp->locked--;
            break;
        }
    }
    return false;
}

/**
    Unlock input where we don't expect a failure regardless how malformed
    the input is (i.e., when the production being parsed does not parse
    any references).

    @param h Reader handle
    @return Nothing
*/
static void
xml_reader_input_unlock_assert(xml_reader_t *h)
{
    bool rv;

    rv = xml_reader_input_unlock(h);
    OOPS_ASSERT(rv);
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
    Check if reached the end of all inputs.

    @param h Reader handle
    @return True if all input is consumed
*/
static bool
xml_eof(xml_reader_t *h)
{
    xml_reader_input_complete_notify(h);
    return SLIST_EMPTY(&h->active_input);
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
xml_lookahead(xml_reader_t *h, utf8_t *buf, size_t bufsz)
{
    xml_reader_input_t *inp;
    ucs4_t tmp[MAX_LOOKAHEAD_SIZE];
    ucs4_t *ptr = tmp;
    size_t i, nread;
    const void *begin, *end;

    OOPS_ASSERT(bufsz <= MAX_LOOKAHEAD_SIZE);

    while (true) {
        if ((inp = SLIST_FIRST(&h->active_input)) == NULL) {
            return 0;
        }
        nread = strbuf_lookahead(inp->buf, ptr, bufsz * sizeof(ucs4_t));
        if (nread) {
            break;
        }
        if (inp->locked) {
            // We wanted more input to end an open production, but there's none.
            // Break the lock (noting the number of the locks thus broken, to
            // avoid complaining about them twice), issue an error message and retry.

            /// @todo Consider lock tokens with callback functions with more
            /// specific error info (i.e., which exact production locked the
            /// input and most importantly where)
            if (inp->external) {
                xml_reader_message_current(h, h->ctx->errcode,
                        "Fails to parse: does not match %s production",
                        h->ctx->production);
            }
            else {
                // Shouldn't be locking character references...
                OOPS_ASSERT(inp->entity);
                if (inp->entity->parameter) {
                    xml_reader_message_current(h,
                            XMLERR(ERROR, XML, VC_PROPER_DECL_PE_NESTING),
                            "Fails to parse: parameter entities not properly nested");
                }
                else {
                    xml_reader_message_current(h,
                            XMLERR(ERROR, XML, P_content),
                            "Fails to parse: does not match content production");
                }
            }
            h->brokenlocks += inp->locked;
            inp->locked = 0;
        }
        (void)xml_reader_input_rptr(h, &begin, &end); // Just drop empty inputs
    }
    OOPS_ASSERT((nread & 3) == 0); // input buf must have an integral number of characters
    nread /= 4;
    for (i = 0; i < nread; i++) {
        if (*ptr >= 0x7F) {
            break; // Non-ASCII
        }
        *buf++ = *ptr++;
    }
    return ptr - tmp;
}

/**
    Allocate a new notation.

    @param hash Hash with notations
    @param name Notation name
    @param namelen Notation name length
    @return Newly allocated initialized notation
*/
static xml_reader_notation_t *
xml_notation_new(strhash_t *hash, const utf8_t *name, size_t namelen)
{
    xml_reader_notation_t *n;

    n = xmalloc(sizeof(xml_reader_notation_t));
    memset(n, 0, sizeof(xml_reader_notation_t));
    xml_loader_info_init(&n->loader_info, NULL, NULL);
    n->name = strhash_set(hash, name, namelen, n);
    n->namelen = namelen;
    return n;
}

/**
    Free an entity information structure.

    @param arg Pointer to entity information structure
    @return Nothing
*/
static void
xml_notation_destroy(void *arg)
{
    xml_reader_notation_t *n = arg;

    xml_loader_info_destroy(&n->loader_info);
    xfree(n);
}

/**
    Allocate a new entity.

    @param ehash Entity hash
    @param name Entity name
    @param namelen Entity name length
    @return Newly allocated initialized entity
*/
static xml_reader_entity_t *
xml_entity_new(strhash_t *ehash, const utf8_t *name, size_t namelen)
{
    xml_reader_entity_t *e;
    const char *s;

    e = xmalloc(sizeof(xml_reader_entity_t));
    memset(e, 0, sizeof(xml_reader_entity_t));
    xml_loader_info_init(&e->loader_info, NULL, NULL);
    e->name = strhash_set(ehash, name, namelen, e);
    e->namelen = namelen;
    s = utf8_strtolocal(e->name);
    e->location = xasprintf("entity(%s)", s);
    utf8_strfreelocal(s);
    return e;
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

    xml_loader_info_destroy(&e->loader_info);
    xfree(e->refrplc);
    xfree(e->rplc);
    xfree(e->location);
    xfree(e);
}

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
    { .name = U"lt",    .namelen = 2, .rplc = { "&#60;",  "&#x3C;",   "&#x3c;",   NULL,       }, },
    { .name = U"gt",    .namelen = 2, .rplc = { ">",      "&#62;",    "&#x3E;",   "&#x3e;",   }, },
    { .name = U"amp",   .namelen = 3, .rplc = { "&#38;",  "&#x26;",   NULL,       NULL,       }, },
    { .name = U"apos",  .namelen = 4, .rplc = { "'",      "&#39;",    "&#x27;",   NULL,       }, },
    { .name = U"quot",  .namelen = 4, .rplc = { "\"",     "&#34;",    "&#x22;",   NULL,       }, },
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
        e = xml_entity_new(ehash, predef->name, predef->namelen);
        e->type = XML_READER_REF_INTERNAL;
        // Only ASCII replacements here, 1 byte per character
        nchars = strlen(s);
        e->rplclen = nchars * sizeof(ucs4_t);
        rplc = xmalloc(e->rplclen);
        for (j = 0; j < nchars; j++) {
            rplc[j] = ucs4_fromlocal(s[j]);
        }
        e->rplc = rplc;
        nchars = predef->namelen + 2;
        e->refrplclen = nchars * sizeof(ucs4_t);
        rplc = xmalloc(e->refrplclen);
        rplc[0] = ucs4_fromlocal('&');
        for (j = 0; j < predef->namelen; j++) {
            rplc[j + 1] = predef->name[j];
        }
        rplc[nchars - 1] = ucs4_fromlocal(';');
        e->refrplc = rplc;
        e->predef = predef;
    }
}

/**
    Destroy external entity information structure.

    @param ex External entity
    @return Nothing
*/
static void
xml_reader_external_destroy(xml_reader_external_t *ex)
{
    if (ex->norm_unicode) {
        nfc_destroy(ex->norm_unicode);
    }
    (void)xml_reader_set_encoding(ex, NULL);
    strbuf_delete(ex->buf);
    xfree(ex->location);
    xfree(ex->enc_transport);
    xfree(ex->enc_detected);
    xfree(ex->enc_declared);
    xfree(ex);
}


/**
    Dummy callback function.

    @param arg Arbitrary argument
    @param cbparam Callback parameter structure
    @return Nothing
*/
static void
dummy_callback(void *arg, xml_reader_cbparam_t *cbparam)
{
    // No-op
}

/// Default XML reader options
static const xml_reader_options_t opts_default = {
    .normalization = XML_READER_NORM_DEFAULT,
    .loctrack = true,
    .tabsize = 8,
    .entity_hash_order = 6,
    .notation_hash_order = 4,
    .initial_tokenbuf = 1024,
};

/**
    Initialize XML reader's settings to default values.

    @param opts Options structure to be initialized
    @return Nothing
*/
void
xml_reader_opts_default(xml_reader_options_t *opts)
{
    memcpy(opts, &opts_default, sizeof(xml_reader_options_t));
}

/**
    Create an XML reading handle.

    @param opts Reader options
    @return Handle
*/
xml_reader_t *
xml_reader_new(const xml_reader_options_t *opts)
{
    xml_reader_t *h;

    if (!opts) {
        opts = &opts_default;
    }
    h = xmalloc(sizeof(xml_reader_t));
    memset(h, 0, sizeof(xml_reader_t));

    h->cb_func = dummy_callback;
    h->cb_arg = NULL;
    h->loader = xml_loader_noload;
    h->loader_arg = NULL;

    h->tabsize = opts->tabsize;
    if (opts->loctrack) {
        h->flags |= R_LOCTRACK;
    }

    // what would be the context of the entities loaded from it
    h->standalone = XML_INFO_STANDALONE_NO_VALUE;
    h->normalization = opts->normalization;
    h->norm_include = NULL;

    h->tokenbuf = xmalloc(opts->initial_tokenbuf);
    h->tokenbuf_end = h->tokenbuf + opts->initial_tokenbuf;
    h->tokenlen = 0;

    xml_loader_info_init(&h->dtd_loader_info, NULL, NULL);

    h->entities_param = strhash_create(opts->entity_hash_order, xml_entity_destroy);
    h->entities_gen = strhash_create(opts->entity_hash_order, xml_entity_destroy);
    h->notations = strhash_create(opts->notation_hash_order, xml_notation_destroy);

    SLIST_INIT(&h->active_input);
    SLIST_INIT(&h->free_input);
    h->completed = NULL;
    STAILQ_INIT(&h->external);

    xml_entity_populate(h->entities_gen);

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
    xml_reader_input_t *inp;
    xml_reader_external_t *ex;

    while ((inp = SLIST_FIRST(&h->active_input)) != NULL) {
        xml_reader_input_complete(h, inp);
    }
    xml_reader_input_complete_notify(h);
    while ((inp = SLIST_FIRST(&h->free_input)) != NULL) {
        SLIST_REMOVE_HEAD(&h->free_input, link);
        xml_reader_input_destroy(inp);
    }
    while ((ex = STAILQ_FIRST(&h->external)) != NULL) {
        STAILQ_REMOVE_HEAD(&h->external, link);
        xml_reader_external_destroy(ex);
    }

    if (h->norm_include) {
        nfc_destroy(h->norm_include);
    }

    xml_loader_info_destroy(&h->dtd_loader_info);

    strhash_destroy(h->entities_param);
    strhash_destroy(h->entities_gen);
    strhash_destroy(h->notations);

    xfree(h->tokenbuf);
    xfree(h->ucs4buf);
    xfree(h);
}

/**
    Change the callback function/argument for XML events.

    @param h Reader handle
    @param func Function to call for XML events
    @param arg Argument to @a func
    @return Nothing
*/
void
xml_reader_set_callback(xml_reader_t *h, xml_reader_cb_t func, void *arg)
{
    h->cb_func = func;
    h->cb_arg  = arg;
}

/**
    Change the entity loader for external entities.

    @param h Reader handle
    @param func Loader function
    @param arg Argument to @a func
    @return Nothing
*/
void
xml_reader_set_loader(xml_reader_t *h, xml_loader_t func, void *arg)
{
    h->loader = func;
    h->loader_arg = arg;
}

/**
    Call a user-registered function for the specified event.

    @param h Reader handle
    @param cbparam Parameter for the callback
    @return None
*/
static inline void
xml_reader_invoke_callback(xml_reader_t *h, xml_reader_cbparam_t *cbparam)
{
    h->cb_func(h->cb_arg, cbparam);
}

/**
    Call user-registered entity loader.

    @param h Reader handle
    @param loader_info Loader information for entity being loaded
    @param e Entity being added, or NULL if not loading an entity
    @param ctx Parser context associated with this external entity
    @param inc_in_literal Entity is being included from a literal if true
    @return true if an entity was loaded, false otherwise
*/
static bool
xml_reader_invoke_loader(xml_reader_t *h, const xml_loader_info_t *loader_info,
        xml_reader_entity_t *e, const xml_reader_context_t *ctx, bool inc_in_literal)
{
    xml_reader_hidden_loader_arg_t ha;
    xml_reader_cbparam_t cbp;

    ha.entityref = e;
    ha.ctx = ctx;
    ha.inc_in_literal = inc_in_literal;

    // Hidden arguments:
    // - if the loader decides to add an external input for this entity, we know
    // what entity it belongs to
    // - if an external input is added, we may need to save (and, on input's completion,
    // restore) the parser context
    // - if an input is loaded from a literal (where quotes have special meaning), mark
    // the input as such
    h->hidden_loader_arg = &ha;
    h->loader(h, h->loader_arg, loader_info);
    if (h->hidden_loader_arg) {
        // Loader didn't create an input
        h->hidden_loader_arg = NULL;
        // Notify the app
        cbp.cbtype = XML_READER_CB_ENTITY_NOT_LOADED;
        cbp.loc = h->lastreadloc;
        if (e) {
            cbp.token.str = e->name;
            cbp.token.len = e->namelen;
            cbp.entity.type = e->type;
        }
        else {
            OOPS_ASSERT(ctx); // For non-entity inputs, context must be provided.
            cbp.token.str = NULL;
            cbp.token.len = 0;
            cbp.entity.type = ctx->reftype;
        }
        cbp.entity.system_id = loader_info->system_id;
        cbp.entity.public_id = loader_info->public_id;
        xml_reader_invoke_callback(h, &cbp);
        return false;
    }
    return true;
}

/**
    Update reader's position when reading the specified character.

    @param inp Input handle
    @param cp Code point being read
    @param tabsize Number of spaces in a tabulation
    @return Nothing
*/
static void
xml_reader_update_position(xml_reader_input_t *inp, ucs4_t cp, size_t tabsize)
{
    if (cp == 0x0A) {
        // Newline and it wasn't rejected - increment line number *after this character*
        inp->curloc.line++;
        inp->curloc.pos = 1;
    }
    else if (cp == 0x09) {
        // Round down, move to next tabstop, account for 1-based position
        inp->curloc.pos = (inp->curloc.pos / tabsize) * tabsize + tabsize + 1;
    }
    else if (ucs4_get_ccc(cp) == 0) {
        // Do not count combining marks - supposedly they're displayed with the preceding
        // character.
        /// @todo Check UAX#19 - AFAIU, this is what "Stacked boundaries" treatment implies
        inp->curloc.pos++;
    }
}

/// State structure for input ops while parsing the declaration
typedef struct xml_reader_initial_xcode_s {
    xml_reader_external_t *ex;  ///< Reader handle
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
    xml_reader_external_t *ex = xc->ex;
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
            xc->la_avail = strbuf_lookahead(ex->buf, xc->la_start, xc->la_size);
            if (xc->la_offs == xc->la_avail) {
                return 0; // Despite our best efforts... got no new data
            }
        }
        // Transcode a single UCS-4 code point
        xc->la_offs += encoding_in(ex->enc, xc->la_start + xc->la_offs,
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
    xml_reader_external_t *ex = arg;
    ucs4_t *bptr, *cptr, *eptr;

    bptr = cptr = begin;
    eptr = bptr + sz / sizeof(ucs4_t);
    encoding_in_from_strbuf(ex->enc, ex->buf, &cptr, eptr);
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

    @param h Reader handle
    @param func Function to call to check for the condition
    @param arg Argument to @a func
    @param flags Reader flags (temporarily or'ed into reader flags just for this call)
    @return Reason why the token parser returned
*/
static inline xru_t
xml_read_until(xml_reader_t *h, xml_condread_func_t func, void *arg,
        uint32_t flags)
{
    xml_reader_input_t *inp;
    const void *begin, *end;
    const ucs4_t *ptr;
    ucs4_t cp, cp0;
    size_t clen;
    utf8_t *bufptr;
    xru_t rv = XRU_CONTINUE;
    bool saw_cr = false;
    bool saved_loc = false;
    bool norm_warned;

    xml_reader_input_complete_notify(h); // Process any outstanding notifications

    bufptr = h->tokenbuf;
    h->rejected = UCS4_NOCHAR;
    h->tokenlen = 0;
    flags |= h->flags;

    // TBD change to do {} while (rv == XRU_CONTINUE)
    while (rv == XRU_CONTINUE) { // First check the status from inner for-loop...
        // ... and only if we're not terminating yet, try to get next read pointers
        rv = xml_reader_input_rptr(h, &begin, &end);
        inp = SLIST_FIRST(&h->active_input);
        if (!saved_loc && inp) {
            saved_loc = true;
            h->lastreadloc = inp->curloc;
        }
        if (rv != XRU_CONTINUE) {
            break;
        }
        for (ptr = begin;
                rv == XRU_CONTINUE && ptr < (const ucs4_t *)end;
                ptr++) {

            cp0 = *ptr; // codepoint before possible substitution by func
            if (saw_cr && (cp0 == 0x0A || cp0 == 0x85)) {
                // EOL normalization. This is "continuation" of a previous character - so
                // is treated before positioning update.
                /// @todo This also means these characters do not reach the normalization
                /// checker... but they are never denormalizing (neither decomposanble, nor
                /// do they appear in decompositions of other characters), so that's ok.
                saw_cr = false;
                continue;
            }

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
            if (((ucs4_cheq(cp0, '&') && (flags & R_RECOGNIZE_REF) != 0)
                        || (ucs4_cheq(cp0, '%') && (flags & R_RECOGNIZE_PEREF) != 0))
                    && !inp->ignore_references) {
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
            else if (cp0 >= 0x7F && (flags & R_ASCII_ONLY) != 0) {
                // Only complain once. Clean in the handle as well.
                flags &= ~R_ASCII_ONLY;
                h->flags &= ~R_ASCII_ONLY;
                OOPS_ASSERT(h->ctx->declinfo);
                xml_reader_message_current(h, XMLERR(ERROR, XML, P_XMLDecl),
                        "Non-ASCII characters in %s", h->ctx->declinfo->name);
            }
            else if (!inp->charref
                    && xml_is_restricted(cp0, h->current_external->version)) {
                // Ignore if it came from character reference (if it is prohibited,
                // the character reference parser already complained)
                // Non-fatal: just let the app figure what to do with it
                xml_reader_message_current(h, XMLERR(ERROR, XML, P_Char),
                        "Restricted character U+%04X", cp0);
            }

            // If normalization checking is enabled, verify the text is fully normalized:
            // - check for Unicode normalization
            // - unless parsing the reference (which will be replaced by other text),
            //   check include normalization
            // - if parsing a relevant construct, as indicated by the caller, ensure
            // Only warn once for any given location (even if different kinds of denormalization
            // occur there) - if the caller cares, it's going to take action on the first callback.
            // But, need to feed the character to both normalization checkers to maintain context.
            if (h->normalization == XML_READER_NORM_ON) {
                norm_warned = false;
                // Does it come from the regular input or was a result of some substitution?
                if (inp->external
                        && !nfc_check_nextchar(inp->external->norm_unicode, cp0)) {
                    xml_reader_message_current(h, XMLERR(WARN, XML, NORMALIZATION),
                            "Input is not Unicode-normalized");
                    norm_warned = true;
                }
                // Is this going to be a part of the document or will it be replaced?
                if ((flags & R_NO_INC_NORM) == 0
                        && !nfc_check_nextchar(h->norm_include, cp0)
                        && !norm_warned) {
                    xml_reader_message_current(h, XMLERR(WARN, XML, NORMALIZATION),
                            "Input is not include-normalized");
                    norm_warned = true;
                }
                // Relevant construct start?
                if (h->relevant) {
                    if (!norm_warned && (ucs4_get_ccc(cp0) || ucs4_get_cw_len(cp0))) {
                        // XML 1.1 spec:
                        // A composing character is a character that is one or both of
                        // the following:
                        // 1. the second character in the canonical decomposition mapping
                        // of some primary composite (as defined in D3 of UAX #15 [Unicode]),
                        // or
                        // 2. of non-zero canonical combining class (as defined in Unicode
                        // [Unicode]).
                        xml_reader_message_current(h, XMLERR(WARN, XML, NORMALIZATION),
                                "Relevant construct (%s) begins with a composing character",
                                h->relevant);
                        // TBD set h->relevant in NmToken (non-CDATA attributes)
                    }
                    h->relevant = NULL;
                }
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
                    xml_tokenbuf_realloc(h);
                    bufptr = h->tokenbuf + h->tokenlen;
                }
                utf8_store(&bufptr, cp);
                h->tokenlen += clen;
                if (flags & R_SAVE_UCS4) {
                    xml_ucs4_store(h, cp);
                }
            }

            // Character not rejected, update position. Note that we're checking
            // the original character - cp0 - not processed, so that we update position
            // based on actual input.
            if (flags & R_LOCTRACK) {
                xml_reader_update_position(inp, cp0, h->tabsize);
            }
        }

        // Consumed this block
        xml_reader_input_radvance(h, (const uint8_t *)ptr - (const uint8_t *)begin);
    }
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
    Consumes whitespace without expanding entities. Does not modify the token buffer.

    @param h Reader handle
    @return PR_OK if consumed any whitespace, PR_NOMATCH otherwise.
*/
static prodres_t
xml_parse_whitespace(xml_reader_t *h)
{
    bool had_ws = false;
    size_t tlen;

    // Whitespace may cross entity boundaries; repeat until we get something other
    // than whitespace
    tlen = h->tokenlen;
    while (xml_read_until(h, xml_cb_not_whitespace, &had_ws, 0) == XRU_INPUT_BOUNDARY) {
        // Keep reading
    }
    h->tokenlen = tlen;
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
    @param flags Reading flags
    @return PR_OK if Name production has been read, PR_NOMATCH otherwise
*/
static prodres_t
xml_read_Name(xml_reader_t *h, uint32_t flags)
{
    bool startchar = true;

    // May stop at either non-Name character, or input boundary. The first character
    // is also subject to composing character check if normalization check is active.
    h->relevant = "Name";
    (void)xml_read_until(h, xml_cb_not_name, &startchar, flags);
    if (!h->tokenlen) {
        // No error: this is an auxillary function often used to differentiate between
        // Name or some alternative (e.g. entity vs char references)
        h->relevant = NULL;
        return PR_NOMATCH;
    }
    // At least 1 character was accepted, and h->relevant is cleared on the first accepted
    // character.
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
    tlen = h->tokenlen;
    if (xml_read_until(h, xml_cb_string, &state, 0) != XRU_STOP
            || state.cur != state.end) {
        if (errinfo != XMLERR_NOERROR) {
            xml_reader_message_lastread(h, errinfo, "Expected string: '%s'", s);
        }
        h->tokenlen = tlen;
        return PR_NOMATCH;
    }
    h->tokenlen = tlen;
    return PR_OK;
}

/**
    Read an expected string where the content has already been checked via
    lookahead. Does not raise an error; rather just checks the result with
    an assertion.

    @param h Reader handle
    @param s String expected in the document; must be ASCII-only
    @return PR_OK on success, PR_NOMATCH on failure
*/
static void
xml_read_string_assert(xml_reader_t *h, const char *s)
{
    prodres_t rv;

    rv = xml_read_string(h, s, XMLERR_NOERROR);
    OOPS_ASSERT(rv == PR_OK);
}

/**
    Looking for a pattern-terminated string, using KMP (Knuth-Morris-Pratt)
    algorithm. A failure function (or table in our case) tell how much to slide
    the token back if we matched N characters and N+1 character didn't match.
*/
typedef struct {
    const char *str;        ///< Terminator string
    size_t len;             ///< Length of the terminator string
    const size_t *failtab;  ///< Array of failure function values, @a termlen elements
} xml_termstring_desc_t;

/// Current state structure for xml_cb_termstring
typedef struct xml_cb_termstring_state_s {
    xml_termstring_desc_t term;     ///< Terminator string description
    size_t pos;                     ///< Currently matched position
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

    while (st->pos > 0 && ucs4_fromlocal(st->term.str[st->pos]) != cp) {
        if (st->func) {
            st->func(st->arg, st->pos);
        }
        st->pos = st->term.failtab[st->pos - 1];
    }
    if (ucs4_fromlocal(st->term.str[st->pos]) == cp) {
        st->pos++;
    }

    // Strictly speaking, h->relevant flag should be handled specially here:
    // when starting to parse the terminator, we should stop checking for
    // relevant construct's first character until we conclude that the
    // character is not a part of the terminator. Then, when failing back
    // via fail function, we should catch up by feeding the characters
    // between the new and the old positions in the terminator to the
    // normalization checker.
    // That's a lot of complication that we can avoid by relying on
    // terminator string to be ASCII-only (which it is, XML spec does
    // not define any terminator strings with non-ASCII characters).
    // With that in mind, we may end up checking the first character of the
    // terminator string for being a non-composing character - and that
    // check will always pass, since none of ASCII characters are composing.
    return st->pos == st->term.len ? (cp | UCS4_LASTCHAR) : cp;
}

/**
    Read a string until a terminating string is seen. Terminating string itself
    is not stored into the token buffer. Terminator string may not contain
    newlines, tabs or combining characters (location update logic for backtracking
    is very simple-minded).

    @param h Reader handle
    @param ts Terminator string info (string, length, failure function)
    @param func Function to call in case of we need to backtrack (i.e., if a part
        of the terminator string is seen, but then a mismatch is detected). The
        function shall accept one argument, the number of characters matched before
        a mismatch occurred. NULL if no notifications are requested.
    @param arg Argument to @a func callback
    @return PR_OK on success, PR_NOMATCH if terminator string was not found.
*/
static prodres_t
xml_read_termstring(xml_reader_t *h, const xml_termstring_desc_t *ts,
        void (*func)(void *, size_t), void *arg)
{
    xml_cb_termstring_state_t st;

    st.term = *ts;
    st.pos = 0;
    st.func = func;
    st.arg = arg;
    if (xml_read_until(h, xml_cb_termstring, &st, 0) != XRU_STOP) {
        return PR_NOMATCH;
    }
    // Drop match terminator from token buffer
    h->tokenlen -= st.term.len;
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
        [XML_READER_REF_GENERAL] = { "general entity", XMLERR_XML_P_EntityRef },
        [XML_READER_REF_UNKNOWN] = { "unknown", XMLERR_XML_P_Reference },
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
    static ucs4_t rplc_percent[] = { 0x25 /* '%' in Unicode */ };
    xml_cb_charref_state_t st;
    xml_reader_input_t *inp;
    const xml_reference_info_t *ri;
    xmlerr_loc_t saveloc;           // Report reference at the start character
    xru_t rv;
    ucs4_t startchar = h->rejected;

    // We know startchar is there, it has been rejected by previous call. Whatever
    // we read is not going to be a part of include-normalization check.
    h->flags |= R_NO_INC_NORM;
    if (ucs4_cheq(startchar, '&')) {
        // This may be either entity or character reference
        xml_read_string_assert(h, "&");
        xml_reader_input_lock(h);
        saveloc = h->lastreadloc;
        if (xml_read_Name(h, 0) == PR_OK) {
            // EntityRef
            *reftype = XML_READER_REF_GENERAL;
            goto read_content;
        }
        else if (ucs4_cheq(h->rejected, '#')) {
            // CharRef
            *reftype = XML_READER_REF__CHAR;
            xml_read_string_assert(h, "#");
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
            *reftype = XML_READER_REF_UNKNOWN;
            goto malformed;
        }
    }
    else if (ucs4_cheq(startchar, '%')) {
        // PEReference or standalone percent sign. In external subset,
        // percent sign may be taken literally in the parameter entity
        // definition. If that's the case, it is followed by a whitespace
        // (S) rather than Name.
        xml_read_string_assert(h, "%");
        xml_reader_input_lock(h);
        saveloc = h->lastreadloc;
        *reftype = XML_READER_REF_PARAMETER;
        if (xml_read_Name(h, 0) == PR_OK) {
            goto read_content;
        }
        if (h->flags & R_AMBIGUOUS_PERCENT) {
            goto literal_percent;
        }
        goto malformed;
    }
    else {
        // How did we get here?
        OOPS;
    }

literal_percent:
    // Consider the percent sign as having literal meaning. Prepend an
    // an input with percent sign; mark it as reference-ignoring so that
    // we don't try to interpret this as a PE reference again
    h->flags &= ~R_NO_INC_NORM;
    xml_reader_input_unlock_assert(h);
    inp = xml_reader_input_new(h, "literal percent sign");
    strbuf_set_input(inp->buf, rplc_percent, sizeof(rplc_percent));
    inp->curloc = saveloc;
    inp->ignore_references = true;
    return PR_NOMATCH;

read_content:
    ri = xml_entity_type_info(*reftype);
    // Reading as a whole - if fail to match string, error will be raised below
    if (xml_read_string(h, ";", XMLERR_NOERROR) != PR_OK) {
        goto malformed;
    }
    h->flags &= ~R_NO_INC_NORM;
    h->lastreadloc = saveloc;
    xml_reader_input_unlock_assert(h);
    return PR_OK;

malformed:
    h->flags &= ~R_NO_INC_NORM;
    ri = xml_entity_type_info(*reftype);
    h->lastreadloc = saveloc;
    xml_reader_message_lastread(h, XMLERR_MK(XMLERR_ERROR, XMLERR_SPEC_XML, ri->ecode),
            "Malformed %s reference", ri->desc);
    xml_reader_input_unlock_assert(h);
    return PR_FAIL;
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

    // The rest is allowed in XML 1.1. In XML 1.0, restricted characters
    // are prohibited even via character references.
    return (h->current_external->version == XML_INFO_VERSION_1_1) ?
            true : !xml_is_restricted(cp, XML_INFO_VERSION_1_0);
}

/**
    Notify application when entity parsing starts

    @param h Reader handle
    @param e Entity
    @return Nothing
*/
static void
entity_start(xml_reader_t *h, xml_reader_entity_t *e)
{
    xml_reader_cbparam_t cbp;

    cbp.cbtype = XML_READER_CB_ENTITY_START;
    cbp.loc = h->lastreadloc;
    cbp.token.str = e->name;
    cbp.token.len = e->namelen;
    cbp.entity.type = e->type;
    cbp.entity.system_id = e->loader_info.system_id;
    cbp.entity.public_id = e->loader_info.public_id;
    xml_reader_invoke_callback(h, &cbp);
    e->included = h->lastreadloc;
    e->being_parsed = true;
}

/**
    When entity finishes parsing, mark it available for other references.

    @param h Reader handle
    @param arg Input that has completed
    @return Nothing
*/
static void
entity_end(xml_reader_t *h, void *arg)
{
    xml_reader_entity_t *e = arg;
    xml_reader_cbparam_t cbp;

    memset(&cbp, 0, sizeof(cbp));
    cbp.cbtype = XML_READER_CB_ENTITY_END;
    cbp.loc = e->included;
    cbp.token.str = e->name;
    cbp.token.len = e->namelen;
    cbp.entity.type = e->type;
    cbp.entity.system_id = e->loader_info.system_id;
    cbp.entity.public_id = e->loader_info.public_id;
    xml_reader_invoke_callback(h, &cbp);
    e->being_parsed = false;
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
            "Reference to %s is forbidden here", ri->desc);
}

/**
    Entity handler: 'Included in literal'

    @param h Reader handle
    @param e Entity information
    @param inc_in_literal True if 'included in literal'
    @param ctx Parser context for the new entity's input; only meaningful for external
        entities. NULL if no context switch is needed.
    @return Nothing
*/
static void
reference_included_common(xml_reader_t *h, xml_reader_entity_t *e, bool inc_in_literal,
        const xml_reader_context_t *ctx)
{
    xml_reader_input_t *inp;

    entity_start(h, e);
    if (xml_loader_info_isset(&e->loader_info)) {
        if (!xml_reader_invoke_loader(h, &e->loader_info, e, ctx, inc_in_literal)) {
            // No input has been added - consider it end of this entity's parsing
            entity_end(h, e);
        }
    }
    else {
        inp = xml_reader_input_new(h, e->location);
        strbuf_set_input(inp->buf, e->rplc, e->rplclen);
        inp->entity = e;
        inp->inc_in_literal = inc_in_literal;
        inp->complete = entity_end;
        inp->complete_arg = e;
    }
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
    reference_included_common(h, e, true, NULL);
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
    reference_included_common(h, e, false, NULL);
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
    // TBD check 'if validating' condition? Or have a separate flag, 'loading entities', that
    // controls this function?
    reference_included_common(h, e, false, NULL);
}

/**
    Entity handler: 'Included as PE (parameter entity)'. Replacement text is
    augmented by spaces before and after.

    @param h Reader handle
    @param e Entity information
    @return Nothing
*/
static void
reference_included_as_pe(xml_reader_t *h, xml_reader_entity_t *e)
{
    static ucs4_t rplc_space[] = { 0x20 /* ' ' in Unicode */ };
    xml_reader_input_t *inp;

    // Inputs are prepended, so adding them in backwards order. Not that it
    // matters, though :)
    inp = xml_reader_input_new(h, NULL);
    strbuf_set_input(inp->buf, rplc_space, sizeof(rplc_space));
    reference_included_common(h, e, false, &parser_external_subset);
    inp = xml_reader_input_new(h, NULL);
    strbuf_set_input(inp->buf, rplc_space, sizeof(rplc_space));
}

/**
    Entity handler: 'Bypassed'

    @param h Reader handle
    @param e Entity information
    @return Nothing
*/
static void
reference_bypassed(xml_reader_t *h, xml_reader_entity_t *e)
{
    xml_reader_input_t *inp;

    inp = xml_reader_input_new(h, e->location);
    strbuf_set_input(inp->buf, e->refrplc, e->refrplclen);
    inp->ignore_references = true;
}

/**
    Entity handler: 'Error'

    @param h Reader handle
    @param e Entity information
    @return Nothing
*/
static void
reference_error(xml_reader_t *h, xml_reader_entity_t *e)
{
    const xml_reference_info_t *ri;

    ri = xml_entity_type_info(e->type);
    xml_reader_message_lastread(h, XMLERR_MK(XMLERR_ERROR, XMLERR_SPEC_XML, ri->ecode),
            "%s reference here is an error", ri->desc);
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

    /// @todo with h->tokenlen/tokenbuf check from the handler - perhaps, avoid
    /// setting a new input and just append the character directly? That will forgo
    /// any normalization if it is performed by the xml_read_until, however.
    inp = xml_reader_input_new(h, e->location);
    strbuf_set_input(inp->buf, e->rplc, e->rplclen);

    // Character reference behavior is close to what's described in XML spec as
    // 'Included in literal' (i.e., in literal the character reference to the quote
    // character does not terminate the literal). They also can represent references
    // to start characters which will not be recognized by xml_read_until.
    inp->inc_in_literal = true;
    inp->ignore_references = true;
    inp->charref = true;
}

/**
    Wrapper around xml_read_until(): if entities are recognized and
    xml_read_until() returned due to start of an entity, issue
    a callback to expand that entity and if that callback returned
    the replacement text, divert the reader's input to that entity.
    Otherwise, skip over the entity and continue.

    @param h Reader handle
    @param refops Actions to perform when encountering an entity, or
        a contiguous text block; a mask of recognized entities, and
        a stop-condition detection.
    @param arg Argument to @a func
    @return Status why the parser terminated
*/
static xru_t
xml_read_until_parseref(xml_reader_t *h, const xml_reference_ops_t *refops, void *arg)
{
    xru_t stopstatus;
    xml_reader_cbparam_t cbp;
    enum xml_reader_reference_e reftype = XML_READER_REF__NONE; // No reference yet
    xml_reader_entity_t *e;
    xml_reader_entity_t fakechar;
    const char *saved_relevant;

    /// @todo drop 4th arg and set all flags in h->flags?
    while (true) {
        do {
            if (reftype != XML_READER_REF__CHAR) {
                // For normalization checking, character references are considered a part
                // of the construct they belong to.
                // "... and by then verifying that none of the relevant constructs listed
                // above begins (after character references are expanded) with a composing
                // character..."
                h->relevant = refops->relevant;
            }
            stopstatus = xml_read_until(h, refops->condread, arg, refops->flags);
            if (refops->textblock) {
                refops->textblock(arg);
            }
        } while (stopstatus == XRU_INPUT_BOUNDARY);

        if (stopstatus != XRU_REFERENCE) {
            h->relevant = NULL;
            return stopstatus; // Saw the terminating condition or EOF
        }

        // We have some kind of entity, read its name or code point. Entity reference
        // itself is not a relevant construct (although Name production inside it,
        // if it is an entity reference, is).
        saved_relevant = h->relevant;
        h->relevant = NULL;
        if (xml_parse_reference(h, &reftype) != PR_OK) {
            // This may or may not be error: PR_NOMATCH means that it just wasn't a PE
            // reference despite having started with a percent sign.  If it is an error,
            // no recovery - just interpret anything after error as plain text.
            reftype = XML_READER_REF__NONE;
            continue;
        }
        h->relevant = saved_relevant;

        switch (reftype) {
        case XML_READER_REF__CHAR:
            /* Parse the character referenced */
            if (h->charrefval == UCS4_NOCHAR) {
                // Did not evaluate to a character; recover by skipping.
                xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_CharRef),
                        "Character reference did not evaluate to a valid "
                        "UCS-4 code point");
                reftype = XML_READER_REF__NONE;
                continue;
            }
            if (!xml_valid_char_reference(h, h->charrefval)) {
                // Recover by skipping invalid character.
                xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_CharRef),
                        "Referenced character does not match Char production");
                reftype = XML_READER_REF__NONE;
                continue;
            }
            fakechar.type = XML_READER_REF__CHAR;
            fakechar.location = NULL;
            fakechar.being_parsed = false;
            fakechar.rplc = &h->charrefval;
            fakechar.rplclen = sizeof(h->charrefval);
            e = &fakechar;
            break;

        case XML_READER_REF_GENERAL:
            // Clarify the type
            e = strhash_get(h->entities_gen, h->tokenbuf, h->tokenlen);
            break;

        case XML_READER_REF_PARAMETER:
            e = strhash_get(h->entities_param, h->tokenbuf, h->tokenlen);
            break;

        default:
            OOPS;
        }

        if (!e) {
            // Entity was not known. This may or may not be error; let the callback decide
            cbp.cbtype = XML_READER_CB_ENTITY_UNKNOWN;
            cbp.loc = h->lastreadloc;
            cbp.entity.type = reftype; // Our best guess
            cbp.token.str = h->tokenbuf;
            cbp.token.len = h->tokenlen;
            cbp.entity.system_id = NULL;
            cbp.entity.public_id = NULL;
            xml_reader_invoke_callback(h, &cbp);
        }
        else if (e->being_parsed) {
            xml_reader_message_lastread(h, XMLERR(ERROR, XML, WFC_NO_RECURSION),
                    "Parsed entity may not contain a recursive reference to itself");
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

/// Virtual methods for reading whitespace with possible PEReference
static const xml_reference_ops_t reference_ops_PEReference = {
    .errinfo = XMLERR(ERROR, XML, P_CharData),
    .condread = xml_cb_not_whitespace,
    .flags = R_RECOGNIZE_PEREF,
    .relevant = NULL,
    .hnd = {
        // Default: 'Not recognized'. The table in XML spec lists the
        // rest of the references as 'forbidden' - but DTD grammar will not
        // even recognize them.
        [XML_READER_REF_PARAMETER] = reference_included_as_pe,
    },
};

/**
    Consume whitespace while checking for parameter entities. Used for parsing the
    DeclSep production and, conditionally, for expanding entities in external subset
    and parameter entities. See xml_parse_whitespace_conditional for details how this
    works in the latter case.

    This is similar to the regular xml_parse_whitespace() except that it calls
    reference-expanding parser.

    @param h Reader handle
    @return PR_OK if consumed any whitespace, PR_NOMATCH otherwise.
*/
static prodres_t
xml_parse_whitespace_peref(xml_reader_t *h)
{
    bool had_ws = false;
    size_t tlen;

    // Whitespace may cross entity boundaries; repeat until we get something other
    // than whitespace
    tlen = h->tokenlen;
    (void)xml_read_until_parseref(h, &reference_ops_PEReference, &had_ws);
    h->tokenlen = tlen;
    return had_ws ? PR_OK : PR_NOMATCH;
}

/**
    Smart consumption of whitespace: if in the internal subset, use the regular
    whitespace consumer. If in the external subset, use PE-expanding consumer.

    The rationale here is that the parameter entity substitution outside of the
    EntityValue production is prepended and appended with a space. Therefore, entity
    references are only valid where whitespace is permitted. We are thus expanding
    them only when we look for whitespace and in that case we know the whitespace
    will be matched. This function is hence used inside the production parsers
    that may be used by external subset - if the same production appears (and is
    allowed) in internal subset, this whitespace parser will behave as if it were
    regular skip-the-whitespace.

    @param h Reader handle
    @return PR_OK if consumed any whitespace, PR_NOMATCH otherwise.
*/
static prodres_t
xml_parse_whitespace_conditional(xml_reader_t *h)
{
    return h->ctx->reftype == XML_READER_REF_EXT_SUBSET ?
            xml_parse_whitespace_peref(h) :
            xml_parse_whitespace(h);
}


/**
    Common part of a handler for text block in literals or content.

    @param h Reader handle
    @param ws If true, appended text contains only whitespace
    @return Nothing
*/
static void
textblock_append_common(xml_reader_t *h, bool ws)
{
    xml_reader_cbparam_t cbp;

    if (h->tokenlen) {
        cbp.cbtype = XML_READER_CB_APPEND;
        cbp.loc = h->lastreadloc;
        cbp.token.str = h->tokenbuf;
        cbp.token.len = h->tokenlen;
        cbp.append.ws = ws;
        xml_reader_invoke_callback(h, &cbp);
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
    Handler for text block in literals: invoke callback to append text.

    @param arg Literal parser state
    @return Nothing
*/
static void
textblock_append_literal(void *arg)
{
    xml_cb_literal_state_t *st = arg;

    textblock_append_common(st->h, false);
}

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
        xml_reader_input_lock(st->h);
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
    Special version of literal parser for parsed entity values: they are considered
    relevant constructs and must perform the check for composing character right
    after the opening quote.

    @param arg Current state
    @param cp Codepoint
    @return true if this character is rejected
*/
static ucs4_t
xml_cb_literal_EntityValue(void *arg, ucs4_t cp)
{
    xml_cb_literal_state_t *st = arg;

    if (st->quote != UCS4_NOCHAR
            && st->h->tokenlen == 0) {
        st->h->relevant = "parsed entity value";
    }

    // Strictly speaking  we should also clear h->relevant when the closing quote is
    // seen, but it is going to pass the check for composing character anyway, so why
    // bother?
    return xml_cb_literal(arg, cp);
}

/// Virtual methods for reading "pseudo-literals" (quoted strings in XMLDecl)
static const xml_reference_ops_t reference_ops_pseudo = {
    .errinfo = XMLERR(ERROR, XML, P_XMLDecl),
    .condread = xml_cb_literal,
    .flags = 0,
    .relevant = NULL,
    .hnd = { /* No entities expected */ },
};

/// Virtual methods for reading attribute values (AttValue production)
/// @todo: .condread must check for forbidden character ('<')
static const xml_reference_ops_t reference_ops_AttValue = {
    .errinfo = XMLERR(ERROR, XML, P_AttValue),
    .condread = xml_cb_literal,
    .flags = R_RECOGNIZE_REF,
    .relevant = NULL,
    .textblock = textblock_append_literal,
    .hnd = {
        /* Default: 'Not recognized' */
        [XML_READER_REF_INTERNAL] = reference_included_in_literal,
        [XML_READER_REF_EXTERNAL] = reference_forbidden,
        [XML_READER_REF_UNPARSED] = reference_forbidden,
        [XML_READER_REF__CHAR] = reference_included_charref,
    },
};

/// Virtual methods for reading system ID (SystemLiteral production)
static const xml_reference_ops_t reference_ops_SystemLiteral = {
    .errinfo = XMLERR(ERROR, XML, P_SystemLiteral),
    .condread = xml_cb_literal,
    .flags = 0,
    .relevant = NULL,
    .hnd = { /* No entities expected */ },
};

/// Virtual methods for reading public ID (PubidLiteral production)
/// @todo Need to disallow characters except for PubidChar. Do it in some
/// way so that READER_ASCII may also make use of that approach? Also,
/// can attribute value normalization use that approach?
static const xml_reference_ops_t reference_ops_PubidLiteral = {
    .errinfo = XMLERR(ERROR, XML, P_PubidLiteral),
    .condread = xml_cb_literal,
    .flags = 0,
    .relevant = NULL,
    .hnd = { /* No entities expected */ },
};

/// Virtual methods for reading entity value (EntityValue production) in internal subset
static const xml_reference_ops_t reference_ops_EntityValue_internal = {
    .errinfo = XMLERR(ERROR, XML, P_EntityValue),
    .condread = xml_cb_literal_EntityValue,
    .flags = R_RECOGNIZE_REF | R_RECOGNIZE_PEREF | R_SAVE_UCS4,
    .relevant = NULL,
    .textblock = textblock_append_literal,
    .hnd = {
        [XML_READER_REF_PARAMETER] = reference_forbidden,
        [XML_READER_REF_INTERNAL] = reference_bypassed,
        [XML_READER_REF_EXTERNAL] = reference_bypassed,
        [XML_READER_REF_UNPARSED] = reference_error,
        [XML_READER_REF__CHAR] = reference_included_charref,
    },
};

/// Virtual methods for reading entity value (EntityValue production) in external subset
static const xml_reference_ops_t reference_ops_EntityValue_external = {
    .errinfo = XMLERR(ERROR, XML, P_EntityValue),
    .condread = xml_cb_literal_EntityValue,
    .flags = R_RECOGNIZE_REF | R_RECOGNIZE_PEREF | R_SAVE_UCS4,
    .relevant = NULL,
    .textblock = textblock_append_literal,
    .hnd = {
        [XML_READER_REF_PARAMETER] = reference_included_in_literal,
        [XML_READER_REF_INTERNAL] = reference_bypassed,
        [XML_READER_REF_EXTERNAL] = reference_bypassed,
        [XML_READER_REF_UNPARSED] = reference_error,
        [XML_READER_REF__CHAR] = reference_included_charref,
    },
};

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
    if (xml_read_until_parseref(h, refops, &st) != XRU_STOP
            || st.quote != UCS4_STOPCHAR) {
        if (st.quote == UCS4_NOCHAR) {
            xml_reader_message_lastread(h, refops->errinfo,
                    "Quoted literal expected");
            // Input only locked when quote character is seen
        }
        else {
            xml_reader_message_lastread(h, refops->errinfo,
                    "Unterminated literal");
            // Quote character loses its meaning if entity is included
            // in literal
            xml_reader_input_unlock_assert(h);
        }
        return PR_FAIL;
    }
    xml_reader_input_unlock_assert(h);
    return PR_OK;
}

/**
    Check for VersionInfo production.

    @verbatim
    VersionNum ::= '1.' [0-9]+    {{XML1.0}}
    VersionNum ::= '1.1'          {{XML1.1}}
    @endverbatim

    @param ex External entity info
    @return Nothing
*/
static void
check_VersionInfo(xml_reader_external_t *ex)
{
    xml_reader_t *h = ex->h;
    const utf8_t *str = h->tokenbuf;
    size_t sz = h->tokenlen;
    size_t i;

    if (sz == 3) {
        if (utf8_eqn(str, "1.0", 3)) {
            ex->version = XML_INFO_VERSION_1_0;
            return;
        }
        else if (utf8_eqn(str, "1.1", 3)) {
            ex->version = XML_INFO_VERSION_1_1;
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
    ex->version = XML_INFO_VERSION_1_0;
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

    @param ex External entity info
    @return Nothing
*/
static void
check_EncName(xml_reader_external_t *ex)
{
    xml_reader_t *h = ex->h;
    const utf8_t *str = h->tokenbuf;
    const utf8_t *s;
    size_t sz = h->tokenlen;
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

    ex->enc_declared = utf8_ndup(str, sz);
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

    @param ex External entity info
    @return Nothing
*/
static void
check_SD_YesNo(xml_reader_external_t *ex)
{
    xml_reader_t *h = ex->h;
    const utf8_t *str = h->tokenbuf;
    size_t sz = h->tokenlen;

    // Standalone status applies to the whole document and can only be set
    // in XMLDecl (i.e., in document entity).
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
    const xml_reader_xmldecl_declinfo_t *declinfo = h->ctx->declinfo;
    const xml_reader_xmldecl_attrdesc_t *attrlist = declinfo->attrlist;
    xml_reader_cbparam_t cbp;
    utf8_t labuf[6]; // ['<?xml' + whitespace] or [?>]
    bool had_ws;

    if (6 != xml_lookahead(h, labuf, 6)
            || !utf8_eqn(labuf, "<?xml", 5)
            || !xml_is_whitespace(labuf[5])) {
        return PR_NOMATCH; // Does not start with a declaration
    }

    // We know it's there, checked above
    xml_read_string_assert(h, "<?xml");
    xml_reader_input_lock(h);
    cbp.cbtype = XML_READER_CB_XMLDECL;
    cbp.token.str = NULL;
    cbp.token.len = 0;
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
        if (!had_ws || xml_read_Name(h, 0) != PR_OK) {
            goto malformed;
        }

        // Go through the remaining attributes and see if this one is known
        // (and if we skipped any mandatory attributes while advancing).
        while (attrlist->name) {
            if (h->tokenlen == strlen(attrlist->name)
                    && utf8_eqn(h->tokenbuf, attrlist->name, h->tokenlen)) {
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
            attrlist->check(h->current_external);
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
    cbp.xmldecl.encoding = h->current_external->enc_declared;
    cbp.xmldecl.version = h->current_external->version;
    cbp.xmldecl.standalone = h->standalone; // TBD do away with XML declaration reporting? doesn't seem
                                            // to have any value for consumer, and standalone status
                                            // does not make sense except in doc entity. Instead,
                                            // provide interfaces to query it via API
    xml_reader_invoke_callback(h, &cbp);
    xml_reader_input_unlock_assert(h);

    return PR_OK;

malformed: // Any fatal malformedness: report location where actual error was
    xml_reader_message_current(h, XMLERR(ERROR, XML, P_XMLDecl),
            "Malformed %s", declinfo->name);
    xml_reader_input_unlock_assert(h);
    return PR_FAIL;
}

/// State of CharData parser
typedef struct {
    xml_reader_t *h;        ///< Reader handle
    bool ws;                ///< True if parsed token only has whitespace
} cb_CharData_t;

/**
    Callback to find the end of the character data.

    @param arg CharData parser state
    @param cp Current codepoint
    @return Nothing
*/
static ucs4_t
xml_cb_CharData(void *arg, ucs4_t cp)
{
    cb_CharData_t *st = arg;

    // TBD: need to check if the content matches ']]>' token and raise an error if it does
    if (!ucs4_cheq(cp, '<') || SLIST_FIRST(&st->h->active_input)->charref) {
        if (st->ws && !xml_is_whitespace(cp)) {
            st->ws = false;
        }
        return cp;
    }
    return UCS4_STOPCHAR;
}

/**
    Handler for text block in content: invoke callback to append text.

    @param arg CharData parser state
    @return Nothing
*/
static void
textblock_append_CharData(void *arg)
{
    cb_CharData_t *st = arg;

    textblock_append_common(st->h, st->ws);
}

/// Virtual methods for reading CharData production
static const xml_reference_ops_t reference_ops_CharData = {
    .errinfo = XMLERR(ERROR, XML, P_CharData),
    .condread = xml_cb_CharData,
    .flags = R_RECOGNIZE_REF,
    .relevant = "CharData",
    .textblock = textblock_append_CharData,
    .hnd = {
        /* Default: 'Not recognized' */
        [XML_READER_REF_INTERNAL] = reference_included,
        [XML_READER_REF_EXTERNAL] = reference_included_if_validating,
        [XML_READER_REF_UNPARSED] = reference_forbidden,
        [XML_READER_REF__CHAR] = reference_included_charref,
    },
};

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
    cb_CharData_t st;

    st.h = h;
    st.ws = true; // Until we've seen anything but
    (void)xml_read_until_parseref(h, &reference_ops_CharData, &st);
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

/// Terminator string description for comment closing tag: '-->'
static const xml_termstring_desc_t termstring_comment = {
    .str = "-->",
    .len = 3,
    .failtab = (const size_t[3]){ 0, 1, 0 },
};

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

    xml_read_string_assert(h, "<!--");
    xml_reader_input_lock(h);
    cbp.cbtype = XML_READER_CB_COMMENT;
    cbp.loc = h->lastreadloc;

    cbh.h = h;
    cbh.warned = false;
    if (xml_read_termstring(h, &termstring_comment, comment_backtrack_handler, &cbh) != PR_OK) {
        // no need to recover (EOF)
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_Comment),
                "Unterminated comment");
        xml_reader_input_unlock_assert(h);
        return PR_STOP;
    }
    cbp.token.str = h->tokenbuf;
    cbp.token.len = h->tokenlen;
    xml_reader_invoke_callback(h, &cbp);
    xml_reader_input_unlock_assert(h);
    return PR_OK;
}

/// Terminator string description for processing instruction closing tag: '?>'
static const xml_termstring_desc_t termstring_pi = {
    .str = "?>",
    .len = 2,
    .failtab = (const size_t[2]){ 0, 0 },
};

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
    xml_reader_notation_t *n;

    xml_read_string_assert(h, "<?");
    xml_reader_input_lock(h);
    cbp.cbtype = XML_READER_CB_PI_TARGET;
    cbp.loc = h->lastreadloc;
    if (xml_read_Name(h, 0) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_PI),
                "Expected PI target here");
        xml_read_until_gt(h);
        xml_reader_input_unlock_assert(h);
        return PR_OK;
    }
    /// @todo Check for XML-reserved names ([Xx][Mm][Ll]*)

    // "The XML Notation mechanism may be used for formal declaration of PI targets"
    // If it was, report notation's system and public IDs.
    cbp.token.str = h->tokenbuf;
    cbp.token.len = h->tokenlen;
    n = strhash_get(h->notations, h->tokenbuf, h->tokenlen);
    cbp.ndata.public_id = n ? n->loader_info.public_id : NULL;
    cbp.ndata.system_id = n ? n->loader_info.system_id : NULL;
    xml_reader_invoke_callback(h, &cbp);

    // Content, if any, must be separated by a whitespace
    if (xml_parse_whitespace(h) == PR_OK) {
        // Whitespace; everything up to closing ?> is the content
        if (xml_read_termstring(h, &termstring_pi, NULL, NULL) == PR_OK) {
            cbp.cbtype = XML_READER_CB_PI_CONTENT;
            cbp.token.str = h->tokenbuf;
            cbp.token.len = h->tokenlen;
            xml_reader_invoke_callback(h, &cbp);
            xml_reader_input_unlock_assert(h);
            return PR_OK;
        }
        else {
            // no need to recover (EOF)
            xml_reader_message_current(h, XMLERR(ERROR, XML, P_PI),
                    "Unterminated processing instruction");
            xml_reader_input_unlock_assert(h);
            return PR_STOP;
        }
    }
    else if (xml_read_string(h, "?>", XMLERR(ERROR, XML, P_PI)) == PR_OK) {
        // We could only have closing ?> if there's no whitespace after PI target.
        // There is no content in this case.
        xml_reader_input_unlock_assert(h);
        return PR_OK;
    }

    // Recover by skipping until closing angle bracket
    xml_read_until_gt(h);
    xml_reader_input_unlock_assert(h);
    return PR_OK;
}

/// Terminator string description for CData closing tag: ']]>'
static const xml_termstring_desc_t termstring_cdata = {
    .str = "]]>",
    .len = 3,
    .failtab = (const size_t[3]){ 0, 1, 0 },
};

/**
    Read and process a CDATA section.

    For purposes of checking of ignorable whitespace, CDATA is never considered
    whitespace: "Note that a CDATA section containing only white space [...]
    do not match the nonterminal S, and hence cannot appear in these positions."
    (XML spec, describing validity constraints for elements with 'children'
    content).

    @verbatim
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

    xml_read_string_assert(h, "<![CDATA[");
    xml_reader_input_lock(h);
    cbp.cbtype = XML_READER_CB_CDSECT;
    cbp.loc = h->lastreadloc;

    // Starting CData - which is relevant construct
    h->relevant = "CData";
    if (xml_read_termstring(h, &termstring_cdata, NULL, NULL) != PR_OK) {
        // no need to recover (EOF)
        /// @todo Test unterminated comments/PIs/CDATA in entities - is PR_STOP proper here?
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_CDSect),
                "Unterminated CDATA section");
        xml_reader_input_unlock_assert(h);
        h->relevant = NULL;
        return PR_STOP;
    }
    h->relevant = NULL;
    cbp.token.str = h->tokenbuf;
    cbp.token.len = h->tokenlen;
    cbp.append.ws = false;
    xml_reader_invoke_callback(h, &cbp);
    xml_reader_input_unlock_assert(h);
    return PR_OK;
}

/**
    Parse an ExternalID or PublicID production preceded by a whitespace (S). Upon entry,
    h->rejected must contain the first character of (presumably) external ID.

    @param h Reader handle
    @param allowed_PublicID If true, PublicID production is allowed. In that case, this
        function may also consume the whitespace following the PubidLiteral.
    @param loader_info If non-NULL, points to the structure where system/public ID copies
        will be saved
    @return PR_OK if parsed either of these productions; PR_FAIL if parsing error was
        detected or PR_NOMATCH if there was no whitespace or it was not followed by 'S'
        or 'P' characters. In case of PR_NOMATCH, whitespace is consumed.
*/
static prodres_t
xml_parse_ExternalID(xml_reader_t *h, bool allowed_PublicID,
        xml_loader_info_t *loader_info)
{
    xml_reader_cbparam_t cbp;
    bool has_system_id = false;
    bool has_public_id = false;

    // 'SYSTEM' ... or 'PUBLIC' ...
    if (ucs4_cheq(h->rejected, 'S')) {
        if (xml_read_string(h, "SYSTEM", XMLERR(ERROR, XML, P_ExternalID)) != PR_OK) {
            return PR_FAIL;
        }
        has_system_id = true;
    }
    else if (ucs4_cheq(h->rejected, 'P')) {
        if (xml_read_string(h, "PUBLIC", XMLERR(ERROR, XML, P_ExternalID)) != PR_OK) {
            return PR_FAIL;
        }
        has_system_id = true;
        has_public_id = true;
    }
    else {
        return PR_NOMATCH;
    }

    if (has_public_id) {
        // Had external ID with PUBLIC: S PubidLiteral
        if (xml_parse_whitespace_conditional(h) != PR_OK) {
            xml_reader_message_current(h, XMLERR(ERROR, XML, P_ExternalID),
                    "Expect whitespace here");
            return PR_FAIL;
        }
        if (xml_parse_literal(h, &reference_ops_PubidLiteral) != PR_OK) {
            return PR_FAIL;
        }
        if (loader_info) {
            xml_loader_info_set_public_id(loader_info,
                    h->tokenbuf, h->tokenlen);
        }
        cbp.cbtype = XML_READER_CB_PUBID;
        cbp.loc = h->lastreadloc;
        cbp.token.str = h->tokenbuf;
        cbp.token.len = h->tokenlen;
        xml_reader_invoke_callback(h, &cbp);
    }
    if (has_system_id) {
        // Had any external ID, or (if allowed) PublicID
        if (allowed_PublicID) {
            if (xml_parse_whitespace_conditional(h) != PR_OK
                    || !(ucs4_cheq(h->rejected, '"') || ucs4_cheq(h->rejected, '\''))) {
                return PR_OK; // Missing second (system) literal, but it's ok
            }
        }
        else {
            if (xml_parse_whitespace_conditional(h) != PR_OK) {
                xml_reader_message_current(h, XMLERR(ERROR, XML, P_ExternalID),
                        "Expect whitespace here");
                return PR_FAIL;
            }
        }
        if (xml_parse_literal(h, &reference_ops_SystemLiteral) != PR_OK) {
            return PR_FAIL;
        }
        if (loader_info) {
            xml_loader_info_set_system_id(loader_info,
                    h->tokenbuf, h->tokenlen);
        }
        cbp.cbtype = XML_READER_CB_SYSID;
        cbp.loc = h->lastreadloc;
        cbp.token.str = h->tokenbuf;
        cbp.token.len = h->tokenlen;
        xml_reader_invoke_callback(h, &cbp);
    }
    return PR_OK;
}

/**
    Parse element declaration (elementdecl).

    @verbatim
    elementdecl ::= '<!ELEMENT' S Name S contentspec S? '>
    contentspec ::= 'EMPTY' | 'ANY' | Mixed | children
    children    ::= (choice | seq) ('?' | '*' | '+')?
    cp          ::= (Name | choice | seq) ('?' | '*' | '+')?
    choice      ::= '(' S? cp ( S? '|' S? cp )+ S? ')'
    seq         ::= '(' S? cp ( S? ',' S? cp )* S? ')'
    Mixed       ::= '(' S? '#PCDATA' (S? '|' S? Name)* S? ')*' | '(' S? '#PCDATA' S? ')'
    @endverbatim

    @param h Reader handle
    @return PR_OK if the declaration parsed successfully, or recovery was performed
*/
static prodres_t
xml_parse_elementdecl(xml_reader_t *h)
{
    /// @todo Implement
    xml_read_until(h, xml_cb_gt, NULL, 0);
    return PR_OK;
}

/**
    Parse attribute list declaration (AttlistDecl).

    @verbatim
    AttlistDecl    ::= '<!ATTLIST' S Name AttDef* S? '>'
    AttDef         ::= S Name S AttType S DefaultDecl
    AttType        ::= StringType | TokenizedType | EnumeratedType
    StringType     ::= 'CDATA'
    TokenizedType  ::= 'ID' | 'IDREF' | 'IDREFS' | 'ENTITY' | 'ENTITIES' |
                       'NMTOKEN' | 'NMTOKENS'
    EnumeratedType ::= NotationType | Enumeration
    NotationType   ::= 'NOTATION' S '(' S? Name (S? '|' S? Name)* S? ')'
    Enumeration    ::= '(' S? Nmtoken (S? '|' S? Nmtoken)* S? ')'
    DefaultDecl    ::= '#REQUIRED' | '#IMPLIED' | (('#FIXED' S)? AttValue)
    @endverbatim

    @param h Reader handle
    @return PR_OK if the declaration parsed successfully, or recovery was performed
*/
static prodres_t
xml_parse_AttlistDecl(xml_reader_t *h)
{
    /// @todo Implement
    xml_read_until(h, xml_cb_gt, NULL, 0);
    return PR_OK;
}

/**
    Parse general or parameter entity declaration (EntityDecl).

    @verbatim
    EntityDecl ::= GEDecl | PEDecl
    GEDecl     ::= '<!ENTITY' S Name S EntityDef S? '>'
    PEDecl     ::= '<!ENTITY' S '%' S Name S PEDef S? '>'
    EntityDef  ::= EntityValue | (ExternalID NDataDecl?)
    PEDef      ::= EntityValue | ExternalID
    ExternalID ::= 'SYSTEM' S SystemLiteral | 'PUBLIC' S PubidLiteral S SystemLiteral
    NDataDecl  ::= S 'NDATA' S Name
    EntityValue::= '"' ([^%&"] | PEReference | Reference)* '"' |
                   "'" ([^%&'] | PEReference | Reference)* "'"
    @endverbatim

    @param h Reader handle
    @return PR_OK if the declaration parsed successfully, or recovery was performed
*/
static prodres_t
xml_parse_EntityDecl(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;
    xml_reader_entity_t *e = NULL;
    xml_reader_notation_t *n;
    xml_reader_entity_t *eold;
    const xml_predefined_entity_t *predef;
    strhash_t *ehash = h->entities_gen;
    bool parameter = false;
    size_t i, j;
    const char *s;
    ucs4_t *rplc;

    // TBD use lock/unlock and check unlock's retval for proper nesting
    // ['<!ENTITY' S]
    xml_read_string_assert(h, "<!ENTITY");
    cbp.cbtype = XML_READER_CB_ENTITY_DEF_START;
    cbp.loc = h->lastreadloc;

    h->flags |= R_AMBIGUOUS_PERCENT;
    if (xml_parse_whitespace_conditional(h) != PR_OK) {
        h->flags &= ~R_AMBIGUOUS_PERCENT;
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_EntityDecl),
                "Expect whitespace here");
        goto malformed;
    }
    h->flags &= ~R_AMBIGUOUS_PERCENT;

    // If ['%' S] follows, it is a parameter entity
    if (ucs4_cheq(h->rejected, '%')) {
        xml_read_string_assert(h, "%");
        ehash = h->entities_param;
        parameter = true;
        if (xml_parse_whitespace_conditional(h) != PR_OK) {
            xml_reader_message_current(h, XMLERR(ERROR, XML, P_EntityDecl),
                    "Expect whitespace here");
            goto malformed;
        }
    }

    // Parameter entities do not have 'bypassed' behavior in any context, for which
    // we'd need the name
    h->ucs4len = 0;
    if (!parameter) {
        xml_ucs4_store(h, ucs4_fromlocal('&'));
    }

    // General or parameter, it is followed by [Name S]
    if (xml_read_Name(h, parameter ? 0 : R_SAVE_UCS4) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_EntityDecl),
                "Expect entity name here");
        goto malformed;
    }

    if (!parameter) {
        xml_ucs4_store(h, ucs4_fromlocal(';'));
    }

    // If the same entity is declared more than once, the first declaration encountered
    // is binding; at user option, an XML processor MAY issue a warning if entities are
    // declared multiple times.
    // ...
    //  For interoperability, valid XML documents SHOULD declare these [predefined]
    // entities, like any others, before using them.
    if ((eold = strhash_get(ehash, h->tokenbuf, h->tokenlen)) != NULL) {
        // We have a previous definition. If it is predefined, we'll verify validity
        // of the replacement text later; predefined entities may be re-declared once
        // by the document without warning. 
        if ((predef = eold->predef) == NULL || eold->declared.src) {
            xml_reader_message(h, &cbp.loc, XMLERR(WARN, XML, ENTITY_REDECLARED),
                    "Redefinition of an entity");
            xml_reader_message(h, &eold->declared, XMLERR_NOTE,
                    "This is the location of a previous definition");
        }
        e = NULL; // Will not create a new definition
    }
    else {
        predef = NULL;
        e = xml_entity_new(ehash, h->tokenbuf, h->tokenlen);
    }
    cbp.token.str = h->tokenbuf;
    cbp.token.len = h->tokenlen;
    cbp.entitydef.parameter = parameter;
    xml_reader_invoke_callback(h, &cbp);

    if (e) {
        // TBD ucs4buf only saved for general entities - does this copy a stale replacement?
        e->parameter = parameter;
        e->refrplclen = h->ucs4len * sizeof(ucs4_t);
        rplc = xmalloc(e->refrplclen);
        memcpy(rplc, h->ucs4buf, e->refrplclen);
        e->refrplc = rplc;
    }

    if (xml_parse_whitespace_conditional(h) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_EntityDecl),
                "Expect whitespace here");
        goto malformed;
    }

    // This may be followed by either [ExternalID], [ExternalID NDataDecl]
    // (only for general entities) or [EntityValue]
    switch (xml_parse_ExternalID(h, false, e ? &e->loader_info : NULL)) {
    case PR_FAIL:
        goto malformed;

    case PR_OK:
        // Predefined entities cannot be declared as external entities:
        // "If the entities [...] are declared, they MUST be declared as internal entities..."
        if (eold && eold->predef) {
            xml_reader_message_current(h, XMLERR(ERROR, XML, PREDEFINED_ENTITY),
                    "Predefined entity may only be declared as internal entity");
            goto malformed;
        }
        if (!parameter) {
            // Optional NDatadecl in general entities
            if (xml_parse_whitespace_conditional(h) == PR_OK && ucs4_cheq(h->rejected, 'N')) {
                if (xml_read_string(h, "NDATA", XMLERR(ERROR, XML, P_EntityDecl)) != PR_OK) {
                    goto malformed;
                }
                if (xml_parse_whitespace_conditional(h) != PR_OK) {
                    xml_reader_message_current(h, XMLERR(ERROR, XML, P_EntityDecl),
                            "Expect whitespace here");
                    goto malformed;
                }
                if (xml_read_Name(h, 0) != PR_OK) {
                    xml_reader_message_current(h, XMLERR(ERROR, XML, P_EntityDecl),
                            "Expect notation name here");
                    goto malformed;
                }
                if ((n = strhash_get(h->notations, h->tokenbuf,  h->tokenlen)) == NULL) {
                    xml_reader_message_lastread(h, XMLERR(ERROR, XML, VC_NOTATION_DECLARED),
                            "Notation must be declared");
                    goto malformed;
                }
                if (e) {
                    e->notation = n;
                    e->type = XML_READER_REF_UNPARSED;
                }
                cbp.cbtype = XML_READER_CB_NDATA;
                cbp.loc = h->lastreadloc;
                cbp.token.str = h->tokenbuf;
                cbp.token.len = h->tokenlen;
                cbp.ndata.system_id = n->loader_info.system_id;
                cbp.ndata.public_id = n->loader_info.public_id;
                xml_reader_invoke_callback(h, &cbp);
            }
            else {
                if (e) {
                    e->type = XML_READER_REF_EXTERNAL;
                }
            }
        }
        else {
            // Parameter entity cannot have notation declaration
            if (e) {
                e->type = XML_READER_REF_PARAMETER;
            }
        }
        break;

    case PR_NOMATCH:
        // Must have EntityValue then
        h->ucs4len = 0;
        if (xml_parse_literal(h, h->ctx->entity_value_parser) != PR_OK) {
            goto malformed;
        }
        if (predef) {
            // Predefined entity: the definition must be compatible
            /// @todo Some function to compare UCS-4 string to local string? Or use UCS-4 in array
            /// of predefined entities?
            for (i = 0;
                    i < sizeofarray(predef->rplc) && (s = predef->rplc[i]) != NULL;
                    i++) {
                for (j = 0; j < h->ucs4len; j++) {
                    // s is nul-terminated, so end of string is caught here
                    if (ucs4_fromlocal(s[j]) != h->ucs4buf[j]) {
                        break;
                    }
                }
                // matched so far, check that it's the end of expected replacement text
                if (j == h->ucs4len && !s[j]) {
                    goto compatible;
                }
                // otherwise, check the next definition if there's any
            }
            // Did not find a compatible definition
            xml_reader_message_lastread(h, XMLERR(ERROR, XML, PREDEFINED_ENTITY),
                    "Incompatible redefinition of a predefined entity");
            goto malformed;

compatible:
            // Save location, so that redefinitions of this entity trigger a warning
            eold->declared = cbp.loc;
        }
        if (e) {
            e->rplclen = h->ucs4len * sizeof(ucs4_t);
            rplc = xmalloc(e->rplclen);
            memcpy(rplc, h->ucs4buf, e->rplclen);
            e->rplc = rplc;
            e->type = parameter ? XML_READER_REF_PARAMETER : XML_READER_REF_INTERNAL;
        }
        break;

    default:
        OOPS_UNREACHABLE;
        break;
    }

    // Optional whitespace and closing angle bracket
    (void)xml_parse_whitespace_conditional(h);
    if (xml_read_string(h, ">", XMLERR(ERROR, XML, P_EntityDecl)) != PR_OK) {
        goto malformed;
    }
    cbp.cbtype = XML_READER_CB_ENTITY_DEF_END;
    cbp.loc = h->lastreadloc;
    cbp.token.str = NULL;
    cbp.token.len = 0;
    xml_reader_invoke_callback(h, &cbp);
    return PR_OK;

malformed:
    if (e) {
        // Remove the entity from the hash
        strhash_set(ehash, e->name, e->namelen, NULL);
    }
    return xml_read_until_gt(h);
}

/**
    Parse notation declaration (NotationDecl).

    @verbatim
    NotationDecl ::= '<!NOTATION' S Name S (ExternalID | PublicID) S? '>'
    ExternalID   ::= 'SYSTEM' S SystemLiteral | 'PUBLIC' S PubidLiteral S SystemLiteral
    PublicID     ::= 'PUBLIC' S PubidLiteral
    @endverbatim

    @param h Reader handle
    @return PR_OK if the declaration parsed successfully, or recovery was performed
*/
static prodres_t
xml_parse_NotationDecl(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;
    xml_reader_notation_t *n = NULL;

    // TBD use lock/unlock and check unlock's retval for proper nesting
    xml_read_string_assert(h, "<!NOTATION");
    cbp.cbtype = XML_READER_CB_NOTATION_DEF_START;
    cbp.loc = h->lastreadloc;

    if (xml_parse_whitespace_conditional(h) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_NotationDecl),
                "Expect whitespace here");
        goto malformed;
    }
    if (xml_read_Name(h, 0) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_EntityDecl),
                "Expect notation name here");
        goto malformed;
    }
    if (strhash_get(h->notations, h->tokenbuf, h->tokenlen) != NULL) {
        xml_reader_message_lastread(h, XMLERR(ERROR, XML, VC_UNIQUE_NOTATION_NAME),
                "Given Name must not be declared in more than one notation declaration");
        goto malformed;
    }
    n = xml_notation_new(h->notations, h->tokenbuf, h->tokenlen);
    cbp.token.str = h->tokenbuf;
    cbp.token.len = h->tokenlen;
    xml_reader_invoke_callback(h, &cbp);

    if (xml_parse_whitespace_conditional(h) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_EntityDecl),
                "Expect whitespace here");
        goto malformed;
    }

    switch (xml_parse_ExternalID(h, true, &n->loader_info)) {
    case PR_FAIL:
        // Error already provided
        goto malformed;

    case PR_NOMATCH:
        // For notations, system and/or public IDs are mandatory
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_NotationDecl),
                "Expect ExternalID or PublicID here");
        goto malformed;

    case PR_OK:
        break;

    default:
        OOPS_UNREACHABLE;
    }

    // Optional whitespace and closing angle bracket
    (void)xml_parse_whitespace_conditional(h);
    if (xml_read_string(h, ">", XMLERR(ERROR, XML, P_NotationDecl)) != PR_OK) {
        goto malformed;
    }
    cbp.cbtype = XML_READER_CB_NOTATION_DEF_END;
    cbp.loc = h->lastreadloc;
    cbp.token.str = NULL;
    cbp.token.len = 0;
    xml_reader_invoke_callback(h, &cbp);
    return PR_OK;

malformed:
    if (n) {
        // Remove the notation from the hash
        strhash_set(h->notations, n->name, n->namelen, NULL);
    }
    return xml_read_until_gt(h);
}

/**
    Parse a conditional section in DTD.

    @param h Reader handle
    @return PR_OK if parsed successfully
*/
static prodres_t
xml_parse_conditionalSect(xml_reader_t *h)
{
    return PR_OK; // TBD
}

/**
    Parse declaration separator (DeclSep) which is whitespace or PE reference.
    If unsuccessful, recover by 

    @verbatim
    DeclSep ::= PEReference | S
    @endverbatim

    Essentially, this function just parses whitespace while allowing for parameter entity
    expansion.

    @param h Reader handle
    @return PR_OK if the declaration parsed successfully, or recovery was performed
*/
static prodres_t
xml_parse_whitespace_peref_or_recover(xml_reader_t *h)
{
    prodres_t rv;

    if ((rv = xml_parse_whitespace_peref(h)) != PR_NOMATCH) {
        return rv;
    }

    xml_reader_message_current(h, XMLERR(ERROR, XML, P_DeclSep),
            "Invalid content in DTD");

    // Recover by skipping to the next angle bracket. If we are already at the
    // angle bracket, then skip to the next one (we didn't recognize the production
    // starting with that angle bracket)
    if (ucs4_cheq(h->rejected, '<')) {
        xml_read_until_gt(h);
    }
    return xml_read_until_lt(h);
}

/**
    Common parser for DTD final part: we may handle DTD parsing in two separate
    locations, depending on whether the internal subset was present.

    @param h Reader handle
    @return PR_OK if parsed successfully
*/
static prodres_t
xml_parse_dtd_end(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;

    (void)xml_parse_whitespace(h); // Only appears in internal subset
    if (xml_read_string(h, ">", XMLERR(ERROR, XML, P_doctypedecl)) != PR_OK) {
        // The only case we're attempting recovery in doctypedecl. Restore
        // context for future entities.
        return xml_read_until_gt(h);
    }

    // We know there's input in the queue, we've just read from it
    h->lastreadloc = SLIST_FIRST(&h->active_input)->curloc;

    cbp.cbtype = XML_READER_CB_DTD_END;
    cbp.loc = h->lastreadloc;
    cbp.token.str = NULL,
    cbp.token.len = 0;

    if (xml_loader_info_isset(&h->dtd_loader_info)) {
        (void)xml_reader_invoke_loader(h, &h->dtd_loader_info,
                NULL, &parser_external_subset, false);
    }

    // Signal the end of DTD parsing
    xml_reader_invoke_callback(h, &cbp);
    return PR_OK;
}

/**
    Trivial parser: exit from internal subset context when closing bracket is seen.
    Note that it

    @param h Reader handle
    @return Always PR_STOP (this function is only called if lookahead confirmed next
        character to be closing bracket)
*/
static prodres_t
xml_end_internal_subset(xml_reader_t *h)
{
    xml_read_string_assert(h, "]");
    h->ctx = &parser_document_entity;
    return xml_parse_dtd_end(h);
}

/**
    Context for parsing internal subset in a document type definition (DTD).

    @verbatim
    intSubset    ::= (markupdecl | DeclSep)*
    markupdecl   ::= elementdecl | AttlistDecl | EntityDecl | NotationDecl | PI | Comment
    DeclSep      ::= PEReference | S
    elementdecl  ::= '<!ELEMENT' S Name S contentspec S? '>'
    AttlistDecl  ::= '<!ATTLIST' S Name AttDef* S? '>'
    EntityDecl   ::= GEDecl | PEDecl
    GEDecl       ::= '<!ENTITY' S Name S EntityDef S? '>'
    PEDecl       ::= '<!ENTITY' S '%' S Name S PEDef S? '>'
    NotationDecl ::= '<!NOTATION' S Name S (ExternalID | PublicID) S? '>'
    PI           ::= '<?' PITarget (S (Char* - (Char* '?>' Char*)))? '?>' 
    Comment      ::= '<!--' ((Char - '-') | ('-' (Char - '-')))* '-->'
    @endverbatim

    Additionally, in internal subset PEReference may only occur in DeclSep. So, we parse
    DeclSep as whitespace with PE reference substitution enabled.
*/
static const xml_reader_context_t parser_internal_subset = {
    .lookahead = {
        LOOKAHEAD("<!ELEMENT", xml_parse_elementdecl),
        LOOKAHEAD("<!ATTLIST", xml_parse_AttlistDecl),
        LOOKAHEAD("<!ENTITY", xml_parse_EntityDecl),
        LOOKAHEAD("<!NOTATION", xml_parse_NotationDecl),
        LOOKAHEAD("<?", xml_parse_PI),
        LOOKAHEAD("<!--", xml_parse_Comment),
        LOOKAHEAD("]", xml_end_internal_subset),
        LOOKAHEAD("", xml_parse_whitespace_peref_or_recover),
    },
    .declinfo = NULL,                   // Not used for reading any external entity
    .reftype = XML_READER_REF__NONE,    // Not an external entity
    .entity_value_parser = &reference_ops_EntityValue_internal,
    .errcode = XMLERR(ERROR, XML, P_intSubset),
    .production = "intSubset",
    .document_entity = false,
};

/**
    Context for parsing external subset in a document type definition (DTD), including
    one loaded via parameter entity.

    @verbatim
    extSubset       ::= TextDecl? extSubsetDecl
    extSubsetDecl   ::= (markupdecl | conditionalSect | DeclSep)*
    conditionalSect ::= includeSect | ignoreSect
    includeSect     ::= '<![' S? 'INCLUDE' S? '[' extSubsetDecl ']]>'
    ignoreSect      ::= '<![' S? 'IGNORE' S? '[' ignoreSectContents* ']]>'
    markupdecl      ::= elementdecl | AttlistDecl | EntityDecl | NotationDecl | PI | Comment
    DeclSep         ::= PEReference | S
    elementdecl     ::= '<!ELEMENT' S Name S contentspec S? '>'
    AttlistDecl     ::= '<!ATTLIST' S Name AttDef* S? '>'
    EntityDecl      ::= GEDecl | PEDecl
    GEDecl          ::= '<!ENTITY' S Name S EntityDef S? '>'
    PEDecl          ::= '<!ENTITY' S '%' S Name S PEDef S? '>'
    NotationDecl    ::= '<!NOTATION' S Name S (ExternalID | PublicID) S? '>'
    PI              ::= '<?' PITarget (S (Char* - (Char* '?>' Char*)))? '?>' 
    Comment         ::= '<!--' ((Char - '-') | ('-' (Char - '-')))* '-->'
    @endverbatim

    Additionally, in internal subset PEReference may only occur in DeclSep. So, we parse
    DeclSep as whitespace with PE reference substitution enabled.
*/
static const xml_reader_context_t parser_external_subset = {
    .lookahead = {
        LOOKAHEAD("<!ELEMENT", xml_parse_elementdecl),
        LOOKAHEAD("<!ATTLIST", xml_parse_AttlistDecl),
        LOOKAHEAD("<!ENTITY", xml_parse_EntityDecl),
        LOOKAHEAD("<!NOTATION", xml_parse_NotationDecl),
        LOOKAHEAD("<![", xml_parse_conditionalSect),
        LOOKAHEAD("<?", xml_parse_PI),
        LOOKAHEAD("<!--", xml_parse_Comment),
        LOOKAHEAD("", xml_parse_whitespace_peref_or_recover),
    },
    .declinfo = &declinfo_textdecl,
    .reftype = XML_READER_REF_EXT_SUBSET, // If not parameter entity, this is external DTD
    .entity_value_parser = &reference_ops_EntityValue_external,
    .errcode = XMLERR(ERROR, XML, P_extSubset),
    .production = "extSubset",
    .document_entity = false,
};

/**
    Read and process a document type declaration; the declaration may reference
    an external subset and contain an internal subset, or have both, or none.

    @verbatim
    doctypedecl ::= '<!DOCTYPE' S Name (S ExternalID)? S? ('[' intSubset ']' S?)? '>'
    ExternalID  ::= 'SYSTEM' S SystemLiteral | 'PUBLIC' S PubidLiteral S SystemLiteral
    @endverbatim

    @par No recovery
    We can try to recover by reading to the next right angle bracket, but if DTD
    contains an internal subset, we're likely to terminate on some entity or other
    markup declaration. Thus, this function signals an abort to the caller if it
    detects a misformatting in most cases; the only exception is when the malformedness
    is detected after the closing bracket following the internal subset; in that case,
    the next right angle bracket must be the one closing the DTD.

    @param h Reader handle
    @return PR_OK if parsed successfully.
*/
static prodres_t
xml_parse_doctypedecl(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;
    prodres_t rv;

    // Expanding doctypedecl production, we get these possible variants:
    //   '<!DOCTYPE' S Name S? '>'
    //   '<!DOCTYPE' S Name 'SYSTEM' S SystemLiteral S? '>'
    //   '<!DOCTYPE' S Name 'PUBLIC' S PubidLiteral S SystemLiteral S? '>'
    //   '<!DOCTYPE' S Name S? '[' intSubset ']' S? '>'
    //   '<!DOCTYPE' S Name 'SYSTEM' S SystemLiteral S? '[' intSubset ']' S? '>'
    //   '<!DOCTYPE' S Name 'PUBLIC' S PubidLiteral S SystemLiteral S? '[' intSubset ']' S? '>'

    // Common part: '<!DOCTYPE' S Name
    xml_read_string_assert(h, "<!DOCTYPE");
    cbp.cbtype = XML_READER_CB_DTD_BEGIN;
    cbp.loc = h->lastreadloc;

    // DTD allowed only once and only before the root element
    if (h->flags & (R_HAS_DTD|R_HAS_ROOT)) {
        xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_document),
                "Document type definition not allowed here");
    }
    h->flags |= R_HAS_DTD;

    if (xml_parse_whitespace(h) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_doctypedecl),
                "Expect whitespace here");
        return PR_FAIL;
    }
    if (xml_read_Name(h, 0) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_doctypedecl),
                "Expect root element type here");
        return PR_FAIL;
    }
    cbp.token.str = h->tokenbuf;
    cbp.token.len = h->tokenlen;
    xml_reader_invoke_callback(h, &cbp);

    if (xml_parse_whitespace(h) == PR_OK) {
        rv = xml_parse_ExternalID(h, false, &h->dtd_loader_info);
        if (rv != PR_OK && rv != PR_NOMATCH) {
            return rv; // See above: no recovery
        }
    }

    // Ignore optional whitespace before internal subset
    (void)xml_parse_whitespace(h);
    if (ucs4_cheq(h->rejected, '[')) {
        // Internal subset: '[' intSubset ']'
        xml_read_string_assert(h, "[");
        cbp.cbtype = XML_READER_CB_DTD_INTERNAL;
        cbp.token.str = NULL,
        cbp.token.len = 0;
        xml_reader_invoke_callback(h, &cbp);

        // Will continue parsing the declaration with internal subset context
        // Any external entities therein are interpreted as external parameter
        // entities.
        h->ctx = &parser_internal_subset;
        return PR_OK;
    }

    // Ignore optional whitespace before closing angle bracket
    return xml_parse_dtd_end(h);
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

    xml_read_string_assert(h, "<");
    xml_reader_input_lock(h);
    cbp.cbtype = XML_READER_CB_STAG;
    cbp.loc = h->lastreadloc;

    // Check the document production: at the top level, only one element is allowed
    if (!h->nestlvl) {
        if (h->flags & R_HAS_ROOT) {
            xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_document),
                    "One root element allowed in a document");
        }
        else {
            h->flags |= R_HAS_ROOT;
        }
    }

    if (xml_read_Name(h, 0) != PR_OK) {
        // No valid name - try to recover by skipping until closing bracket
        xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_STag),
                "Expected element type");
        goto malformed;
    }

    // Notify the application that a new element has started
    cbp.token.str = h->tokenbuf;
    cbp.token.len = h->tokenlen;
    xml_reader_invoke_callback(h, &cbp);

    while (true) {
        had_ws = xml_parse_whitespace(h) == PR_OK;
        if (ucs4_cheq(h->rejected, '/')) {
            if (xml_read_string(h, "/>", XMLERR(ERROR, XML, P_STag)) != PR_OK) {
                goto malformed;
            }
            is_empty = true;
            xml_reader_input_unlock_assert(h);
            break;
        }
        else if (ucs4_cheq(h->rejected, '>')) {
            xml_read_string_assert(h, ">");
            is_empty = false;
            h->nestlvl++; // Opened element
            h->ctx = &parser_content; // No longer at top level
            break;
        }
        else if (had_ws && xml_read_Name(h, 0) == PR_OK) {
            // Attribute, if any, must be preceded by S (whitespace).
            cbp.cbtype = XML_READER_CB_ATTR;
            cbp.loc = h->lastreadloc;
            cbp.token.str = h->tokenbuf;
            cbp.token.len = h->tokenlen;
            cbp.attr.attrnorm = XML_READER_ATTRNORM_CDATA;
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
    cbp.token.str = NULL;
    cbp.token.len = 0;
    cbp.loc = h->lastreadloc;
    cbp.stag_end.is_empty = is_empty;
    xml_reader_invoke_callback(h, &cbp);
    // Do not unlock until a matching ETag
    return PR_OK;

malformed:
    // Try to recover by reading till end of opening tag. Do not lock the input
    // (as we don't know how broken the markup was).
    xml_read_until_gt(h);
    xml_reader_input_unlock_assert(h);
    return PR_OK;
}

/**
    Read and process ETag production.

    @verbatim
    ETag ::= '</' Name S? '>'
    @endverbatim

    Additionally, Name in ETag must match the element type in STag.

    @param h Reader handle
    @return PR_OK if parsed successfully
*/
static prodres_t
xml_parse_ETag(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;

    xml_read_string_assert(h, "</");
    // Locked by STag
    cbp.cbtype = XML_READER_CB_ETAG;
    cbp.loc = h->lastreadloc;
    if (xml_read_Name(h, 0) != PR_OK) {
        // No valid name - try to recover by skipping until closing bracket
        xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_ETag),
                "Expected element type");
        xml_reader_input_unlock_assert(h);
        return xml_read_until_gt(h);
    }

    cbp.token.str = h->tokenbuf;
    cbp.token.len = h->tokenlen;
    xml_reader_invoke_callback(h, &cbp);

    (void)xml_parse_whitespace(h); // optional whitespace
    if (xml_read_string(h, ">", XMLERR(ERROR, XML, P_ETag)) != PR_OK) {
        // Not terminated properly  - try to recover by skipping until closing bracket
        xml_reader_input_unlock_assert(h);
        return xml_read_until_gt(h);
    }

    // Do not decrement nest level if already at the root level. This document
    // is already malformed, so an error message should already be raised.
    if (h->nestlvl && --h->nestlvl == 0) {
        // Returned to top level
        h->ctx = &parser_document_entity;
    }
    if (!xml_reader_input_unlock(h)) {
        // Error, no recovery needed
        xml_reader_message(h, &cbp.loc, XMLERR(ERROR, XML, P_content),
                "Replacement text for entity must match content production");
    }
    return PR_OK;
}

/**
    Wrapper function: consume whitespace or recover by skipping up to the next
    angle bracket.

    @param h Reader handle
    @return PR_OK if parsed successfully
*/
static prodres_t
xml_parse_whitespace_or_recover(xml_reader_t *h)
{
    prodres_t rv;

    // Top level
    if ((rv = xml_parse_whitespace(h)) != PR_NOMATCH) {
        return rv;
    }

    // Recover by skipping to the next angle bracket
    xml_reader_message_current(h, XMLERR(ERROR, XML, P_document),
            "Invalid content at root level");
    return xml_read_until_lt(h);
}

/**
    Expected tokens/handlers for parsing content production.

    Note that content is a recursive production: it may contain element, which in turn
    may contain content. We are processing this in a flat way (substituting loop for
    recursion); instead, we just track the nesting level (to keep track if we're at
    the root level or not). The proper nesting of STag/ETag cannot be checked with
    this approach; it needs to be verified by a higher level, SAX or DOM. Higher level
    is also responsible for checking that both STag/ETag belong to the same input by
    keeping track when entity parsing started and ended.

    TBD nesting-check.diff - in that case, it proper nesting will be verified here

    The content production is defined in XML 1.1 as one of the relevant constructs,
    meaning that it cannot start with a composing character. We do not check that
    explicitly though: this parse context checks that the content starts either with
    a less-than (which is not composing), or with CharData (which is also a relevant
    construct and performs the same check for the first character).

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
        LOOKAHEAD("", xml_parse_CharData),
    },
    .declinfo = &declinfo_textdecl,
    .reftype = XML_READER_REF__NONE, // Can only be loaded via entity
    .entity_value_parser = NULL, // DTD not recognized
    .errcode = XMLERR(ERROR, XML, P_content),
    .production = "content",
    .document_entity = false,
};

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
        LOOKAHEAD("", xml_parse_whitespace_or_recover),
    },
    .declinfo = &declinfo_xmldecl,
    .reftype = XML_READER_REF_DOCUMENT, // Document entity
    .entity_value_parser = &reference_ops_EntityValue_internal,
    .errcode = XMLERR(ERROR, XML, P_document),
    .production = "document",
    .document_entity = true,
};

/**
    Notification of an end of an external entity.

    @param h Reader handle
    @param arg External entity information
    @return Nothing
*/
static void
external_entity_end(xml_reader_t *h, void *arg)
{
    xml_reader_input_t *inp = arg;
    xml_reader_external_t *ex = inp->external;

    // Only if input was parsed fully (i.e. not aborted during addition)
    if (!ex->aborted && !encoding_clean(ex->enc)) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                "Partial characters at end of input");
    }
    // Restore context if needed
    if (ex->saved_ctx) {
        h->ctx = ex->saved_ctx;
    }

    // Clear the ops - this closes the old buffer's underlying resources
    // but retains the buffer structure
    strbuf_setops(ex->buf, NULL, NULL);

    // Call general entity handler if this was an included entity
    if (inp->entity) {
        entity_end(h, inp->entity);
    }
}

/**
    Add an external parsed entity in the current context: if not reading anything,
    add a 'main document' entity. If expanding an external parameter entity reference,
    add a DTD entity. If expanding an external general entity, add an external
    entity.

    This is primarily an internal interface to be invoked by the loader.

    @param h Reader handle
    @param buf Buffer to read
    @param location Location string to be used in messages
    @param transport_encoding Encoding from the transport layer
    @return Nothing
*/
void
xml_reader_add_parsed_entity(xml_reader_t *h, strbuf_t *buf,
        const char *location, const char *transport_encoding)
{
    xml_reader_hidden_loader_arg_t *ha = h->hidden_loader_arg;
    xml_reader_entity_t *e = ha->entityref;
    xml_reader_external_t *ex;
    xml_reader_input_t *inp;
    xml_reader_initial_xcode_t xc;
    utf8_t adbuf[4];       // 4 bytes for encoding detection, per XML spec suggestion
    size_t bom_len, adsz;
    const char *encname;
    bool rv;

    ex = xmalloc(sizeof(xml_reader_external_t));
    memset(ex, 0, sizeof(xml_reader_external_t));
    ex->h = h;
    ex->buf = buf;
    ex->location = xstrdup(location);
    ex->norm_unicode = NULL;
    ex->aborted = false;

    if (ha->ctx) {
        // Switch context for this external
        ex->saved_ctx = h->ctx;
        h->ctx = ha->ctx;
    }

    STAILQ_INSERT_TAIL(&h->external, ex, link);
    h->current_external = ex;

    inp = xml_reader_input_new(h, ex->location);
    inp->entity = e;
    inp->external = ex;
    inp->complete = external_entity_end;
    inp->complete_arg = inp;
    inp->inc_in_literal = ha->inc_in_literal;

    if (transport_encoding) {
        if (!xml_reader_set_encoding(ex, transport_encoding)) {
            goto failed;
        }
        ex->enc_transport = xstrdup(transport_encoding);
    }

    // Try to get the encoding from stream and check for BOM
    memset(adbuf, 0, sizeof(adbuf));
    adsz = strbuf_lookahead(buf, adbuf, sizeof(adbuf));
    if ((encname = encoding_detect(adbuf, adsz, &bom_len)) != NULL) {
        if (!xml_reader_set_encoding(ex, encname)) {
            xml_reader_message_current(h, XMLERR_NOTE, "(autodetected from %s)",
                    bom_len ? "Byte-order Mark" : "content");
            goto failed;
        }
        ex->enc_detected = xstrdup(encname);
    }

    // If byte order mark (BOM) was detected, consume it
    if (bom_len) {
        strbuf_radvance(buf, bom_len);
    }

    // If no encoding passed from the transport layer, and autodetect didn't help,
    // try UTF-8. UTF-8 is built-in, so it should always work.
    if (!ex->enc) {
        rv = xml_reader_set_encoding(ex, "UTF-8");
        OOPS_ASSERT(rv);
    }

    // Temporary reader state
    xc.ex = ex;
    xc.la_start = xc.initial;
    xc.la_size = sizeof(xc.initial);
    xc.la_avail = 0;
    xc.la_offs = 0;

    strbuf_realloc(inp->buf, INITIAL_DECL_LOOKAHEAD_SIZE * sizeof(ucs4_t));
    strbuf_setops(inp->buf, &xml_reader_initial_ops, &xc);

    // Parse the declaration; expect only ASCII
    /// @todo Declaration seems to be forbidden in external subset; do not even try for that
    /// context
    h->flags |= R_ASCII_ONLY;
    switch (xml_parse_XMLDecl_TextDecl(h)) {
    case PR_OK:
        // Consumed declaration from the raw buffer; advance before setting
        // permanent transcoding operations
        strbuf_radvance(buf, xc.la_offs);
        break;
    case PR_NOMATCH:
        // Nothing to do - just a document without declaration
        break;
    case PR_FAIL:
        // Entity failed to parse in the declaration. Parsing the declaration
        // shouldn't have created any new inputs or loaded new external entities.
        // Keep the entity on the list of inputs which have been parsed.
        goto failed;
    default:
        OOPS_UNREACHABLE;
        break;
    }
    h->flags &= ~R_ASCII_ONLY;

    // Done with the temporary buffer: free the memory buffer if it was reallocated
    if (xc.la_start != xc.initial) {
        xfree(xc.la_start);
    }
    strbuf_clear(inp->buf);

    // If there was no XML declaration, assume 1.0 (where XMLDecl is optional)
    /// @todo For external parsed entities, need to inherit version from including document
    if (ex->version == XML_INFO_VERSION_NO_VALUE) {
        ex->version = XML_INFO_VERSION_1_0;
    }

    // Default normalization behavior depends on version: off in 1.0, on in 1.1. Note that
    // we've read the XML declaration already in the latter case - but, since only ASCII
    // is permitted in the declaration, it cannot be denormalized. Note that the document
    // entity's declaration affects all the entities subsequently loaded: per XML 1.1
    // specification, "However, in such a case [...loading 1.0 entities from 1.1 document...]
    // the rules of XML 1.1 are applied to the entire document."
    if (h->normalization == XML_READER_NORM_DEFAULT && h->ctx->document_entity) {
        h->normalization = (ex->version == XML_INFO_VERSION_1_0) ?
                XML_READER_NORM_OFF : XML_READER_NORM_ON;
    }

    /// @todo If the input is not in the Unicode encoding form (UTF-8, UTF-16 or UTF-32)
    /// then it is not Unicode normalized. For full normalization, the rule is somewhat
    /// relaxed then: "... if transcoded to a Unicode encoding form by a <i>normalizing</i>
    /// transcoder...". At this time, transcoders implemented in this library do not perform
    /// any normalization, so if the repertoir of the encoding includes, say, composing
    /// characters, they will be presented verbatim in Unicode, even if this produces a
    /// denormalized input. So, for non-Unicode encoding forms the normalization check is
    /// stricter than prescribed by the standard.
    if (h->normalization == XML_READER_NORM_ON) {
        // Normalization requested. Allocate this external entity's handle (for Unicode
        // normalization check) and, for document entity, global handle (for include
        // normalization check.
        ex->norm_unicode = nfc_create();
        if (h->ctx->document_entity) {
            h->norm_include = nfc_create();
        }
    }

    if (ex->enc_declared) {
        // Encoding should be in clean state - if not, need to fix encoding to not consume
        // excess data. If this fails, the error is already reported - try to recover by
        // keeping the old encoding.
        if (!xml_reader_set_encoding(ex, ex->enc_declared)) {
            xml_reader_message_lastread(h, XMLERR_NOTE, "(encoding from XML declaration)");
        }
    }

    // Set up permanent transcoder
    strbuf_setops(inp->buf, &xml_reader_transcode_ops, ex);

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
    if (!bom_len && ex->enc_declared
            && !strcmp(ex->enc_declared, "UTF-16")) {
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
    if (!ex->enc_declared && !ex->enc_transport
            && strcmp(encoding_name(ex->enc), "UTF-16")
            && strcmp(encoding_name(ex->enc), "UTF-8")) {
        // Non-fatal: recover by using whatever encoding we detected
        xml_reader_message_lastread(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                "No external encoding information, no encoding in %s, content in %s encoding",
                h->ctx->declinfo->name, encoding_name(ex->enc));
    }

    h->hidden_loader_arg = NULL; // Loaded successfully
    return;

failed:
    // Keep the external in the list of entities we attempted to read, so that
    // the locations for events remain valid. Have current location point to
    // the very end of this input (e.g. if we failed mid-way into an assumed string
    // h->lastreadloc will point to the beginning of the string)
    ex->aborted = true;
    h->lastreadloc = inp->curloc;
    xml_reader_input_complete(h, inp);
}

/**
    Higher-level interface for loading document entity.

    @param h Reader handle
    @param pubid Entity's public ID
    @param sysid Entity's system ID
    @return Nothing
*/
void
xml_reader_load_document_entity(xml_reader_t *h, const char *pubid, const char *sysid)
{
    xml_loader_info_t info;

    xml_loader_info_init(&info, pubid, sysid);
    if (xml_reader_invoke_loader(h, &info, NULL, &parser_document_entity, false)) {
        h->flags |= R_DOCUMENT_LOADED;
    }
    xml_loader_info_destroy(&info);
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
    xml_reader_input_t *inp;
    va_list ap;

    cbparam.cbtype = XML_READER_CB_MESSAGE;
    cbparam.token.str = NULL;
    cbparam.token.len = 0;
    if (loc) {
        cbparam.loc = *loc;
    }
    else if ((inp = SLIST_FIRST(&h->active_input)) != NULL) {
        cbparam.loc = inp->curloc;
    }
    else {
        cbparam.loc = h->lastreadloc;
    }
    cbparam.message.info = info;
    va_start(ap, fmt);
    cbparam.message.msg = xvasprintf(fmt, ap);
    va_end(ap);
    xml_reader_invoke_callback(h, &cbparam);
    xfree(cbparam.message.msg);
}

/**
    Process entities in input queue.

    @param h Reader handle
    @return Nothing
*/
void
xml_reader_process(xml_reader_t *h)
{
    // Any entities within are external parsed entities by default
    utf8_t labuf[MAX_PATTERN];
    const xml_reader_pattern_t *pat, *end;
    size_t len;
    prodres_t rv;

    /// @todo Have 2nd argument saved in external info? Or have a separate func for pre-reading
    /// a standalone DTD?
    /// @todo Return the parsing success/failure?
    h->ctx = &parser_document_entity;

    /// @todo Have lookahead read into tokenbuf? Do we need to use xml_lookahead() elsewhere?
    do {
        // xml_lookahead also removes completed inputs
        len = xml_lookahead(h, labuf, sizeof(labuf));
        if (xml_eof(h)) {
            rv = PR_STOP;
        }
        else {
            rv = PR_NOMATCH;
            for (pat = h->ctx->lookahead, end = pat + MAX_LA_PAIRS;
                    pat < end && pat->func;
                    pat++) {
                if (pat->patlen <= len && !memcmp(labuf, pat->pattern, pat->patlen)) {
                    rv = pat->func(h);
                    break;
                }
            }
        }
    } while (rv == PR_OK);

    OOPS_ASSERT(rv == PR_STOP);

    // If document entity was aborted/not loaded, no need to spam: already complained
    if ((h->flags & (R_DOCUMENT_LOADED | R_HAS_ROOT)) == R_DOCUMENT_LOADED) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_document),
                "No root element");
    }
}

/**
    Invoke a callback for each input currently nested. This allows to generate a
    "stacktrace" of the current position of the reader.

    @param h Reader handle
    @param func Function to call for each "frame"
    @param arg Arbitrary argument to the callback function
    @return Nothing
*/
void
xml_reader_stack(xml_reader_t *h, void (*func)(void *, const xmlerr_loc_t *), void *arg)
{
    xml_reader_input_t *inp;

    SLIST_FOREACH(inp, &h->active_input, link) {
        func(arg, &inp->curloc);
    }
}
