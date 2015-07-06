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
#define INITIAL_DECL_LOOKAHEAD_SIZE 64U

/// Maximum number of characters to look ahead
#define MAX_LOOKAHEAD_SIZE          16U

/// Reader status flags
enum {
    R_RECOGNIZE_REF     = 0x0001,   ///< Reading next token will expand Reference production
    R_RECOGNIZE_PEREF   = 0x0002,   ///< Reading next token will expand PEReference production
    R_ASCII_ONLY        = 0x0004,   ///< Only ASCII characters allowed while reading declaration
    R_SAVE_UCS4         = 0x0010,   ///< Also save UCS-4 codepoints
    R_NO_INC_NORM       = 0x0020,   ///< No checking of include normalization
    R_HAS_ROOT          = 0x0040,   ///< Root element seen
    R_HAS_DTD           = 0x0080,   ///< Document declaration seen
    R_AMBIGUOUS_PERCENT = 0x0100,   ///< '%' may either start PE reference or have literal meaning
    R_STARTED           = 0x0200,   ///< Loaded the document entity
};

/// Notation information
/// @todo Export this structure in reader.h? Unlike entities, notations are part of the infoset.
/// Or store a pointer from a callback and pass back that pointer whenever that notation is used?
/// (similar to what I planned for nested stack of elements)
typedef struct xml_reader_notation_s {
    xml_reader_token_t name;                ///< Notation name/length
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
    /// @todo get name/length from the key in the hash using container_of() instead of storing it?
    xml_reader_token_t name;                ///< Entity name/length
    enum xml_reader_reference_e type;       ///< Entity type
    xml_loader_info_t loader_info;          ///< Loader information for this entity
    const char *location;                   ///< How input from this entity will be reported
    xml_reader_notation_t *notation;        ///< Associated notation
    bool being_parsed;                      ///< Recursion detection: this entity is being parsed
    const ucs4_t *rplc;                     ///< Replacement text
    size_t rplclen;                         ///< Length of the replacement text in bytes
    xmlerr_loc_t declared;                  ///< Location of the declaration
    xmlerr_loc_t included;                  ///< Where this entity has been included from
    const xml_predefined_entity_t *predef;  ///< The definition came from a predefined entity
} xml_reader_entity_t;

/// Unknown entities referenced from other entities' literal values. We need to check
/// them if they're later defined - if they are unparsed, it is an error.
typedef struct xml_reader_unknown_entity_s {
    xmlerr_loc_t referenced;                ///< Location of the reference to this entity
} xml_reader_unknown_entity_t;

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

    /// How different types of entities are handled
    xml_refhandler_t hnd[XML_READER_REF__MAXREF];
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
    bool saw_cr;                    ///< Saw U+000D, yet to see U+000A or U+0085.
    encoding_handle_t *enc;         ///< Encoding used to transcode input
    strbuf_t *buf;                  ///< Raw input buffer (in document's encoding)
    nfc_t *norm_unicode;            ///< Normalization check handle for Unicode normalization

    // Saved parser context before this external input was added
    const struct xml_reader_context_s *saved_ctx;

    // Extra processing upon completion
    void (*on_complete)(xml_reader_t *h, const xmlerr_loc_t *loc);
} xml_reader_external_t;

/**
    XML declaration comes in two flavors, XMLDecl and TextDecl, with different
    set of allowed/mandatory/optional attributes. This structure describes an
    attribute in the expected list.
*/
typedef struct xml_reader_xmldecl_attrdesc_s {
    const char *name;       ///< Name of the attribute
    bool mandatory;         ///< True if the attribute is mandatory

    /**
        Value validation function. Upon entry, token buffer contains the value
        of the pseudo-attribute's literal.
    */
    void (*check)(xml_reader_t *h);
} xml_reader_xmldecl_attrdesc_t;

/// Declaration info for XMLDecl/TextDecl
typedef struct xml_reader_xmldecl_declinfo_s {
    const char *name;           ///< Declaration name in XML grammar
    xmlerr_info_t errcode;      ///< Error code associated with this declaration
    const xml_reader_xmldecl_attrdesc_t *attrlist; ///< Allowed/required attributes
} xml_reader_xmldecl_declinfo_t;

/**
    Input method: either strbuf for an external entity, replacement text for an internal
    entity or internal memory buffer (for character references).
*/
typedef struct xml_reader_input_s {
    STAILQ_ENTRY(xml_reader_input_s) link;  ///< Stack of diversions
    strbuf_t *buf;                  ///< String buffer to use
    xmlerr_loc_t curloc;            ///< Current location in this input

    /// Notification when this input is consumed
    void (*complete)(struct xml_reader_s *, void *);
    void *complete_arg;             ///< Argument to completion notification

    // Other fields
    bool inc_in_literal;            ///< 'included in literal' - special handling of quotes
    bool ignore_references;         ///< Ignore reference expansion in this input
    bool charref;                   ///< Input originated from a character reference
    xml_reader_entity_t *entity;    ///< Associated entity if any
    xml_reader_external_t *external;///< External entity information
} xml_reader_input_t;

/// Which productions or other syntactic constructs locked the input
enum xml_reader_locker_e {
    LOCKER_NONE,            ///< Default: invalid value (no locking)
    LOCKER_REFERENCE,       ///< General entity or character reference
    LOCKER_PE_REFERENCE,    ///< Parameter entity reference
    LOCKER_COMMENT,         ///< Comment
    LOCKER_PI,              ///< Processing instruction
    LOCKER_CDATA,           ///< CData section
    LOCKER_ENTITY_DECL,     ///< Entity declaration
    LOCKER_NOTATION_DECL,   ///< Notation declaration
    LOCKER_CONDITIONAL_SECT,///< Conditional section
    LOCKER_DTD,             ///< Document type declaration
    LOCKER_ELEMENT,         ///< Element
    LOCKER_DECLARATION,     ///< XML or text declaration
};

/// Input locking token.
typedef struct xml_reader_lock_token_s {
    SLIST_ENTRY(xml_reader_lock_token_s) link;  ///< Stack of locked productions
    xmlerr_loc_t where;             ///< Where the production locked the input
    xml_reader_input_t *input;      ///< Locked input
    enum xml_reader_locker_e locker;///< Which production locked it
    size_t name_offset;             ///< Associated element name in the buffer (start offset)
    size_t name_len;                ///< Element name length
} xml_reader_lock_token_t;

/// Input head
typedef STAILQ_HEAD(,xml_reader_input_s) xml_reader_input_head_t;

/// Return status for production parser
typedef enum {
    PR_OK,                      ///< Parsed successfully or performed recovery
    PR_STOP,                    ///< Parsed successfully, exit current context parser
    PR_FAIL,                    ///< Parsing failed (fatal)
    PR_NOMATCH,                 ///< Production was not matched
} prodres_t;

/// Production parser function
typedef prodres_t (*prodparser_t)(xml_reader_t *);

/// Maximum number of characters we need to look ahead: '<!NOTATION'
#define MAX_PATTERN     10

/// Flags for the pattern
enum {
    L_NOFLUSHTEXT       = 0x0001,       ///< Do not flush text in token buffer
};

/// Lookahead pattern/handler pairs
typedef struct {
    const utf8_t pattern[MAX_PATTERN];  ///< Lookahead pattern to look for
    size_t patlen;                      ///< Length of the recognized pattern
    prodparser_t func;                  ///< Function to call for this pattern
    uint32_t flags;                     ///< Additional actions for this pattern
} xml_reader_pattern_t;

/// Lookahead initializer
/// @todo Construct a DFA instead of an array? If so, manually or by a constructor?
#define LOOKAHEAD(s, f, fl) \
{ \
    .pattern = U_ARRAY s, \
    .patlen = sizeof(s) - 1, \
    .func = f, \
    .flags = fl, \
}

/// Maximum number of lookahead pairs
#define MAX_LA_PAIRS    9

/**
    Parser settings: entity recognition settings at root level, set of lookahead
    patterns for root level, pointer to a settings for non-root level.
*/
typedef struct xml_reader_context_s {
    /// Lookahead patterns
    const xml_reader_pattern_t lookahead[MAX_LA_PAIRS];

    /// Recovery function for this context
    prodres_t (*on_fail)(xml_reader_t *h);

    /// End of input handler for this context
    prodres_t (*on_end)(xml_reader_t *h);

    /// Whitespace handler
    prodres_t (*whitespace)(xml_reader_t *h);

    /// Expected XMLDecl/TextDecl declaration
    const struct xml_reader_xmldecl_declinfo_s *declinfo;

    /// What is allowed in EntityValue
    const struct xml_reference_ops_s *entity_value_parser;
} xml_reader_context_t;

/// Completion handler for external entity
typedef void (*xml_reader_external_completion_cb_t)(xml_reader_t *h, const xmlerr_loc_t *loc);

/// Hidden argument passed through the loader
typedef struct {
    xml_reader_entity_t *entityref;     ///< Entity information, if loading a defined entity
    const xml_reader_context_t *ctx;    ///< Context associated with loaded entity, if any
    bool inc_in_literal;                ///< Whether this entity is being loaded from a literal

    /// External entity completion
    xml_reader_external_completion_cb_t on_complete;
} xml_reader_hidden_loader_arg_t;

/// Saved token text
typedef struct {
    size_t offset;                  ///< Offset of this token into the token buffer
    size_t len;                     ///< Size of this token
    bool reserved;                  ///< True if this token was reserved in the buffer
} xml_reader_saved_token_t;

/// All saved tokens
typedef struct {
    xml_reader_saved_token_t name;      ///< Object's name
    xml_reader_saved_token_t value;     ///< Object's value
    xml_reader_saved_token_t sysid;     ///< Object's system ID
    xml_reader_saved_token_t pubid;     ///< Object's public ID
    xml_reader_saved_token_t ndata;     ///< Object's notation data
} xml_reader_tokens_t;

/// XML reader structure
struct xml_reader_s {
    xml_reader_cb_t cb_func;        ///< Callback function
    void *cb_arg;                   ///< Argument to callback function

    xml_loader_t loader;            ///< External entity loader
    void *loader_arg;               ///< Argument to loader function

    /// Argument to loader function
    xml_reader_hidden_loader_arg_t *hidden_loader_arg;

    /// Current parser context
    const xml_reader_context_t *ctx;

    /// Declaration type in the entity being added
    const xml_reader_xmldecl_declinfo_t *declinfo;

    /// Currentlly expected attribute in declaration
    const xml_reader_xmldecl_attrdesc_t *declattr;

    /// Options specified at the time of creation
    xml_reader_options_t opt;

    uint32_t flags;                 ///< Reader flags
    const char *relevant;           ///< If not NULL, reading a relevant contruct

    enum xml_info_standalone_e standalone;          ///< Document's standalone status

    xml_reader_external_t *current_external;        ///< External entity being parsed

    nfc_t *norm_include;            ///< Normalization check handle for include normalization

    bool stopping;                  ///< Pending request to stop processing
    bool cdata_ws;                  ///< Seen only whitespace in CharData/CDATA
    bool attr_ws;                   ///< Attribute parser: seen w/s at the end of preceding token
    uint32_t condsects_all;         ///< Total depth of conditional sections
    uint32_t condsects_ign;         ///< Depth of the outermost ignored conditional section

    xml_reader_entity_t ent_ext_subset;     ///< External subset entity
    xml_reader_entity_t ent_document;       ///< Document entity

    struct {
        ucs4_t *start;              ///< Buffer for saved UCS-4 text
        size_t len;                 ///< Count of UCS-4 characters
        size_t sz;                  ///< Size of UCS-4 buffer, in characters
    } rplc;                         ///< Replacement text for an entity

    struct {
        ucs4_t *start;              ///< Reference replacement characters when bypassed
        size_t len;                 ///< Count of characters currently stored
        size_t sz;                  ///< Size of reference replacement buffer
    } refrplc;                      ///< Temporary input when bypassing entity reference

    struct {
        utf8_t *start;              ///< Start of the allocated token buffer
        size_t size;                ///< Size of the token buffer
        size_t used;                ///< Length of saved (reserved) data in token buffer
        size_t len;                 ///< Length of the current (unsaved) token
    } tokenbuf;                     ///< Current token buffer

    struct {
        utf8_t start[MAX_LOOKAHEAD_SIZE];   ///< Lookahead buffer
        size_t len;                         ///< Amount of looked ahead data
    } labuf;                        ///< Lookahead buffer

    struct {
        utf8_t *start;              ///< Allocated name storage buffer
        size_t size;                ///< Size of the name storage buffer
        size_t used;                ///< Number of bytes currently stored
    } namestorage;                  ///< Storage for names associated with lock tokens

    xml_reader_tokens_t svtk;       ///< All saved tokens

    xmlerr_loc_t prodloc;           ///< Reader's position at the start of reportable production
    xmlerr_loc_t refloc;            ///< Entity reference inclusion point
    ucs4_t rejected;                ///< Next character (rejected by xml_read_until_*)
    ucs4_t charrefval;              ///< When parsing character reference: stored value

    strhash_t *entities_param;      ///< Parameter entities
    strhash_t *entities_gen;        ///< General entities
    strhash_t *entities_unknown;    ///< Not yet defined general entities
    strhash_t *notations;           ///< Notations

    xml_reader_input_head_t active_input;       ///< Currently active inputs
    xml_reader_input_head_t free_input;         ///< Free list of input structures
    xml_reader_input_head_t completed_input;    ///< Deferred completion notifications

    SLIST_HEAD(,xml_reader_lock_token_s) active_locks;  ///< Locked productions
    SLIST_HEAD(,xml_reader_lock_token_s) free_locks;    ///< Free lock tokens

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
static const xml_reader_context_t parser_attributes;
static const xml_reader_context_t parser_attr_recovery;
static const xml_reader_context_t parser_internal_subset;
static const xml_reader_context_t parser_external_subset;
static const xml_reader_context_t parser_conditional_section;
static const xml_reader_context_t parser_ignored_section;
static const xml_reader_context_t parser_decl;
static const xml_reader_context_t parser_decl_attributes;

/// Convenience macro: report an error at the start of the last token
#define xml_reader_message_lastread(h, ...) \
        xml_reader_message(h, &h->prodloc, __VA_ARGS__)

/// Convenience macro: report an error at entity/character reference
#define xml_reader_message_ref(h, ...) \
        xml_reader_message(h, &h->refloc, __VA_ARGS__)

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
    @param enc Encoding to be set, NULL to clear current encoding processor
    @return true if successful, false otherwise
*/
static bool
xml_reader_set_encoding(xml_reader_external_t *ex, const encoding_t *enc)
{
    encoding_handle_t *hndnew;

    if (enc != NULL) {
        hndnew = encoding_open(enc);
        if (!ex->enc) {
            ex->enc = hndnew;
        }
        else if (!encoding_switch(&ex->enc, hndnew)) {
            return false;
        }
    }
    else if (ex->enc) {
        encoding_close(ex->enc);
        ex->enc = NULL;
    }
    return true;
}

/**
    Initialize a callback structure.

    @param h Reader handle
    @param cbtype Callback type
    @param cbp Callback parameter structure
    @return None
*/
static inline void
xml_reader_callback_init(xml_reader_t *h, enum xml_reader_cbtype_e cbtype,
        xml_reader_cbparam_t *cbp)
{
    memset(cbp, 0, sizeof(*cbp));
    cbp->cbtype = cbtype;
    cbp->loc = h->prodloc;
}

/**
    Call a user-registered function for the specified event.

    @param h Reader handle
    @param cbp Callback parameter structure
    @return None
*/
static inline void
xml_reader_callback_invoke(xml_reader_t *h, xml_reader_cbparam_t *cbp)
{
    h->cb_func(h->cb_arg, cbp);
}


/**
    Reallocate token buffer.

    @param h Reader handle
    @return Nothing
*/
static void
xml_tokenbuf_realloc(xml_reader_t *h)
{
    h->tokenbuf.size *= 2;
    h->tokenbuf.start = xrealloc(h->tokenbuf.start, h->tokenbuf.size);
}

/**
    Unset a token.

    @param tk Token
    @return Nothing
*/
static inline void
xml_reader_token_unset(xml_reader_token_t *tk)
{
    tk->str = NULL;
    tk->len = 0;
}

/// @todo should be gone when loader uses utf8_t
#define TOKEN_FROM_CHAR(tk, s) do { \
    (tk)->str = (const unsigned char *)(s); \
    (tk)->len = s ? strlen(s) : 0; \
} while (0)

/**
    Save the current token (reserving that portion of the buffer).

    @param h Reader handle
    @param svtk Saved token structure to save into
    @return Nothing
*/
static void
xml_tokenbuf_save(xml_reader_t *h, xml_reader_saved_token_t *svtk)
{
    OOPS_ASSERT(!svtk->reserved);
    svtk->offset = h->tokenbuf.used;
    svtk->len = h->tokenbuf.len;
    svtk->reserved = true;
    h->tokenbuf.used += h->tokenbuf.len;
    h->tokenbuf.len = 0;
}

/**
    Release a previously saved token (must be the last saved token).

    @param h Reader handle
    @param svtk Saved token structure
    @return Nothing
*/
static void
xml_tokenbuf_release(xml_reader_t *h, xml_reader_saved_token_t *svtk)
{
    OOPS_ASSERT(h->tokenbuf.used == svtk->offset + svtk->len); // Last saved?
    OOPS_ASSERT(svtk->reserved);
    h->tokenbuf.used = svtk->offset;
    h->tokenbuf.len = svtk->len;
    svtk->reserved = false;
}

/**
    Pass a saved token info to a callback.

    @param h Reader handle
    @param svtk Saved token
    @param tk Callback token
    @return Nothing
*/
static void
xml_tokenbuf_setcbtoken(xml_reader_t *h, xml_reader_saved_token_t *svtk,
        xml_reader_token_t *tk)
{
    if (svtk->reserved) {
        tk->str = h->tokenbuf.start + svtk->offset;
        tk->len = svtk->len;
    }
    else {
        xml_reader_token_unset(tk);
    }
}

/**
    Flush accumulated data in the token buffer as a TEXT callback.
    TEXT data is special in that it can cross the entity boundaries, and we do not
    know whether the text block has ended until we start the next production (e.g.
    STag).

    @param h Reader handle
    @return Nothing
*/
static void
xml_tokenbuf_flush_text(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;
    xml_reader_saved_token_t tk_cdata = { .reserved = false };

    if (h->tokenbuf.len) {
        xml_tokenbuf_save(h, &tk_cdata);
        xml_reader_callback_init(h, XML_READER_CB_TEXT, &cbp);
        xml_tokenbuf_setcbtoken(h, &tk_cdata, &cbp.text.text);
        cbp.text.ws = h->cdata_ws;
        xml_reader_callback_invoke(h, &cbp);
    }
}

/**
    Set loader info from saved tokens.

    @param h Reader handle
    @param loader_info Loader information to set
    @return Nothing
*/
static void
xml_tokenbuf_set_loader_info(xml_reader_t *h, xml_loader_info_t *loader_info)
{
    if (h->svtk.sysid.reserved) {
        xml_loader_info_set_system_id(loader_info,
                h->tokenbuf.start + h->svtk.sysid.offset, h->svtk.sysid.len);
    }
    if (h->svtk.pubid.reserved) {
        xml_loader_info_set_public_id(loader_info,
                h->tokenbuf.start + h->svtk.pubid.offset, h->svtk.pubid.len);
    }
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
    if (h->rplc.len == h->rplc.sz) {
        h->rplc.sz = h->rplc.sz ? 2 * h->rplc.sz : 256;
        h->rplc.start = xrealloc(h->rplc.start, h->rplc.sz * sizeof(ucs4_t));
    }
    h->rplc.start[h->rplc.len++] = cp;
}

/**
    Store a UCS-4 codepoint in 'reference replacement' buffer, reallocating
    the storage buffer if necessary. Used for storing the text of the reference
    where the reference text itself is inserted into entity value (bypassed).

    @param h Reader handle
    @param cp Codepoint
    @return Nothing
*/
static void
xml_refrplc_store(xml_reader_t *h, ucs4_t cp)
{
    if (h->refrplc.len == h->refrplc.sz) {
        h->refrplc.sz += 32; // Most entity names are going to be shorter than that
        h->refrplc.start = xrealloc(h->refrplc.start, h->refrplc.sz * sizeof(ucs4_t));
    }
    h->refrplc.start[h->refrplc.len++] = cp;
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
    xml_reader_input_t *inp, *parent;
    strbuf_t *buf;

    if ((inp = STAILQ_FIRST(&h->free_input)) != NULL) {
        STAILQ_REMOVE_HEAD(&h->free_input, link);
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
    }
    else {
        parent = STAILQ_FIRST(&h->active_input);
        OOPS_ASSERT(parent);
        inp->curloc = parent->curloc;
    }

    STAILQ_INSERT_HEAD(&h->active_input, inp, link);
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

    while ((inp = STAILQ_FIRST(&h->completed_input)) != NULL) {
        STAILQ_REMOVE_HEAD(&h->completed_input, link);
        inp->complete(h, inp->complete_arg);
        STAILQ_INSERT_HEAD(&h->free_input, inp, link);
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

    OOPS_ASSERT(inp == STAILQ_FIRST(&h->active_input));

    STAILQ_REMOVE_HEAD(&h->active_input, link);
    if (inp->external) {
        h->current_external = NULL;
        STAILQ_FOREACH(next, &h->active_input, link) {
            if (next->external) {
                h->current_external = next->external;
                break;
            }
        }
    }
    // Postpone notifications so that we issue them after processing the
    // last token from this input, if the input has a notification callback.
    STAILQ_INSERT_TAIL(inp->complete ? &h->completed_input : &h->free_input,
            inp, link);
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
    xml_reader_lock_token_t *l;
    xru_t rv = XRU_CONTINUE;

    while ((inp = STAILQ_FIRST(&h->active_input)) != NULL) {
        OOPS_ASSERT(inp->buf);
        if (strbuf_rptr(inp->buf, begin, end) != 0) {
            return rv;
        }
        if ((l = SLIST_FIRST(&h->active_locks)) != NULL && l->input == inp) {
            // Can't remove this input yet
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
    @param locker Production type that locked this input
    @return Nothing
*/
static void
xml_reader_input_lock(xml_reader_t *h, enum xml_reader_locker_e locker)
{
    xml_reader_input_t *inp;
    xml_reader_lock_token_t *l;

    OOPS_ASSERT(locker != LOCKER_NONE);
    inp = STAILQ_FIRST(&h->active_input);
    OOPS_ASSERT(inp);
    if ((l = SLIST_FIRST(&h->free_locks)) != NULL) {
        SLIST_REMOVE_HEAD(&h->free_locks, link);
    }
    else {
        l = xmalloc(sizeof(xml_reader_lock_token_t));
    }
    l->where = inp->curloc;
    l->input = inp;
    l->locker = locker;
    SLIST_INSERT_HEAD(&h->active_locks, l, link);

    l->name_offset = h->namestorage.used;
    l->name_len = 0;
}

/**
    Set name on the most recent lock token.

    @param h Reader handle
    @return Nothing
*/
static void
xml_reader_input_lock_set_name(xml_reader_t *h)
{
    xml_reader_saved_token_t *svtk = &h->svtk.name;
    xml_reader_lock_token_t *l;

    // Get the most recent lock
    l = SLIST_FIRST(&h->active_locks);
    OOPS_ASSERT(l);

    // Check if namestorage buffer has enough space
    OOPS_ASSERT(svtk->reserved);
    while (h->namestorage.used + svtk->len > h->namestorage.size) {
        h->namestorage.size *= 2;
        h->namestorage.start = xrealloc(h->namestorage.start, h->namestorage.size);
    }

    // Then copy the name and reserve that portion
    memcpy(h->namestorage.start + l->name_offset, h->tokenbuf.start + svtk->offset,
            svtk->len);
    h->namestorage.used += svtk->len;
    l->name_len = svtk->len;
}

/**
    Unlock a previously locked input.

    @param h Reader handle
    @return true if the input was locked, false otherwise
*/
static bool __warn_unused_result
xml_reader_input_unlock(xml_reader_t *h)
{
    xml_reader_lock_token_t *l;
    bool rv;

    /*
        Productions lock/unlock inputs in a stack-like fashion. Normally, we
        should be in the same input when unlocking as we were when locking;
        otherwise, signal an error and unlock the closest input (since execution
        will not go back to the same production).
    */
    l = SLIST_FIRST(&h->active_locks);
    OOPS_ASSERT(l);
    rv = l->input == STAILQ_FIRST(&h->active_input);
    SLIST_REMOVE_HEAD(&h->active_locks, link);
    h->namestorage.used = l->name_offset;
    SLIST_INSERT_HEAD(&h->free_locks, l, link);
    return rv;
}

/**
    Attempt to unlock the input, but ignore any failures (used when there
    was some preceding malformedness - so there is no point in the extra error
    message.

    @param h Reader handle
    @return Nothing
*/
static void
xml_reader_input_unlock_ignore(xml_reader_t *h)
{
    bool unlocked;

    unlocked = xml_reader_input_unlock(h);
    if (!unlocked) {
        // Do nothing
    }
}

/**
    Ensure the last input was locked and unlock.

    @param h Reader handle
    @return Nothing
*/
static void
xml_reader_input_unlock_assert(xml_reader_t *h)
{
    bool unlocked;

    unlocked = xml_reader_input_unlock(h);
    OOPS_ASSERT(unlocked);
}

/**
    Check proper nesting of markup declarations.

    @param h Reader handle
    @return Nothing
*/
static void
xml_reader_input_unlock_markupdecl(xml_reader_t *h)
{
    bool unlocked;

    unlocked = xml_reader_input_unlock(h);
    if (!unlocked) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, VC_PROPER_DECL_PE_NESTING),
                "Parameter entity replacement text must be properly nested with "
                "markup declarations");
        xml_reader_message_lastread(h, XMLERR_NOTE,
                "This is the start of the markup declaration");
    }
}

/**
    Check if the current input is locked without unlocking it.

    @param h Reader handle
    @return Lock token if the input is locked, or NULL ortherwise
*/
static xml_reader_lock_token_t *
xml_reader_input_is_locked(xml_reader_t *h)
{
    xml_reader_lock_token_t *l;

    l = SLIST_FIRST(&h->active_locks);
    return l && l->input == STAILQ_FIRST(&h->active_input) ? l : NULL;
}

/**
    Check if locking constraint for conditional section is satisfied.

    @param h Reader handle
    @param markup Currently read markup (for error message)
    @return Nothing (issues error event if constraint is broken)
*/
static void
xml_reader_input_is_locked_condsect(xml_reader_t *h, const char *markup)
{
    xml_reader_lock_token_t *l;

    if (!xml_reader_input_is_locked(h)) {
        l = SLIST_FIRST(&h->active_locks);
        xml_reader_message_current(h, XMLERR(ERROR, XML, VC_PROPER_COND_SECT_PE_NESTING),
                "If %s is contained in PE replacement text, <![ must be in the same "
                "replacement text", markup);
        xml_reader_message(h, &l->where, XMLERR_NOTE,
                "This is the location of <![ markup of the conditional section");
    }
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

    if (sz) {
        inp = STAILQ_FIRST(&h->active_input);
        OOPS_ASSERT(inp);
        OOPS_ASSERT(inp->buf);
        strbuf_radvance(inp->buf, sz);
    }
}

/**
    Look ahead in the parsed stream without advancing the current read location.
    Stops on a non-ASCII character; all mark-up (that requires look-ahead) is
    using ASCII characters.

    @param h Reader handle
    @return true if input is available, false if no more input (EOF or no data in current
        input and cannot break the lock).
*/
static bool
xml_lookahead(xml_reader_t *h)
{
    xml_reader_input_t *inp;
    ucs4_t tmp[MAX_LOOKAHEAD_SIZE];
    ucs4_t *ptr = tmp;
    utf8_t *bufptr = h->labuf.start;
    size_t i, nread;

    if ((inp = STAILQ_FIRST(&h->active_input)) == NULL) {
        h->labuf.len = 0;
        return false;
    }
    if ((nread = strbuf_lookahead(inp->buf, ptr, MAX_LOOKAHEAD_SIZE * sizeof(ucs4_t))) == 0) {
        h->labuf.len = 0;
        return false;
    }
    OOPS_ASSERT((nread & 3) == 0); // input buf must have an integral number of characters
    nread /= 4;
    for (i = 0; i < nread; i++) {
        if (*ptr >= 0x7F) {
            break; // Non-ASCII
        }
        *bufptr++ = *ptr++;
    }
    h->labuf.len = ptr - tmp;
    return true; // Even if we didn't put anything into token buffer, there's data to process
}

/**
    Allocate a new notation in the handle. Use the saved name token as the notation name.

    @param h Reader handle
    @return Newly allocated initialized notation
*/
static xml_reader_notation_t *
xml_notation_new(xml_reader_t *h)
{
    const utf8_t *name = h->tokenbuf.start + h->svtk.name.offset;
    size_t namelen = h->svtk.name.len;
    xml_reader_notation_t *n;

    n = xmalloc(sizeof(xml_reader_notation_t));
    memset(n, 0, sizeof(xml_reader_notation_t));
    xml_loader_info_init(&n->loader_info, NULL, NULL);
    n->name.str = strhash_set(h->notations, name, namelen, n);
    n->name.len = namelen;
    return n;
}

/**
    Get notation by the saved token.

    @param h Reader handle
    @param svtk Saved token with notation name
    @return Previously defined notation, or NULL if none found.
*/
static xml_reader_notation_t *
xml_notation_get(xml_reader_t *h, const xml_reader_saved_token_t *svtk)
{
    const utf8_t *name = h->tokenbuf.start + svtk->offset;
    size_t namelen = svtk->len;

    return strhash_get(h->notations, name, namelen);
}

/**
    Delete a notation.

    @param h Reader handle
    @param n Notation being deleted
    @return Nothing
*/
static void
xml_notation_delete(xml_reader_t *h, xml_reader_notation_t *n)
{
    strhash_set(h->notations, n->name.str, n->name.len, NULL);
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

    @param h Reader handle
    @param parameter True if parameter entity is created
    @return Newly allocated initialized entity
*/
static xml_reader_entity_t *
xml_entity_new(xml_reader_t *h, bool parameter)
{
    strhash_t *ehash = parameter ? h->entities_param : h->entities_gen;
    const utf8_t *name = h->tokenbuf.start + h->svtk.name.offset;
    size_t namelen = h->svtk.name.len;
    xml_reader_entity_t *e;
    const char *s;

    e = xmalloc(sizeof(xml_reader_entity_t));
    memset(e, 0, sizeof(xml_reader_entity_t));
    xml_loader_info_init(&e->loader_info, NULL, NULL);
    e->name.str = strhash_set(ehash, name, namelen, e);
    e->name.len = namelen;
    s = utf8_strtolocal(e->name.str);
    e->location = xasprintf("entity(%s)", s);
    e->type = parameter ? XML_READER_REF_PE : XML_READER_REF_GENERAL;
    utf8_strfreelocal(s);
    return e;
}

/**
    Get entity by the saved token.

    @param h Reader handle
    @param svtk Saved token with entity name
    @param parameter True if the parameter entity is queried
    @return Previously defined notation, or NULL if none found.
*/
static xml_reader_entity_t *
xml_entity_get(xml_reader_t *h, const xml_reader_saved_token_t *svtk, bool parameter)
{
    strhash_t *ehash = parameter ? h->entities_param : h->entities_gen;
    const utf8_t *name = h->tokenbuf.start + svtk->offset;
    size_t namelen = svtk->len;

    return strhash_get(ehash, name, namelen);
}

/**
    Delete an entity.

    @param h Reader handle
    @param e Entity being deleted
    @return Nothing
*/
static void
xml_entity_delete(xml_reader_t *h, xml_reader_entity_t *e)
{
    strhash_t *ehash;
   
    switch (e->type) {
    case XML_READER_REF_PE:
    case XML_READER_REF_PE_INTERNAL:
    case XML_READER_REF_PE_EXTERNAL:
        ehash = h->entities_param;
        break;
    default:
        ehash = h->entities_gen;
        break;
    }

    strhash_set(ehash, e->name.str, e->name.len, NULL);
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
    xfree(e->rplc);
    xfree(e->location);
    xfree(e);
}

/**
    Get unknown entity by the saved token.

    @param h Reader handle
    @param svtk Saved token with entity name
    @return Previously defined notation, or NULL if none found.
*/
static xml_reader_unknown_entity_t *
xml_unknown_entity_get(xml_reader_t *h, const xml_reader_saved_token_t *svtk)
{
    const utf8_t *name = h->tokenbuf.start + svtk->offset;
    size_t namelen = svtk->len;

    return strhash_get(h->entities_unknown, name, namelen);
}

/**
    Delete an unknown entity record.

    @param h Reader handle
    @param svtk Saved token with entity name
    @return Nothing
*/
static void
xml_unknown_entity_delete(xml_reader_t *h, const xml_reader_saved_token_t *svtk)
{
    const utf8_t *name = h->tokenbuf.start + svtk->offset;
    size_t namelen = svtk->len;

    /// @todo strhash_delete that doesn't have to lookup using container_of to find item
    strhash_set(h->entities_unknown, name, namelen, NULL);
}

/**
    Destructor for unknown entity record.

*/
static void
xml_unknown_entity_destroy(void *arg)
{
    xml_reader_unknown_entity_t *ue = arg;

    xfree(ue);
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

    @param h Reader handle
    @return Nothing
*/
static void
xml_entity_populate(xml_reader_t *h)
{
    const xml_predefined_entity_t *predef;
    const char *s;
    xml_reader_entity_t *e;
    ucs4_t *rplc;
    size_t i, j, nchars;

    // We'll use token buffer, make sure it's empty
    OOPS_ASSERT(h->tokenbuf.used == 0);
    OOPS_ASSERT(h->tokenbuf.len == 0);
    for (i = 0, predef = predefined_entities; i < sizeofarray(predefined_entities);
            i++, predef++) {
        s = predef->rplc[0];
        // Entity allocation routine is tailored for allocating from a definition,
        // emulate that. We know the buffer is large enough to accommodate the predefined
        // entities.
        OOPS_ASSERT(predef->namelen <= h->tokenbuf.size);
        memcpy(h->tokenbuf.start, predef->name, predef->namelen);
        h->svtk.name.offset = 0;
        h->svtk.name.len = predef->namelen;
        e = xml_entity_new(h, false);
        e->type = XML_READER_REF_INTERNAL;
        // Only ASCII replacements here, 1 byte per character
        nchars = strlen(s);
        e->rplclen = nchars * sizeof(ucs4_t);
        rplc = xmalloc(e->rplclen);
        for (j = 0; j < nchars; j++) {
            rplc[j] = ucs4_fromlocal(s[j]);
        }
        e->rplc = rplc;
        e->predef = predef;
    }
}

/**
    Initialize a special internally used entity - document, external subset.

    @param e Entity to initialize
    @param enttype Entity type
    @return Nothing
*/
static void
entity_init_special(xml_reader_entity_t *e, enum xml_reader_reference_e enttype)
{
    memset(e, 0, sizeof(*e));
    e->type = enttype;
    xml_loader_info_init(&e->loader_info, NULL, NULL);
}

/**
    Destroy a special internally used entity.

    @param e Entity to destroy
    @return Nothing
*/
static void
entity_destroy_special(xml_reader_entity_t *e)
{
    xml_loader_info_destroy(&e->loader_info);
}

/**
    Check if the entity is external or internal.

    @param e Entity
    @return true if the entity is external
*/
static bool
entity_is_external(xml_reader_entity_t *e)
{
    switch (e->type) {
    case XML_READER_REF_PE_EXTERNAL:
    case XML_READER_REF_EXTERNAL:
    case XML_READER_REF_UNPARSED:
    case XML_READER_REF_DOCUMENT:
    case XML_READER_REF_EXT_SUBSET:
        return true;
    default:
        return false;
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
    .normalization_accept_unknown = false,
    .loctrack = true,
    .load_externals = true,
    .tabsize = 8,
    .entity_hash_order = 6,
    .notation_hash_order = 4,
    .initial_tokenbuf = 1024,
    .initial_namestorage = 256,
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

    h->opt = *opts;

    // what would be the context of the entities loaded from it
    h->standalone = XML_INFO_STANDALONE_NO_VALUE;
    h->norm_include = NULL;

    h->tokenbuf.size = max(opts->initial_tokenbuf, MAX_LOOKAHEAD_SIZE);
    h->tokenbuf.start = xmalloc(h->tokenbuf.size);

    h->namestorage.size = opts->initial_namestorage;
    h->namestorage.start = xmalloc(h->namestorage.size);

    entity_init_special(&h->ent_ext_subset, XML_READER_REF_EXT_SUBSET);
    entity_init_special(&h->ent_document, XML_READER_REF_DOCUMENT);

    // Hash of unknown entities not used for parsing content (only DTD), so use a
    // zero order (essentially turning it into a list, but with fast comparison).
    h->entities_param = strhash_create(opts->entity_hash_order, xml_entity_destroy);
    h->entities_gen = strhash_create(opts->entity_hash_order, xml_entity_destroy);
    h->entities_unknown = strhash_create(0, xml_unknown_entity_destroy);
    h->notations = strhash_create(opts->notation_hash_order, xml_notation_destroy);

    STAILQ_INIT(&h->active_input);
    STAILQ_INIT(&h->free_input);
    STAILQ_INIT(&h->completed_input);

    SLIST_INIT(&h->active_locks);
    SLIST_INIT(&h->free_locks);

    STAILQ_INIT(&h->external);

    xml_entity_populate(h);

    // When we start parsing, it will be document entity context
    h->ctx = &parser_document_entity;

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
    xml_reader_lock_token_t *l;

    while ((l = SLIST_FIRST(&h->active_locks)) != NULL) {
        SLIST_REMOVE_HEAD(&h->active_locks, link);
        xfree(l);
    }
    while ((l = SLIST_FIRST(&h->free_locks)) != NULL) {
        SLIST_REMOVE_HEAD(&h->free_locks, link);
        xfree(l);
    }
    while ((inp = STAILQ_FIRST(&h->active_input)) != NULL) {
        STAILQ_REMOVE_HEAD(&h->active_input, link);
        xml_reader_input_destroy(inp);
    }
    // Upon valid exit from xml_reader_run() (via end-of-input or via STOP request,
    // the notification list must have been flushed.
    OOPS_ASSERT(STAILQ_EMPTY(&h->completed_input));
    while ((inp = STAILQ_FIRST(&h->free_input)) != NULL) {
        STAILQ_REMOVE_HEAD(&h->free_input, link);
        xml_reader_input_destroy(inp);
    }
    while ((ex = STAILQ_FIRST(&h->external)) != NULL) {
        STAILQ_REMOVE_HEAD(&h->external, link);
        xml_reader_external_destroy(ex);
    }

    if (h->norm_include) {
        nfc_destroy(h->norm_include);
    }

    entity_destroy_special(&h->ent_ext_subset);
    entity_destroy_special(&h->ent_document);

    strhash_destroy(h->entities_param);
    strhash_destroy(h->entities_gen);
    strhash_destroy(h->entities_unknown);
    strhash_destroy(h->notations);

    xfree(h->tokenbuf.start);
    xfree(h->namestorage.start);

    xfree(h->rplc.start);
    xfree(h->refrplc.start);
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
    Call user-registered entity loader.

    @param h Reader handle
    @param loader_info Loader information for entity being loaded
    @param e Entity being added, or NULL if not loading an entity
    @param ctx Parser context associated with this external entity
    @param inc_in_literal Entity is being included from a literal if true
    @param on_complete Additional processing to be called on input completion
    @return true if an entity was loaded, false otherwise
*/
static bool
xml_reader_invoke_loader(xml_reader_t *h, const xml_loader_info_t *loader_info,
        xml_reader_entity_t *e, const xml_reader_context_t *ctx, bool inc_in_literal,
        xml_reader_external_completion_cb_t on_complete)
{
    xml_reader_hidden_loader_arg_t ha;
    xml_reader_cbparam_t cbp;

    // TBD if e is document entity, disregard h->opt.load_externals
    // TBD if standalone and we get here and e is not a document entity - emit an error
    if (h->opt.load_externals) {
        ha.entityref = e;
        ha.ctx = ctx;
        ha.inc_in_literal = inc_in_literal;
        ha.on_complete = on_complete;

        // Hidden arguments:
        // - if the loader decides to add an external input for this entity, we know
        // what entity it belongs to
        // - if an external input is added, we may need to save (and, on input's completion,
        // restore) the parser context
        // - if an input is loaded from a literal (where quotes have special meaning), mark
        // the input as such
        h->hidden_loader_arg = &ha;
        h->loader(h, h->loader_arg, loader_info);
        if (!h->hidden_loader_arg) {
            return true;
        }
    }

    // Loader didn't create an input or we didn't even invoke it
    h->hidden_loader_arg = NULL;
    xml_reader_callback_init(h, XML_READER_CB_ENTITY_NOT_LOADED, &cbp);
    cbp.entity.name = e->name;
    cbp.entity.type = e->type;
    cbp.loc = e->included;
    // TBD ctx argument should go away (be determined by the entity type)
    // TBD loader_info argument should go away (be passed in the entity)
    /// @todo make loader use utf8_t (and size?)
    TOKEN_FROM_CHAR(&cbp.entity.system_id, loader_info->system_id);
    TOKEN_FROM_CHAR(&cbp.entity.public_id, loader_info->public_id);
    xml_reader_callback_invoke(h, &cbp);
    return false;
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

    /// Position (@a la_offs) at each looked ahead character
    size_t la_pos[MAX_LOOKAHEAD_SIZE];

    /// Index in the position index
    size_t la_pos_idx;

    /// Flag if current position has been set (if more than 1 byte is consumed per character,
    /// do not update the position on 2nd and further bytes)
    bool la_pos_set;

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

    // The loop below can be converted to reading into lookahead buffer in bulk, but
    // we'd then need to transcode the characters one by one as the position of each
    // of these characters needs to be recorded. After reading the declaration, the
    // encoding may need to be changed, we will need to skip the exact number of bytes
    // that the declaration used.
    OOPS_ASSERT(sz != 0);
    OOPS_ASSERT((sz & 3) == 0); // Reading in 32-bit blocks
    bptr = cptr = begin;
    while (true) {
        if (xc->la_offs == xc->la_avail) {
            // Need to read more data into the buffer ...
            if (xc->la_avail == xc->la_size) {
                /// @todo add a configurable limit on how large we can ever go
                // (or malicious input can keep this library consuming more and more memory)
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
        /// @todo to cover the else-branch of this conditional, need multibyte input
        /// which is broken (by the downstream strbuf) at an odd position.
        if (!xc->la_pos_set) {
            xc->la_pos_set = true;
            OOPS_ASSERT(xc->la_pos_idx < sizeofarray(xc->la_pos));
            xc->la_pos[xc->la_pos_idx++] = xc->la_offs;
        }
        xc->la_offs += encoding_in(ex->enc, xc->la_start + xc->la_offs,
                xc->la_start + xc->la_avail, &cptr, bptr + 1);

        if (cptr != bptr) {
            xc->la_pos_set = false;
            break;
        }

        // If reading did not produce a character (was absorbed by encoding
        // state), repeat - possibly reading more
    }

    OOPS_ASSERT(cptr == bptr + 1); // Must have 1 character
    return sizeof(ucs4_t);
}

/**
    Notification when the read pointer is advanced.

    @param arg Pointer to transcoder state
    @param sz Number of bytes to advance
    @return Nothing
*/
static void
xml_reader_initial_op_radvance(void *arg, size_t sz)
{
    xml_reader_initial_xcode_t *xc = arg;

    OOPS_ASSERT((sz & 3) == 0); // Reading in 32-bit blocks
    sz /= 4;
    memmove(xc->la_pos, xc->la_pos + sz, sizeof(xc->la_pos) - sizeof(*xc->la_pos) * sz);
    xc->la_pos_idx -= sz;
}

/// Operations for transcoding XMLDecl/TextDecl
static const strbuf_ops_t xml_reader_initial_ops = {
    .more = xml_reader_initial_op_more,
    .radvance = xml_reader_initial_op_radvance,
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
    @return Reason why the token parser returned
*/
static inline xru_t
xml_read_until(xml_reader_t *h, xml_condread_func_t func, void *arg)
{
    xml_reader_input_t *inp;
    xml_reader_external_t *ex;
    const void *begin, *end;
    const ucs4_t *ptr;
    ptrdiff_t offs;
    ucs4_t cp, cp0;
    size_t clen;
    utf8_t *bufptr;
    xru_t rv;
    bool norm_warned;

    xml_reader_input_complete_notify(h); // Process any outstanding notifications

    bufptr = h->tokenbuf.start + h->tokenbuf.used + h->tokenbuf.len;
    h->rejected = UCS4_NOCHAR; // Avoid stale data if we exit without looking at next char

    do {
        // ... and only if we're not terminating yet, try to get next read pointers
        if ((rv = xml_reader_input_rptr(h, &begin, &end)) != XRU_CONTINUE) {
            break;
        }
        inp = STAILQ_FIRST(&h->active_input);
        ex = inp->external;
        for (ptr = begin;
                rv == XRU_CONTINUE && ptr < (const ucs4_t *)end;
                ptr++) {

            cp0 = *ptr; // codepoint before possible substitution by func
            if (ex) {
                if (ex->saw_cr) {
                    ex->saw_cr = false;
                    if (cp0 == 0x0A || cp0 == 0x85) {
                        // EOL normalization. This is "continuation" of a previous character - so
                        // is treated before positioning update.
                        /// @todo This also means these characters do not reach the normalization
                        /// checker... but they are never denormalizing (neither decomposanble, nor
                        /// do they appear in decompositions of other characters), so that's ok.
                        continue;
                    }
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
                    // If 0x0D is not accepted, ex->saw_cr will be reset above when 0x0D is
                    // processed again.
                    ex->saw_cr = true;
                    cp0 = 0x0A;
                }
                else if ((cp0 == 0x85 || cp0 == 0x2028)
                        && !(h->flags & R_ASCII_ONLY)) {
                    cp0 = 0x0A;
                }
            }

            // Check if entity expansion is needed
            if (((ucs4_cheq(cp0, '&') && (h->flags & R_RECOGNIZE_REF) != 0)
                        || (ucs4_cheq(cp0, '%') && (h->flags & R_RECOGNIZE_PEREF) != 0))
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
            else if (cp0 >= 0x7F && (h->flags & R_ASCII_ONLY)) {
                // Only complain once.
                h->flags &= ~R_ASCII_ONLY;
                OOPS_ASSERT(h->declinfo);
                xml_reader_message_current(h, XMLERR(ERROR, XML, P_XMLDecl),
                        "Malformed %s: non-ASCII character", h->declinfo->name);
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
            if (h->opt.normalization == XML_READER_NORM_ON) {
                norm_warned = false;
                // Is this character known? If not, do we care?
                if (!ucs4_is_assigned(cp0) && !h->opt.normalization_accept_unknown) {
                    xml_reader_message_current(h, XMLERR(WARN, XML, NORMALIZATION),
                            "Unicode character U+%04X is not assigned in this Unicode version.", cp0);
                    norm_warned = true;
                }
                // Does it come from the regular input or was a result of some substitution?
                if (inp->external
                        && !nfc_check_nextchar(inp->external->norm_unicode, cp0)) {
                    // Above there is only the check for unassigned characters - which are not,
                    // by definition, a part of any composite.
                    OOPS_ASSERT(!norm_warned);
                    xml_reader_message_current(h, XMLERR(WARN, XML, NORMALIZATION),
                            "Input is not Unicode-normalized");
                    norm_warned = true;
                }
                // Is this going to be a part of the document or will it be replaced?
                if ((h->flags & R_NO_INC_NORM) == 0
                        && !nfc_check_nextchar(h->norm_include, cp0)) {
                    /// @todo _ref or _current? _ref is where the last inclusion occurred, but
                    /// it may not be the relevant part (i.e. if the denormalization happend
                    /// in the nested include). Have refloc saved in each input when it is interrupted
                    /// by another input inclusion?
                    if (!norm_warned) {
                        xml_reader_message_current(h, XMLERR(WARN, XML, NORMALIZATION),
                                "Input is not include-normalized");
                        norm_warned = true;
                    }
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
                        /// @todo set h->relevant in NmToken (non-CDATA attributes)
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
                if (bufptr + clen > h->tokenbuf.start + h->tokenbuf.size) {
                    // Double token storage
                    offs = bufptr - h->tokenbuf.start;
                    xml_tokenbuf_realloc(h);
                    bufptr = h->tokenbuf.start + offs;
                }
                utf8_store(&bufptr, cp);
                h->tokenbuf.len += clen;
                if (h->flags & R_SAVE_UCS4) {
                    xml_ucs4_store(h, cp);
                }
            }

            // Character not rejected, update position. Note that we're checking
            // the original character - cp0 - not processed, so that we update position
            // based on actual input.
            if (h->opt.loctrack) {
                xml_reader_update_position(inp, cp0, h->opt.tabsize);
            }
        }

        // Consumed this block
        xml_reader_input_radvance(h, (const uint8_t *)ptr - (const uint8_t *)begin);
    } while (rv == XRU_CONTINUE);
    return rv;
}

/**
    Read condition: until first non-whitespace.

    @param arg Pointer to boolean, set when whitespace is seen.
    @param cp Codepoint
    @return UCS4_STOPCHAR if @a cp is whitespace, UCS4_NOCHAR otherwise
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

    (void)xml_read_until(h, xml_cb_not_whitespace, &had_ws);
    return had_ws ? PR_OK : PR_NOMATCH;
}

/// Recovery state
typedef struct {
    const char *stopchars;  ///< Stop characters
} xml_cb_recover_state_t;

/**
    Read condition: recovery until the specified stop character.

    @param arg Recovery state
    @param cp Codepoint
    @return UCS4_STOPCHAR if @a cp is next char after a right angle bracket,
        @a cp otherwise
*/
static ucs4_t
xml_cb_recover(void *arg, ucs4_t cp)
{
    xml_cb_recover_state_t *st = arg;
    const char *p;

    for (p = st->stopchars; *p; p++) {
        if (ucs4_cheq(cp, *p)) {
            return UCS4_STOPCHAR;
        }
    }
    return UCS4_NOCHAR;
}

/**
    Recovery function: read until the next stop character.

    @param h Reader handle
    @param stopchars Markup characters that will stop this function; not consumed.
    @return Always PR_OK if reached one of the stop characters, PR_NOMATCH otherwise
*/
static prodres_t
xml_read_recover(xml_reader_t *h, const char *stopchars)
{
    xml_cb_recover_state_t st;

    st.stopchars = stopchars;
    if (xml_read_until(h, xml_cb_recover, &st) == XRU_STOP) {
        // Found the stop character
        return PR_OK;
    }
    return PR_NOMATCH;
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

    if (*isstartchar) {
        if (xml_is_NameStartChar(cp)) {
            *isstartchar = false;
            return cp;
        }
    }
    else if (xml_is_NameChar(cp)) {
        return cp;
    }
    return UCS4_STOPCHAR;
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

    // May stop at either non-Name character, or input boundary. The first character
    // is also subject to composing character check if normalization check is active.
    h->relevant = "Name";
    (void)xml_read_until(h, xml_cb_not_name, &startchar);
    if (startchar) {
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

    tmp = ucs4_fromlocal(*st->cur);
    OOPS_ASSERT(tmp < 0x7F); // Only ASCII in markup
    if (tmp != cp) {
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
    xml_cb_string_state_t st;
    xmlerr_loc_t startloc;

    // Production must lock to expect fixed markup
    OOPS_ASSERT(!STAILQ_EMPTY(&h->active_input));
    startloc = STAILQ_FIRST(&h->active_input)->curloc;
    st.cur = s;
    st.end = s + strlen(s);
    if (xml_read_until(h, xml_cb_string, &st) != XRU_STOP || st.cur != st.end) {
        if (errinfo != XMLERR_NOERROR) {
            xml_reader_message(h, &startloc, errinfo, "Expected string: '%s'", s);
        }
        return PR_NOMATCH;
    }
    return PR_OK;
}

/**
    Read an expected string where the content has already been checked via
    lookahead. Does not raise an error; rather just checks the result with
    an assertion.

    @param h Reader handle
    @param s String expected in the document; must be ASCII-only
    @return Nothing (asserts on no match)
*/
static void
xml_read_string_assert(xml_reader_t *h, const char *s)
{
    prodres_t rv;

    rv = xml_read_string(h, s, XMLERR_NOERROR);
    OOPS_ASSERT(rv == PR_OK);
}

/**
    Read an expected string that starts a locked production.

    @param h Reader handle
    @param s String expected in the document; must be ASCII-only
    @param locker Locking production type
    @return Nothing (asserts on no match)
*/
static void
xml_read_string_lock(xml_reader_t *h, const char *s, enum xml_reader_locker_e locker)
{
    xml_reader_input_lock(h, locker);
    xml_read_string_assert(h, s);
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

    /// Function to call on change in match position
    void (*func)(void *, size_t, size_t);
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
    size_t newpos;

    while (st->pos > 0 && ucs4_fromlocal(st->term.str[st->pos]) != cp) {
        newpos = st->term.failtab[st->pos - 1];
        if (st->func) {
            st->func(st->arg, st->pos, newpos);
        }
        st->pos = newpos;
    }
    if (ucs4_fromlocal(st->term.str[st->pos]) == cp) {
        newpos = st->pos + 1;
        if (st->func) {
            st->func(st->arg, st->pos, newpos);
        }
        st->pos = newpos;
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
    Read a string until a terminating string is seen. ASCII only strings are
    allowed.

    @param h Reader handle
    @param ts Terminator string info (string, length, failure function)
    @param func Function to call when matching position changes; NULL
        if no notifications are requested.
    @param arg Argument to @a func callback
    @return PR_OK on success, PR_NOMATCH if terminator string was not found.
*/
static prodres_t
xml_read_termstring(xml_reader_t *h, const xml_termstring_desc_t *ts,
        void (*func)(void *, size_t, size_t), void *arg)
{
    xml_cb_termstring_state_t st;

    st.term = *ts;
    st.pos = 0;
    st.func = func;
    st.arg = arg;
    if (xml_read_until(h, xml_cb_termstring, &st) != XRU_STOP) {
        return PR_NOMATCH;
    }
    // Drop match terminator from token buffer
    h->tokenbuf.len -= st.term.len;
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
        [XML_READER_REF_NONE] = { "unknown", XMLERR_XML_P_Reference },
        [XML_READER_REF_PE] = { "parameter entity", XMLERR_XML_P_PEReference },
        [XML_READER_REF_PE_INTERNAL] = { "parameter entity", XMLERR_XML_P_PEReference },
        [XML_READER_REF_PE_EXTERNAL] = { "parameter entity", XMLERR_XML_P_PEReference },
        [XML_READER_REF_GENERAL] = { "general entity", XMLERR_XML_P_EntityRef },
        [XML_READER_REF_INTERNAL] = { "internal general entity", XMLERR_XML_P_EntityRef },
        [XML_READER_REF_EXTERNAL] = { "external parsed general entity", XMLERR_XML_P_EntityRef },
        [XML_READER_REF_UNPARSED] = { "external unparsed general entity", XMLERR_XML_P_EntityRef },
        [XML_READER_REF_CHARACTER] = { "character", XMLERR_XML_P_CharRef },
    };

    OOPS_ASSERT(type < sizeofarray(refinfo));
    OOPS_ASSERT(type < XML_READER_REF__MAXREF);
    return &refinfo[type];
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
    xru_t rv;
    ucs4_t startchar = h->rejected;

    // Until we know better
    *reftype = XML_READER_REF_NONE;

    // Where this reference occurred
    h->refloc = STAILQ_FIRST(&h->active_input)->curloc;

    // We know startchar is there, it has been rejected by previous call. Whatever
    // we read is not going to be a part of include-normalization check.
    h->flags |= R_NO_INC_NORM;
    if (ucs4_cheq(startchar, '&')) {
        // This may be either entity or character reference
        xml_read_string_lock(h, "&", LOCKER_REFERENCE);
        if (xml_read_Name(h) == PR_OK) {
            // EntityRef
            *reftype = XML_READER_REF_GENERAL;
            goto read_content;
        }
        else if (ucs4_cheq(h->rejected, '#')) {
            // CharRef
            *reftype = XML_READER_REF_CHARACTER;
            xml_read_string_assert(h, "#");
            st.val = 0;
            st.hasdigits = false;
            st.toobig = false;
            if (xml_read_string(h, "x", XMLERR_NOERROR) == PR_OK) {
                // Using hexadecimal form
                rv = xml_read_until(h, xml_cb_charref_hex, &st);
            }
            else {
                // Using decimal form
                rv = xml_read_until(h, xml_cb_charref_dec, &st);
            }
            if (rv != XRU_STOP || !st.hasdigits) {
                goto malformed;
            }
            h->charrefval = st.toobig ? UCS4_NOCHAR : st.val;
            goto read_content;
        }
        // What the ... reference is this?
        goto malformed;
    }

    OOPS_ASSERT(!!ucs4_cheq(startchar, '%'));
    // PEReference or standalone percent sign. In external subset,
    // percent sign may be taken literally in the parameter entity
    // definition. If that's the case, it is followed by a whitespace
    // (S) rather than Name.
    xml_read_string_lock(h, "%", LOCKER_PE_REFERENCE);
    if (xml_read_Name(h) == PR_OK) {
        *reftype = XML_READER_REF_PE;
        goto read_content;
    }
    if (h->flags & R_AMBIGUOUS_PERCENT) {
        goto literal_percent;
    }
    *reftype = XML_READER_REF_PE;
    goto malformed;

read_content:
    ri = xml_entity_type_info(*reftype);
    // Reading as a whole - if fail to match string, error will be raised below
    if (xml_read_string(h, ";", XMLERR_NOERROR) != PR_OK) {
        goto malformed;
    }
    h->flags &= ~R_NO_INC_NORM;
    xml_reader_input_unlock_assert(h); // No recognized entities parsed since lock
    return PR_OK;

literal_percent:
    // Consider the percent sign as having literal meaning. Prepend an
    // an input with percent sign; mark it as reference-ignoring so that
    // we don't try to interpret this as a PE reference again
    h->flags &= ~R_NO_INC_NORM;
    xml_reader_input_unlock_assert(h); // No recognized entities parsed since lock
    inp = xml_reader_input_new(h, "literal percent sign");
    strbuf_set_input(inp->buf, rplc_percent, sizeof(rplc_percent));
    inp->ignore_references = true;
    return PR_NOMATCH;

malformed:
    h->flags &= ~R_NO_INC_NORM;
    ri = xml_entity_type_info(*reftype);
    xml_reader_message_ref(h, XMLERR_MK(XMLERR_ERROR, XMLERR_SPEC_XML, ri->ecode),
            "Malformed %s reference", ri->desc);
    xml_reader_input_unlock_assert(h); // No recognized entities parsed since lock
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

    xml_reader_callback_init(h, XML_READER_CB_ENTITY_PARSE_START, &cbp);
    cbp.loc = h->refloc;
    cbp.entity.type = e->type;
    cbp.entity.name = e->name;
    TOKEN_FROM_CHAR(&cbp.entity.system_id, e->loader_info.system_id);
    TOKEN_FROM_CHAR(&cbp.entity.public_id, e->loader_info.public_id);
    xml_reader_callback_invoke(h, &cbp);
    e->included = h->refloc;
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

    // OOPS_ASSERT(e->being_parsed);
    // TBD temp hack - called once from invoke_loader and once from external_entity_end
    // Need to use ex->aborted to skip the other call? Or remove the input without completion
    // notification call? In any case, easier to do once add_parsed_entity is moved into
    // invoke_loader and merged with entity_include.
    if (!e->being_parsed) { return; }
    xml_reader_callback_init(h, XML_READER_CB_ENTITY_PARSE_END, &cbp);
    cbp.loc = e->included;
    cbp.entity.type = e->type;
    cbp.entity.name = e->name;
    TOKEN_FROM_CHAR(&cbp.entity.system_id, e->loader_info.system_id);
    TOKEN_FROM_CHAR(&cbp.entity.public_id, e->loader_info.public_id);
    xml_reader_callback_invoke(h, &cbp);
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
    xml_reader_message_ref(h, XMLERR_MK(XMLERR_ERROR, XMLERR_SPEC_XML, ri->ecode),
            "Reference to %s is forbidden here", ri->desc);
}

/**
    Entity handler: 'Included in literal'

    @param h Reader handle
    @param e Entity information
    @param inc_in_literal True if 'included in literal'
    @param ctx Parser context for the new entity's input; only meaningful for external
        entities. NULL if no context switch is needed.
    @param on_complete For external entities, handler of completion
    @return Nothing
*/
static void
entity_include(xml_reader_t *h, xml_reader_entity_t *e, bool inc_in_literal,
        const xml_reader_context_t *ctx, void (*on_complete)(xml_reader_t *, const xmlerr_loc_t *))
{
    // TBD merge with xml_reader_invoke_loader once it is invoked only from here
    xml_reader_input_t *inp;

    // TBD determine completion handler by entity type? seems awkward that it is only passed
    // for externals. Or save in entity and call from entity_end()? In that case, remove on_complete
    // call from invoke_loader (and may not even need to pass it down - entity_end will call it)
    if (entity_is_external(e)) {
        if (xml_loader_info_isset(&e->loader_info)) {
            entity_start(h, e);
            if (!xml_reader_invoke_loader(h, &e->loader_info, e, ctx, inc_in_literal, on_complete)) {
                // No input has been added - consider it end of this entity's parsing
                entity_end(h, e);
                if (on_complete) {
                    on_complete(h, NULL);
                }
            }
        }
        else {
            if (on_complete) {
                on_complete(h, NULL);
            }
        }
    }
    else {
        // Internal entity - notify about start and either add the replacement text
        // to the input stack or, if empty, signal the end immediately.
        entity_start(h, e);
        if (e->rplclen) {
            inp = xml_reader_input_new(h, e->location);
            strbuf_set_input(inp->buf, e->rplc, e->rplclen);
            inp->entity = e;
            inp->inc_in_literal = inc_in_literal;
            inp->complete = entity_end;
            inp->complete_arg = e;
        }
        else {
            entity_end(h, e);
        }
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
    entity_include(h, e, true, NULL, NULL);
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
    entity_include(h, e, false, NULL, NULL);
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
    /// @todo check 'if validating' condition? Or have a separate flag, 'loading entities', that
    /// controls this function?
    entity_include(h, e, false, NULL, NULL);
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
    // matters, though, as we add identical spaces before and after :)
    inp = xml_reader_input_new(h, NULL);
    strbuf_set_input(inp->buf, rplc_space, sizeof(rplc_space));
    entity_include(h, e, false, &parser_external_subset, NULL);
    inp = xml_reader_input_new(h, NULL);
    strbuf_set_input(inp->buf, rplc_space, sizeof(rplc_space));
}

/**
    Entity handler: 'Bypassed'. Can only be used for general entities.

    @param h Reader handle
    @param e Entity information
    @return Nothing
*/
static void
reference_bypassed(xml_reader_t *h, xml_reader_entity_t *e)
{
    xml_reader_unknown_entity_t *ue;
    xml_reader_input_t *inp;
    const utf8_t *ptr, *end;

    // Prepare the replacement text for the reference
    h->refrplc.len = 0;
    xml_refrplc_store(h, ucs4_fromlocal('&'));
    ptr = e->name.str;
    end = ptr + e->name.len;
    while (ptr < end) {
        xml_refrplc_store(h, utf8_load(&ptr));
    }
    xml_refrplc_store(h, ucs4_fromlocal(';'));
    inp = xml_reader_input_new(h, NULL);
    strbuf_set_input(inp->buf, h->refrplc.start, h->refrplc.len * sizeof(ucs4_t));
    inp->ignore_references = true;

    // If we don't know this entity yet, record it so that we can later complain if
    // it is defined as unparsed
    if (e->type == XML_READER_REF_GENERAL) {
        ue = xmalloc(sizeof(xml_reader_unknown_entity_t));
        ue->referenced = h->prodloc;
        strhash_set(h->entities_unknown, e->name.str, e->name.len, ue);
    }
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
    xml_reader_message_ref(h, XMLERR_MK(XMLERR_ERROR, XMLERR_SPEC_XML, ri->ecode),
            "%s reference here is an error", ri->desc);

    // Bypass the reference so that we complain where it is used, too
    reference_bypassed(h, e);
}

/**
    Entity hanler: unknown entity in a context where we must include its
    replacement text.

    @param h Reader handle
    @param e Entity information
    @return Nothing
*/
static void
reference_unknown(xml_reader_t *h, xml_reader_entity_t *e)
{
    xml_reader_cbparam_t cbp;

    /// @todo flag to callback_init which location to use? if so, move curloc back to handle
    /// and just save/restore the position when new input is added or removed
    xml_reader_callback_init(h, XML_READER_CB_ENTITY_UNKNOWN, &cbp);
    cbp.loc = h->refloc;
    cbp.entity.type = e->type;
    cbp.entity.name = e->name;
    xml_reader_callback_invoke(h, &cbp);
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
    // to start characters which will not be recognized by xml_read_until.
    inp->inc_in_literal = true;
    inp->ignore_references = true;
    inp->charref = true;

    // Character reference, even if it evaluates to a whitespace character, does
    // not match the S production.
    h->cdata_ws = false;
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
    @param arg Argument to @a refops->condread
    @return Status why the parser terminated
*/
static xru_t
xml_read_until_parseref(xml_reader_t *h, const xml_reference_ops_t *refops, void *arg)
{
    enum xml_reader_reference_e reftype = XML_READER_REF_NONE; // No reference yet
    xml_reader_saved_token_t tk_content, tk_ref;
    xru_t stopstatus;
    xml_reader_entity_t *e;
    xml_reader_entity_t fakeent;
    const char *saved_relevant;
    uint32_t saved_flags;

    // Unused initially
    tk_content.reserved = false;
    tk_ref.reserved = false;

    saved_flags = h->flags;
    while (true) {
        do {
            if (reftype != XML_READER_REF_CHARACTER) {
                // For normalization checking, character references are considered a part
                // of the construct they belong to.
                // "... and by then verifying that none of the relevant constructs listed
                // above begins (after character references are expanded) with a composing
                // character..."
                h->relevant = refops->relevant;
            }
            h->flags |= refops->flags;
            stopstatus = xml_read_until(h, refops->condread, arg);
            h->flags = saved_flags;
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
        xml_tokenbuf_save(h, &tk_content);
        if (xml_parse_reference(h, &reftype) != PR_OK) {
            // This may or may not be error: PR_NOMATCH may mean that it just wasn't a PE
            // reference despite having started with a percent sign.  If it is an error,
            // no recovery - just interpret anything after error as plain text.
            // No need to restore h->relevant, will be reset anyway in the above loop
            xml_tokenbuf_release(h, &tk_content); // continue gathering content
            continue;
        }
        h->relevant = saved_relevant;

        // Save current token (entity name) into reference token
        xml_tokenbuf_save(h, &tk_ref);

        e = NULL;
        switch (reftype) {
        case XML_READER_REF_GENERAL:
        case XML_READER_REF_PE:
            if ((e = xml_entity_get(h, &tk_ref, reftype == XML_READER_REF_PE)) == NULL) {
                goto unknown_entity;
            }
            reftype = e->type;
            break;

        unknown_entity:
            /* Create a fake entity record */
            memset(&fakeent, 0, sizeof(fakeent));
            xml_tokenbuf_setcbtoken(h, &tk_ref, &fakeent.name);
            fakeent.type = reftype;
            e = &fakeent;
            break;

        default:
            OOPS_ASSERT(reftype == XML_READER_REF_CHARACTER);
            /* Parse the character referenced */
            if (h->charrefval == UCS4_NOCHAR) {
                // Did not evaluate to a character; recover by skipping.
                xml_reader_message_ref(h, XMLERR(ERROR, XML, P_CharRef),
                        "Character reference did not evaluate to a valid "
                        "UCS-4 code point");
                reftype = XML_READER_REF_NONE;
                break;
            }
            if (!xml_valid_char_reference(h, h->charrefval)) {
                // Recover by skipping invalid character.
                xml_reader_message_ref(h, XMLERR(ERROR, XML, P_CharRef),
                        "Referenced character does not match Char production");
                reftype = XML_READER_REF_NONE;
                break;
            }
            memset(&fakeent, 0, sizeof(fakeent));
            fakeent.type = XML_READER_REF_CHARACTER;
            fakeent.rplc = &h->charrefval;
            fakeent.rplclen = sizeof(h->charrefval);
            e = &fakeent;
            break;
        }

        if (!e) {
            // Do nothing; there was some previously signaled error
        }
        else if (e->being_parsed) {
            xml_reader_message_ref(h, XMLERR(ERROR, XML, WFC_NO_RECURSION),
                    "Parsed entity may not contain a recursive reference to itself");
            xml_reader_message(h, &e->included, XMLERR_NOTE,
                    "This is the location of previous inclusion");
        }
        else {
            // Flags setting in refops should've prevented us from recognizing this reference
            OOPS_ASSERT(refops->hnd[e->type]);
            refops->hnd[e->type](h, e);
        }

        // Release the saved tokens (dropping the reference name & continuing gathering content)
        xml_tokenbuf_release(h, &tk_ref);
        xml_tokenbuf_release(h, &tk_content);
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
        [XML_READER_REF_PE] = reference_unknown,
        [XML_READER_REF_PE_INTERNAL] = reference_included_as_pe,
        [XML_READER_REF_PE_EXTERNAL] = reference_included_as_pe,
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

    // Whitespace may cross entity boundaries; repeat until we get something other
    // than whitespace
    (void)xml_read_until_parseref(h, &reference_ops_PEReference, &had_ws);
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
    OOPS_ASSERT(h->ctx->whitespace);
    return h->ctx->whitespace(h);
}


/// Callback state for literal reading
typedef struct xml_cb_literal_state_s {
    /// UCS4_NOCHAR at start, quote seen in progress, or UCS4_STOPCHAR if saw final quote
    ucs4_t quote;
    /// Reader handle (need to check the state of the current input
    xml_reader_t *h;
    /// Deferred setting of 'relevant construct'
    bool starting;
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
        if (cp != st->quote || STAILQ_FIRST(&st->h->active_input)->inc_in_literal) {
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
    ucs4_t oquote, rv;

    oquote = st->quote;
    rv = xml_cb_literal(arg, cp);
    if (oquote == UCS4_NOCHAR && st->quote != UCS4_NOCHAR) {
        // the *next* character starts a relevant construct, unless it is a closing quote
        st->starting = true;
    }
    else if (oquote != UCS4_NOCHAR && st->quote == UCS4_STOPCHAR) {
        // If literal was empty, it is not subject to 'relevant construct' check
        st->h->relevant = NULL;
    }
    else if (st->starting) {
        st->h->relevant = "parsed entity value";
        st->starting = false;
    }
    return rv;
}

// Assumptions relied upon by xml_cb_literal_EntityValue
UCS4_ASSERT(does_not_compose_with_preceding, ucs4_fromlocal('"'))
UCS4_ASSERT(does_not_compose_with_preceding, ucs4_fromlocal('\''))

/// Virtual methods for reading "pseudo-literals" (quoted strings in XMLDecl)
static const xml_reference_ops_t reference_ops_pseudo = {
    .errinfo = XMLERR(ERROR, XML, P_XMLDecl), /// @todo differentiate P_XMLDecl vs P_TextDecl?
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
    .hnd = {
        /* Default: 'Not recognized' */
        [XML_READER_REF_GENERAL] = reference_unknown,
        [XML_READER_REF_INTERNAL] = reference_included_in_literal,
        [XML_READER_REF_EXTERNAL] = reference_forbidden,
        [XML_READER_REF_UNPARSED] = reference_forbidden,
        [XML_READER_REF_CHARACTER] = reference_included_charref,
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
/// way so that R_ASCII may also make use of that approach? Also,
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
    .hnd = {
        [XML_READER_REF_PE] = reference_forbidden,
        [XML_READER_REF_PE_INTERNAL] = reference_forbidden,
        [XML_READER_REF_PE_EXTERNAL] = reference_forbidden,
        [XML_READER_REF_GENERAL] = reference_bypassed,
        [XML_READER_REF_INTERNAL] = reference_bypassed,
        [XML_READER_REF_EXTERNAL] = reference_bypassed,
        [XML_READER_REF_UNPARSED] = reference_error,
        [XML_READER_REF_CHARACTER] = reference_included_charref,
    },
};

/// Virtual methods for reading entity value (EntityValue production) in external subset
static const xml_reference_ops_t reference_ops_EntityValue_external = {
    .errinfo = XMLERR(ERROR, XML, P_EntityValue),
    .condread = xml_cb_literal_EntityValue,
    .flags = R_RECOGNIZE_REF | R_RECOGNIZE_PEREF | R_SAVE_UCS4,
    .relevant = NULL,
    .hnd = {
        [XML_READER_REF_PE] = reference_unknown,
        [XML_READER_REF_PE_INTERNAL] = reference_included_in_literal,
        [XML_READER_REF_PE_EXTERNAL] = reference_included_in_literal,
        [XML_READER_REF_GENERAL] = reference_bypassed,
        [XML_READER_REF_INTERNAL] = reference_bypassed,
        [XML_READER_REF_EXTERNAL] = reference_bypassed,
        [XML_READER_REF_UNPARSED] = reference_error,
        [XML_READER_REF_CHARACTER] = reference_included_charref,
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
    xml_reader_input_t *inp;
    xmlerr_loc_t startloc;
    xml_cb_literal_state_t st;

    // Literals are always inside a locked production (element/XMLDecl/EntityDecl/...)
    inp = STAILQ_FIRST(&h->active_input);
    OOPS_ASSERT(inp);
    startloc = inp->curloc;
    // xml_read_until() may return 0 (empty literal), which is valid
    st.quote = UCS4_NOCHAR;
    st.h = h;
    st.starting = false;
    if (xml_read_until_parseref(h, refops, &st) != XRU_STOP
            || st.quote != UCS4_STOPCHAR) {
        xml_reader_message(h, &startloc, refops->errinfo,
                st.quote == UCS4_NOCHAR ? "Quoted literal expected" : "Unterminated literal");
        return PR_FAIL;
    }
    return PR_OK;
}

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
    xml_reader_external_t *ex = h->current_external;
    const utf8_t *str = h->tokenbuf.start + h->svtk.value.offset;
    size_t sz = h->svtk.value.len;
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

    @param h Reader handle
    @return Nothing
*/
static void
check_EncName(xml_reader_t *h)
{
    xml_reader_external_t *ex = h->current_external;
    const utf8_t *str = h->tokenbuf.start + h->svtk.value.offset;
    size_t sz = h->svtk.value.len;
    const utf8_t *s;
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

    @param h Reader handle
    @return Nothing
*/
static void
check_SD_YesNo(xml_reader_t *h)
{
    const utf8_t *str = h->tokenbuf.start + h->svtk.value.offset;
    size_t sz = h->svtk.value.len;

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
    /// @todo  have a macro to combine spec/code, so that severity can be added later;
    /// use here and in other ecode/errcode fields; go over places invoking
    /// P_XMLDecl code and convert to use this via h->declinfo->errcode
    .errcode = XMLERR(ERROR, XML, P_XMLDecl),
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
    .errcode = XMLERR(ERROR, XML, P_XMLDecl),
    .attrlist = (const struct xml_reader_xmldecl_attrdesc_s[]){
        { "version", true, check_VersionInfo },
        { "encoding", false, check_EncName },
        { "standalone", false, check_SD_YesNo },
        { NULL, false, NULL },
    },
};

/**
    Trivial parser: always returns 'Not matching'.

    @param h Reader handle
    @return Always PR_NOMATCH
*/
static prodres_t
xml_parse_nomatch(xml_reader_t *h)
{
    return PR_NOMATCH;
}

/**
    Start parsing XMLDecl/TextDecl if one is present.

    @verbatim
    XMLDecl      ::= '<?xml' VersionInfo EncodingDecl? SDDecl? S? '?>'
    TextDecl     ::= '<?xml' VersionInfo? EncodingDecl S? '?>'
    @endverbatim

    @param h Reader handle
    @return PR_NOMATCH if declaration is not found, PR_OK if start is parsed
        successfully (switches to pseudo-attribute parsing in that case).
*/
static prodres_t
xml_parse_decl_start(xml_reader_t *h)
{
    // We know '<?xml' is here, but it must be followed by a whitespace
    // so that it can be distinguished from a XML PI, e.g. '<?xml-model'.
    // If we don't get enought characters to tell, consider it a no-match
    // (as we don't know whether it is a truncated declaration or PI).
    if (h->labuf.len < 6 || !xml_is_whitespace(h->labuf.start[5])) {
        return PR_NOMATCH;
    }

    // Ok, this is a declaration.
    // We know it's there, checked above
    xml_read_string_assert(h, "<?xml");
    h->declattr = h->declinfo->attrlist; // Currently expected attribute
    (void)xml_parse_whitespace(h); // checked above
    h->attr_ws = true;
    h->ctx = &parser_decl_attributes;
    return PR_OK;
}

/**
    Parse pseudo-attributes in XMLDecl/TextDecl.

    @verbatim
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
    @return PR_NOMATCH if declaration is not found, PR_OK if start is parsed
        successfully (switches to pseudo-attribute parsing in that case).
*/
static prodres_t
xml_parse_decl_attr(xml_reader_t *h)
{
    const xml_reader_xmldecl_attrdesc_t *attr;
    utf8_t *name;

    /// @todo Enhance error messages to show which exact pseudo-attribute(s) were expected
    if (!h->attr_ws) {
        xml_reader_message_current(h, h->declinfo->errcode,
                "Malformed %s: expect whitespace or ?> here",
                h->declinfo->name);
        return PR_FAIL;
    }

    if (xml_read_Name(h) != PR_OK) {
        xml_reader_message_current(h, h->declinfo->errcode,
                "Malformed %s: expect pseudo-attribute name or ?> here",
                h->declinfo->name);
        return PR_FAIL;
    }
    xml_tokenbuf_save(h, &h->svtk.name);

    // Go through the remaining attributes and see if this one is known
    // (and if we skipped any mandatory attributes while advancing).
    name = h->tokenbuf.start + h->svtk.name.offset;
    for (attr = h->declattr; attr->name; attr++) {
        if (h->svtk.name.len == strlen(attr->name)
                && utf8_eqn(name, attr->name, h->svtk.name.len)) {
            break; // Yes, that is what we expect
        }
        if (attr->mandatory) {
            // Non-fatal: continue with next pseudo-attributes
            xml_reader_message_lastread(h, h->declinfo->errcode,
                    "Mandatory pseudo-attribute '%s' missing in %s",
                    attr->name, h->declinfo->name);
        }
    }

    if (!attr->name) {
        // Non-fatal: continue parsing as if matching the following production
        //   Name Eq ('"' (Char - '"')* '"' | "'" (Char - "'")* "'")
        xml_reader_message_lastread(h, h->declinfo->errcode,
                "Malformed %s: unexpected pseudo-attribute",
                h->declinfo->name);
    }

    // Parse Eq production
    (void)xml_parse_whitespace(h);
    if (xml_read_string(h, "=", h->declinfo->errcode) != PR_OK) {
        // Already complained
        return PR_FAIL;
    }
    (void)xml_parse_whitespace(h);
    if (xml_parse_literal(h, &reference_ops_pseudo) != PR_OK) {
        // Already complained
        return PR_FAIL;
    }
    xml_tokenbuf_save(h, &h->svtk.value);

    if (attr->name) {
        attr->check(h);
        h->declattr = attr + 1; // Expect the next attribute after this
    }
    else {
        h->declattr = attr; // Expect nothing else, stay at the end marker
    }
    h->attr_ws = xml_parse_whitespace(h) == PR_OK;
    return PR_OK;
}

/**
    Finish parsing XMLDecl/TextDecl.

    @verbatim
    XMLDecl      ::= '<?xml' VersionInfo EncodingDecl? SDDecl? S? '?>'
    TextDecl     ::= '<?xml' VersionInfo? EncodingDecl S? '?>'
    @endverbatim

    @param h Reader handle
    @return PR_OK (emits errors but recovers)
*/
static prodres_t
xml_parse_decl_end(xml_reader_t *h)
{
    const xml_reader_xmldecl_attrdesc_t *attr;
    xml_reader_cbparam_t cbp;

    xml_read_string_assert(h, "?>");
    for (attr = h->declattr; attr->name; attr++) {
        if (attr->mandatory) {
            // No recovery: just assume the default
            xml_reader_message_lastread(h, h->declinfo->errcode,
                    "Mandatory pseudo-attribute '%s' missing in %s",
                    attr->name, h->declinfo->name);
        }
    }
    /// @todo Do away with XML declaration reporting? doesn't seem to have any
    /// value for consumer, and standalone status does not make sense except
    /// in doc entity. Instead, provide interfaces to query it via API?
    xml_reader_callback_init(h, XML_READER_CB_XMLDECL, &cbp);
    cbp.xmldecl.encoding = h->current_external->enc_declared;
    cbp.xmldecl.version = h->current_external->version;
    cbp.xmldecl.standalone = h->standalone;
    xml_reader_callback_invoke(h, &cbp);
    h->declattr = NULL;
    return PR_STOP;
}

/**
    Callback to find the end of the character data.

    @param arg Reader handle cast to void pointer
    @param cp Current codepoint
    @return Nothing
*/
static ucs4_t
xml_cb_CharData(void *arg, ucs4_t cp)
{
    xml_reader_t *h = arg;

    /// @todo need to check if the content matches ']]>' token and raise an error if it does
    if (!ucs4_cheq(cp, '<') || STAILQ_FIRST(&h->active_input)->charref) {
        if (h->cdata_ws && !xml_is_whitespace(cp)) {
            h->cdata_ws = false;
        }
        return cp;
    }
    return UCS4_STOPCHAR;
}

/// Virtual methods for reading CharData production
static const xml_reference_ops_t reference_ops_CharData = {
    .errinfo = XMLERR(ERROR, XML, P_CharData),
    .condread = xml_cb_CharData,
    .flags = R_RECOGNIZE_REF,
    .relevant = "CharData",
    .hnd = {
        /* Default: 'Not recognized' */
        [XML_READER_REF_GENERAL] = reference_unknown,
        [XML_READER_REF_INTERNAL] = reference_included,
        [XML_READER_REF_EXTERNAL] = reference_included_if_validating,
        [XML_READER_REF_UNPARSED] = reference_forbidden,
        [XML_READER_REF_CHARACTER] = reference_included_charref,
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
    (void)xml_read_until_parseref(h, &reference_ops_CharData, h);
    return PR_OK;
}

/// State structure for comment backtrack handler
typedef struct {
    xml_reader_t *h;    ///< Reader handle
    bool warned;        ///< 1 error per comment
} comment_backtrack_handler_t;

/**
    If comment parser backtracks after 2 characters (--), it is an error:
    For compatibility, the string "--" (double-hyphen) MUST NOT occur within
    comments. This function is called whenever the match position advances
    or retracts.

    @param arg State structure
    @param oldpos Old position in the matched template
    @param newpos New position in the matched template
    @return Nothing
*/
static void
cb_matchpos_comment(void *arg, size_t oldpos, size_t newpos)
{
    comment_backtrack_handler_t *cbh = arg;

    if (oldpos == 2 && newpos < oldpos && !cbh->warned) {
        // Backtracking after having matched double hyphen
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

    xml_read_string_lock(h, "<!--", LOCKER_COMMENT);

    cbh.h = h;
    cbh.warned = false;
    if (xml_read_termstring(h, &termstring_comment, cb_matchpos_comment, &cbh) != PR_OK) {
        // no need to recover (EOF)
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_Comment),
                "Unterminated comment");
        xml_reader_input_unlock_assert(h); // Entities not recognized
        return PR_FAIL;
    }
    xml_tokenbuf_save(h, &h->svtk.value);

    xml_reader_callback_init(h, XML_READER_CB_COMMENT, &cbp);
    xml_tokenbuf_setcbtoken(h, &h->svtk.value, &cbp.comment.text);
    xml_reader_callback_invoke(h, &cbp);

    xml_reader_input_unlock_assert(h); // Entities not recognized
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

    xml_read_string_lock(h, "<?", LOCKER_PI);

    if (xml_read_Name(h) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_PI),
                "Expected PI target here");
        xml_reader_input_unlock_assert(h); // No recognized entities
        return PR_FAIL;
    }
    xml_tokenbuf_save(h, &h->svtk.name);
    /// @todo Check for XML-reserved names ([Xx][Mm][Ll]*)

    // Content, if any, must be separated by a whitespace.
    // We could only have closing ?> if there's no whitespace after PI target.
    // There is no content in this case.
    if (xml_parse_whitespace(h) == PR_OK) {
        // Whitespace; everything up to closing ?> is the content
        if (xml_read_termstring(h, &termstring_pi, NULL, NULL) == PR_OK) {
            xml_tokenbuf_save(h, &h->svtk.value);
        }
        else {
            xml_reader_message_current(h, XMLERR(ERROR, XML, P_PI),
                    "Unterminated processing instruction");
            xml_reader_input_unlock_assert(h); // No recognized entities
            return PR_FAIL;
        }
    }
    else if (xml_read_string(h, "?>", XMLERR(ERROR, XML, P_PI)) != PR_OK) {
        // Recover by skipping until closing angle bracket
        xml_reader_input_unlock_assert(h); // No recognized entities
        return PR_FAIL;
    }

    xml_reader_callback_init(h, XML_READER_CB_PI, &cbp);
    xml_tokenbuf_setcbtoken(h, &h->svtk.name, &cbp.pi.target);
    xml_tokenbuf_setcbtoken(h, &h->svtk.value, &cbp.pi.content);

    // "The XML Notation mechanism may be used for formal declaration of PI targets"
    // If it was, report notation's system and public IDs.
    if ((n = xml_notation_get(h, &h->svtk.name)) != NULL) {
        TOKEN_FROM_CHAR(&cbp.pi.nsystem_id, n->loader_info.system_id);
        TOKEN_FROM_CHAR(&cbp.pi.npublic_id, n->loader_info.public_id);
    }
    xml_reader_callback_invoke(h, &cbp);

    xml_reader_input_unlock_assert(h); // No recognized entities
    return PR_OK;
}

/// Terminator string description for CData closing tag: ']]>'
static const xml_termstring_desc_t termstring_cdata = {
    .str = "]]>",
    .len = 3,
    .failtab = (const size_t[3]){ 0, 1, 0 },
};

/**
    Turn off normalization check when matching the closing markup for CDSect
    and turn it back on when backtracking.

    @param arg Reader handle, cast to void pointer
    @param oldpos Old position in the matched template
    @param newpos New position in the matched template
    @return Nothing
*/
static void
cb_matchpos_cdata(void *arg, size_t oldpos, size_t newpos)
{
    xml_reader_t *h = arg;
    bool rv;
    size_t i;

    if (newpos && !oldpos) {
        // Starting matching the closing markup
        h->flags |= R_NO_INC_NORM;
    }
    else if (newpos < oldpos) {
        // Backtracking
        if (!newpos) {
            h->flags &= ~R_NO_INC_NORM; // Back to parsing regular content
        }
        // Supply skipped characters to include checker
        if (h->norm_include) {
            for (i = 0; i < oldpos - newpos; i++) {
                rv = nfc_check_nextchar(h->norm_include, ucs4_fromlocal(']'));
                OOPS_ASSERT(rv);
            }
        }
    }
}

// Assumption from the above character
UCS4_ASSERT(does_not_compose, ucs4_fromlocal(']'));

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
    // CDSect is considered an escape mechanism; the markup before and after
    // is not subject to include normalization check.
    h->flags |= R_NO_INC_NORM;
    xml_read_string_lock(h, "<![CDATA[", LOCKER_CDATA);
    h->flags &= ~R_NO_INC_NORM;

    // Starting CData - which is relevant construct
    h->relevant = "CData";
    if (xml_read_termstring(h, &termstring_cdata, cb_matchpos_cdata, h) != PR_OK) {
        xml_tokenbuf_flush_text(h); // Salvage as much already read text as possible
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_CDSect),
                "Unterminated CDATA section");
        xml_reader_input_unlock_assert(h); // No recognized entities
        h->flags &= ~R_NO_INC_NORM; // Set in callback when parsing closing markup
        h->relevant = NULL;
        return PR_FAIL;
    }
    h->flags &= ~R_NO_INC_NORM; // Set in callback when parsing closing markup
    h->relevant = NULL;
    h->cdata_ws = false; // CDATA is never considered matching S non-terminal

    xml_reader_input_unlock_assert(h); // No recognized entities
    return PR_OK;
}

/**
    Parse an ExternalID or PublicID production preceded by a whitespace (S). Upon entry,
    h->rejected must contain the first character of (presumably) external ID.

    @param h Reader handle
    @param allowed_PublicID If true, PublicID production is allowed. In that case, this
        function may also consume the whitespace following the PubidLiteral.
    @return PR_OK if parsed either of these productions; PR_FAIL if parsing error was
        detected or PR_NOMATCH if there was no whitespace or it was not followed by 'S'
        or 'P' characters. In case of PR_NOMATCH, whitespace is consumed.
*/
static prodres_t
xml_parse_ExternalID(xml_reader_t *h, bool allowed_PublicID)
{
    bool has_public_id = false;

    // 'SYSTEM' ... or 'PUBLIC' ...
    if (ucs4_cheq(h->rejected, 'S')) {
        if (xml_read_string(h, "SYSTEM", XMLERR(ERROR, XML, P_ExternalID)) != PR_OK) {
            return PR_FAIL;
        }
    }
    else if (ucs4_cheq(h->rejected, 'P')) {
        if (xml_read_string(h, "PUBLIC", XMLERR(ERROR, XML, P_ExternalID)) != PR_OK) {
            return PR_FAIL;
        }
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
        xml_tokenbuf_save(h, &h->svtk.pubid);
    }

    // System ID is always allowed (though may not be always present, i.e. in notation declaration)
    if (allowed_PublicID && has_public_id) {
        // May be missing second (system) literal, but it's ok
        if (xml_parse_whitespace_conditional(h) != PR_OK) {
            return PR_OK;
        }
        if (!ucs4_cheq(h->rejected, '"') && !ucs4_cheq(h->rejected, '\'')) {
            return PR_OK;
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
    xml_tokenbuf_save(h, &h->svtk.sysid);
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
    xml_read_recover(h, ">");
    xml_read_string(h, ">", XMLERR_NOERROR);
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
    xml_read_recover(h, ">");
    xml_read_string(h, ">", XMLERR_NOERROR);
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
    xml_reader_unknown_entity_t *ue = NULL;
    xml_reader_entity_t *e = NULL;
    xml_reader_notation_t *n = NULL;
    xml_reader_entity_t *eold;
    const xml_predefined_entity_t *predef;
    bool parameter = false;
    size_t i, j;
    const char *s;
    ucs4_t *rplc;
    prodres_t rv;

    // ['<!ENTITY' S]
    xml_read_string_lock(h, "<!ENTITY", LOCKER_ENTITY_DECL);

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
        parameter = true;
        if (xml_parse_whitespace_conditional(h) != PR_OK) {
            xml_reader_message_current(h, XMLERR(ERROR, XML, P_EntityDecl),
                    "Expect whitespace here");
            goto malformed;
        }
    }

    // General or parameter, it is followed by [Name S].
    if (xml_read_Name(h) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_EntityDecl),
                "Expect entity name here");
        goto malformed;
    }
    xml_tokenbuf_save(h, &h->svtk.name);

    // If the same entity is declared more than once, the first declaration encountered
    // is binding; at user option, an XML processor MAY issue a warning if entities are
    // declared multiple times.
    // ...
    //  For interoperability, valid XML documents SHOULD declare these [predefined]
    // entities, like any others, before using them.
    if ((eold = xml_entity_get(h, &h->svtk.name, parameter)) != NULL) {
        // We have a previous definition. If it is predefined, we'll verify validity
        // of the replacement text later; predefined entities may be re-declared once
        // by the document without warning. 
        if ((predef = eold->predef) == NULL || eold->declared.src) {
            /// @todo Would be nice to have entity name in the message. Or convert this
            /// to a non-message event and pass in UTF-8?
            xml_reader_message_lastread(h, XMLERR(WARN, XML, ENTITY_REDECLARED),
                    "Redefinition of an entity");
            xml_reader_message(h, &eold->declared, XMLERR_NOTE,
                    "This is the location of the previous definition");
        }
        e = NULL; // Will not create a new definition
    }
    else {
        predef = NULL;
        e = xml_entity_new(h, parameter);
        e->declared = h->prodloc;

        // Check if this general entity was referenced previously. If it was, it must not
        // be defined as unparsed entity.
        if (!parameter) {
            ue = xml_unknown_entity_get(h, &h->svtk.name);
        }
    }

    if (xml_parse_whitespace_conditional(h) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_EntityDecl),
                "Expect whitespace here");
        goto malformed;
    }

    // This may be followed by either [ExternalID], [ExternalID NDataDecl]
    // (only for general entities) or [EntityValue]
    switch ((rv = xml_parse_ExternalID(h, false))) {
    case PR_OK:
        if (e) {
            xml_tokenbuf_set_loader_info(h, &e->loader_info);
        }

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
                if (xml_read_Name(h) != PR_OK) {
                    xml_reader_message_current(h, XMLERR(ERROR, XML, P_EntityDecl),
                            "Expect notation name here");
                    goto malformed;
                }
                xml_tokenbuf_save(h, &h->svtk.ndata);
                if ((n = xml_notation_get(h, &h->svtk.ndata)) == NULL) {
                    xml_reader_message_lastread(h, XMLERR(ERROR, XML, VC_NOTATION_DECLARED),
                            "Notation must be declared");
                    goto malformed;
                }
                if (e) {
                    e->notation = n;
                    e->type = XML_READER_REF_UNPARSED;
                    if (ue) {
                        xml_reader_message_current(h, XMLERR(ERROR, XML, P_EntityRef),
                                "Unparsed entity referenced from another entity value");
                        xml_reader_message(h, &ue->referenced, XMLERR_NOTE,
                                "This is the location of the reference");
                    }
                }
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
                e->type = XML_READER_REF_PE_EXTERNAL;
            }
        }
        break;

    case PR_NOMATCH:
        // Must have EntityValue then
        h->rplc.len = 0;
        if (xml_parse_literal(h, h->ctx->entity_value_parser) != PR_OK) {
            goto malformed;
        }
        xml_tokenbuf_save(h, &h->svtk.value);
        if (predef) {
            // Predefined entity: the definition must be compatible
            /// @todo Some function to compare UCS-4 string to local string? Or use UCS-4 in array
            /// of predefined entities?
            for (i = 0;
                    i < sizeofarray(predef->rplc) && (s = predef->rplc[i]) != NULL;
                    i++) {
                for (j = 0; j < h->rplc.len; j++) {
                    // s is nul-terminated, so end of string is caught here
                    if (ucs4_fromlocal(s[j]) != h->rplc.start[j]) {
                        break;
                    }
                }
                // matched so far, check that it's the end of expected replacement text
                if (j == h->rplc.len && !s[j]) {
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
            eold->declared = h->prodloc;
        }
        if (e) {
            e->rplclen = h->rplc.len * sizeof(ucs4_t);
            rplc = xmalloc(e->rplclen);
            memcpy(rplc, h->rplc.start, e->rplclen);
            e->rplc = rplc;
            e->type = parameter ? XML_READER_REF_PE_INTERNAL : XML_READER_REF_INTERNAL;
        }
        break;

    default:
        OOPS_ASSERT(rv = PR_FAIL);
        goto malformed;
    }

    // Optional whitespace and closing angle bracket
    (void)xml_parse_whitespace_conditional(h);
    if (xml_read_string(h, ">", XMLERR(ERROR, XML, P_EntityDecl)) != PR_OK) {
        goto malformed;
    }
    xml_reader_input_unlock_markupdecl(h);

    if (ue) {
        // This entity is now known
        xml_unknown_entity_delete(h, &h->svtk.name);
    }

    if (e) {
        // No callbacks for redefinitions - first definition is binding
        xml_reader_callback_init(h, XML_READER_CB_ENTITY_DEF, &cbp);
        cbp.entity.type = e->type;
        xml_tokenbuf_setcbtoken(h, &h->svtk.name, &cbp.entity.name);
        xml_tokenbuf_setcbtoken(h, &h->svtk.value, &cbp.entity.text);
        xml_tokenbuf_setcbtoken(h, &h->svtk.sysid, &cbp.entity.system_id);
        xml_tokenbuf_setcbtoken(h, &h->svtk.pubid, &cbp.entity.public_id);
        xml_tokenbuf_setcbtoken(h, &h->svtk.ndata, &cbp.entity.ndata);
        if (n) {
            TOKEN_FROM_CHAR(&cbp.entity.nsystem_id, n->loader_info.system_id);
            TOKEN_FROM_CHAR(&cbp.entity.npublic_id, n->loader_info.public_id);
        }
        xml_reader_callback_invoke(h, &cbp);
    }

    return PR_OK;

malformed:
    if (e) {
        // Remove the entity from the hash
        xml_entity_delete(h, e);
    }
    xml_reader_input_unlock_ignore(h);
    return PR_FAIL;
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
    prodres_t rv;

    xml_read_string_lock(h, "<!NOTATION", LOCKER_NOTATION_DECL);

    if (xml_parse_whitespace_conditional(h) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_NotationDecl),
                "Expect whitespace here");
        goto malformed;
    }
    if (xml_read_Name(h) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_NotationDecl),
                "Expect notation name here");
        goto malformed;
    }
    xml_tokenbuf_save(h, &h->svtk.name);
    if (xml_notation_get(h, &h->svtk.name) != NULL) {
        xml_reader_message_lastread(h, XMLERR(ERROR, XML, VC_UNIQUE_NOTATION_NAME),
                "Given Name must not be declared in more than one notation declaration");
        goto malformed;
    }
    n = xml_notation_new(h);

    if (xml_parse_whitespace_conditional(h) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_NotationDecl),
                "Expect whitespace here");
        goto malformed;
    }

    switch ((rv = xml_parse_ExternalID(h, true))) {
    case PR_OK:
        xml_tokenbuf_set_loader_info(h, &n->loader_info);
        break;

    case PR_NOMATCH:
        // For notations, system and/or public IDs are mandatory
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_NotationDecl),
                "Expect ExternalID or PublicID here");
        goto malformed;

    default:
        // Error already provided
        OOPS_ASSERT(rv = PR_FAIL);
        goto malformed;
    }

    // Optional whitespace and closing angle bracket
    (void)xml_parse_whitespace_conditional(h);
    if (xml_read_string(h, ">", XMLERR(ERROR, XML, P_NotationDecl)) != PR_OK) {
        goto malformed;
    }
    xml_reader_input_unlock_markupdecl(h);

    xml_reader_callback_init(h, XML_READER_CB_NOTATION_DEF, &cbp);
    xml_tokenbuf_setcbtoken(h, &h->svtk.name, &cbp.notation.name);
    xml_tokenbuf_setcbtoken(h, &h->svtk.sysid, &cbp.notation.system_id);
    xml_tokenbuf_setcbtoken(h, &h->svtk.pubid, &cbp.notation.public_id);
    xml_reader_callback_invoke(h, &cbp);
    return PR_OK;

malformed:
    if (n) {
        // Remove the notation from the hash
        xml_notation_delete(h, n);
    }
    xml_reader_input_unlock_ignore(h);
    return PR_FAIL;
}

/**
    Parse declaration separator (DeclSep) which is whitespace or PE reference.

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

    // Consume the opening bracket, if any, before signaling the error: if there
    // is some <>-enclosed markup that we didn't recognize, make sure the recovery
    // advances when it resyncs to opening/closing bracket (DTD parser context do
    // not have lookahead patterns for just the bracket).
    xml_reader_message_current(h, XMLERR(ERROR, XML, P_DeclSep),
            "Invalid content in DTD");
    (void)xml_read_string(h, "<", XMLERR_NOERROR);
    return PR_FAIL;
}

/**
    Parse a conditional section in DTD.

    Context for parsing conditional sections.

    @verbatim
    conditionalSect    ::= includeSect | ignoreSect
    includeSect        ::= '<![' S? 'INCLUDE' S? '[' extSubsetDecl ']]>'
    ignoreSect         ::= '<![' S? 'IGNORE' S? '[' ignoreSectContents* ']]>'
    @endverbatim

    @param h Reader handle
    @return PR_OK (this function does not expect anything besides what's already
        established by lookahead.
*/
static prodres_t
xml_parse_conditionalSect(xml_reader_t *h)
{
    // Conditional sections are only recognized in external subset - where PE references
    // are allowed.
    xml_read_string_lock(h, "<![", LOCKER_CONDITIONAL_SECT);
    (void)xml_parse_whitespace_peref(h); // this also expands PE reference
    h->ctx = &parser_conditional_section;
    return PR_OK;
}

/**
    Parse an included conditional section in DTD.

    @verbatim
    conditionalSect    ::= includeSect | ignoreSect
    includeSect        ::= '<![' S? 'INCLUDE' S? '[' extSubsetDecl ']]>'
    ignoreSect         ::= '<![' S? 'IGNORE' S? '[' ignoreSectContents* ']]>'
    @endverbatim

    @param h Reader handle
    @return PR_OK on success, PR_FAIL on parsing failure
*/
static prodres_t
xml_parse_includeSect(xml_reader_t *h)
{
    xml_read_string_assert(h, "INCLUDE");
    (void)xml_parse_whitespace_peref(h);
    if (xml_read_string(h, "[", XMLERR(ERROR, XML, P_includeSect)) != PR_OK) {
        return PR_FAIL;
    }

    xml_reader_input_is_locked_condsect(h, "[");

    // Switch back to external subset context - now we'll recognize
    // the closure markup in external subset.
    h->condsects_all++;
    h->ctx = &parser_external_subset;
    return PR_OK;
}

/**
    Parse an ignored conditional section in DTD.

    @param h Reader handle
    @return PR_OK on success, PR_FAIL on parsing failure
*/
static prodres_t
xml_parse_ignoreSect(xml_reader_t *h)
{
    xml_read_string_assert(h, "IGNORE");
    (void)xml_parse_whitespace_peref(h);
    if (xml_read_string(h, "[", XMLERR(ERROR, XML, P_includeSect)) != PR_OK) {
        return PR_FAIL;
    }
    xml_reader_input_is_locked_condsect(h, "[");
    h->condsects_ign = h->condsects_all++;
    h->ctx = &parser_ignored_section;
    return PR_OK;
}

/**
    Parse a conditional section where the keyword is neither INCLUDE nor IGNORE.

    @param h Reader handle
    @return PR_OK always (attempts to recover to the next [)
*/
static prodres_t
xml_parse_bad_ignoreSect(xml_reader_t *h)
{
    xml_reader_message_current(h, XMLERR(ERROR, XML, P_conditionalSect),
            "Expect IGNORE or INCLUDE token here");
    if (xml_read_recover(h, "[") == PR_NOMATCH) {
        return PR_FAIL;
    }
    // Consider it ignored section
    (void)xml_read_string(h, "[", XMLERR_NOERROR); // checked above
    xml_reader_input_is_locked_condsect(h, "[");
    h->condsects_ign = h->condsects_all++;
    h->ctx = &parser_ignored_section;
    return PR_OK;
}

/**
    Parse closing markup of an included conditional section.

    @param h Reader handle
    @return PR_OK on success, PR_NOMATCH if there was no opening section
*/
static prodres_t
xml_parse_include_section_closure(xml_reader_t *h)
{
    if (!h->condsects_all) {
        // It's going to fail, we know, just reuse the recovery logic.
        return xml_parse_whitespace_peref_or_recover(h);
    }
    // We remain in external subset context
    xml_read_string_assert(h, "]]>");
    h->condsects_all--;
    xml_reader_input_is_locked_condsect(h, "]]>");
    xml_reader_input_unlock_ignore(h);
    return PR_OK;
}

/**
    Inside an ignored section, account for a closing markup.

    @param h Reader handle
    @return PR_OK (only consumes looked-ahead content)
*/
static prodres_t
xml_parse_ignored_dec(xml_reader_t *h)
{
    xml_read_string_assert(h, "]]>");
    if (--h->condsects_all == h->condsects_ign) {
        // This concludes the ignored part. Unlock the input and switch to external
        // subset context.
        xml_reader_input_is_locked_condsect(h, "]]>");
        xml_reader_input_unlock_ignore(h);
        h->ctx = &parser_external_subset;
        h->condsects_ign = 0;
    }
    return PR_OK;
}

/**
    Inside an ignored section, account for a opening markup.

    @param h Reader handle
    @return PR_OK (only consumes looked-ahead content)
*/
static prodres_t
xml_parse_ignored_inc(xml_reader_t *h)
{
    // One more closing markup to be consumed without returning to external subset context
    xml_read_string_assert(h, "<![");
    h->condsects_all++;
    return PR_OK;
}

/**
    Inside an ignored section, skip content (not matching opening/closing markup).

    @param h Reader handle
    @return PR_OK (only consumes looked-ahead content)
*/
static prodres_t
xml_parse_ignored_skip(xml_reader_t *h)
{
    // Didn't match open/close markup, so skip < or ] if any of them immediately follows
    // so as not to stall the advance.
    if (xml_read_string(h, "<", XMLERR_NOERROR) == PR_NOMATCH
            && ucs4_cheq(h->rejected, ']')) {
        xml_read_string_assert(h, "]");
    }

    // Not a recovery, but similar logic: skip until the next character of a set. But,
    // even if not found, return PR_OK and let the EOF handler process the failure.
    (void)xml_read_recover(h, "]<");
    return PR_OK;
}

/**
    Complain about entities left undefined after processing the DTD.

    @param arg Reader handle cast to void
    @param key String key (entity name)
    @param keylen Length of the string key
    @param payload Hashed payload
    @return Nothing
*/
static void
xml_unknown_entity(void *arg, const void *key, size_t keylen, const void *payload)
{
    xml_reader_t *h = arg;
    const char *entity_name = utf8_strtolocal(key);
    const xml_reader_unknown_entity_t *ue = payload;

    xml_reader_message(h, &ue->referenced, XMLERR(WARN, XML, P_EntityRef),
            "Entity '%s' referenced here is not defined (would be error if this "
            "entity is defined as unparsed)", entity_name);
    utf8_strfreelocal(entity_name);
    strhash_set(h->entities_unknown, key, keylen, NULL);
}

/**
    DTD completion handler

    @param h Reader handle
    @param loc Last location in this DTD, or NULL if it was not loaded (ignored).
    @return Nothing
*/
static void
xml_dtd_on_complete(xml_reader_t *h, const xmlerr_loc_t *loc)
{
    xml_reader_cbparam_t cbp;

    /// @todo if a production yields PR_FAIL while locked (or xml_reader_stop() is called,
    /// the unlock_assert() will fail during xml_reader_delete() when it calls ->on_complete().
    /// - Eliminate completion calls during delete? But need to do in the manner that will close
    ///   the input string buffers
    /// - Evaluate xml_reader_input_unlock_assert() calls and replace them with _ignore or error-
    ///   checking calls to simple unlock()?
    xml_reader_input_unlock_assert(h);

    strhash_foreach(h->entities_unknown, xml_unknown_entity, h);

    // Use current location in including entity
    xml_reader_callback_init(h, XML_READER_CB_DTD_END, &cbp);
    cbp.loc = STAILQ_FIRST(&h->active_input)->curloc;
    xml_reader_callback_invoke(h, &cbp);
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
    (void)xml_parse_whitespace(h); // Only appears in internal subset
    if (xml_read_string(h, ">", XMLERR(ERROR, XML, P_doctypedecl)) != PR_OK) {
        // Restore context for future entities.
        xml_dtd_on_complete(h, NULL);
        return PR_FAIL;
    }

    h->refloc = STAILQ_FIRST(&h->active_input)->curloc; // Input still locked
    entity_include(h, &h->ent_ext_subset, false, &parser_external_subset,
            xml_dtd_on_complete);
    return PR_OK;
}

/**
    Trivial parser: exit from internal subset context when closing bracket is seen.
    Note that it

    @param h Reader handle
    @return Always PR_OK (this function is only called if lookahead confirmed next
        character to be closing bracket)
*/
static prodres_t
xml_end_internal_subset(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;

    /// @todo add matching START_INTERNAL event?
    xml_read_string_assert(h, "]");
    xml_reader_callback_init(h, XML_READER_CB_DTD_END_INTERNAL, &cbp);
    xml_reader_callback_invoke(h, &cbp);

    h->ctx = &parser_document_entity;
    return xml_parse_dtd_end(h);
}

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
    xml_read_string_lock(h, "<!DOCTYPE", LOCKER_DTD);

    // DTD allowed only once and only before the root element
    if (h->flags & (R_HAS_DTD|R_HAS_ROOT)) {
        xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_document),
                "Document type definition not allowed here");
    }
    h->flags |= R_HAS_DTD;

    if (xml_parse_whitespace(h) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_doctypedecl),
                "Expect whitespace here");
        xml_reader_input_unlock_assert(h);
        return PR_FAIL;
    }
    if (xml_read_Name(h) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_doctypedecl),
                "Expect root element type here");
        xml_reader_input_unlock_assert(h);
        return PR_FAIL;
    }
    xml_tokenbuf_save(h, &h->svtk.name);

    if (xml_parse_whitespace(h) == PR_OK) {
        rv = xml_parse_ExternalID(h, false);
        if (rv == PR_FAIL) {
            xml_reader_input_unlock_assert(h);
            return PR_FAIL;
        }
        else if (rv == PR_OK) {
            xml_tokenbuf_set_loader_info(h, &h->ent_ext_subset.loader_info);
        }
    }

    xml_reader_callback_init(h, XML_READER_CB_DTD_BEGIN, &cbp);
    xml_tokenbuf_setcbtoken(h, &h->svtk.name, &cbp.dtd.root);
    xml_tokenbuf_setcbtoken(h, &h->svtk.sysid, &cbp.dtd.system_id);
    xml_tokenbuf_setcbtoken(h, &h->svtk.pubid, &cbp.dtd.public_id);
    xml_reader_callback_invoke(h, &cbp);

    // Ignore optional whitespace before internal subset
    (void)xml_parse_whitespace(h);
    if (ucs4_cheq(h->rejected, '[')) {
        // Internal subset: '[' intSubset ']'
        xml_read_string_assert(h, "[");

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
    @endverbatim

    @param h Reader handle
    @return PR_OK if parsed successfully or recovered, PR_NOMATCH on (unexpected) error
*/
static prodres_t
xml_parse_STag_EmptyElemTag(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;

    // Check the document production: at the top level, only one element is allowed
    if (SLIST_EMPTY(&h->active_locks)) {
        if (h->flags & R_HAS_ROOT) {
            xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_document),
                    "One root element allowed in a document");
        }
        else {
            h->flags |= R_HAS_ROOT;
        }
    }

    xml_read_string_lock(h, "<", LOCKER_ELEMENT);

    if (xml_read_Name(h) != PR_OK) {
        // No valid name - try to recover by skipping until closing bracket
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_STag),
                "Expected element type");
        xml_reader_input_unlock_assert(h); // No recognized entities yet
        return PR_FAIL;
    }
    xml_tokenbuf_save(h, &h->svtk.name);
    xml_reader_input_lock_set_name(h);  // For later check to match ETag

    // Notify the application that a new element has started
    xml_reader_callback_init(h, XML_READER_CB_STAG, &cbp);
    xml_tokenbuf_setcbtoken(h, &h->svtk.name, &cbp.tag.name);
    xml_reader_callback_invoke(h, &cbp);

    // Consume whitespace, if any, and pass that info to further parsers in the
    // attribute-parsing context
    h->attr_ws = xml_parse_whitespace(h) == PR_OK;
    h->ctx = &parser_attributes;
    return PR_OK;
}

/**
    Parse an attribute.

    @verbatim
    Attribute    ::= Name Eq AttValue
    AttValue     ::= '"' ([^<&"] | Reference)* '"' | "'" ([^<&'] | Reference)* "'"
    Eq           ::= S? '=' S?
    @endverbatim

    @param h Reader handle
    @return PR_OK on success or recovery
*/
static prodres_t
xml_parse_attribute(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;

    if (!h->attr_ws) {
        // Try to recover by reading till end of opening tag
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_STag),
                "Expect whitespace, or >, or /> here");
        return PR_FAIL;
    }

    if (xml_read_Name(h) != PR_OK) {
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_STag),
                "Expect attribute name here");
        return PR_FAIL;
    }
    xml_tokenbuf_save(h, &h->svtk.name);

    (void)xml_parse_whitespace(h);
    if (xml_read_string(h, "=", XMLERR(ERROR, XML, P_Attribute)) != PR_OK) {
        // Already complained
        return PR_FAIL;
    }
    (void)xml_parse_whitespace(h);

    if (xml_parse_literal(h, &reference_ops_AttValue) != PR_OK) {
        // Already complained
        return PR_FAIL;
    }
    xml_tokenbuf_save(h, &h->svtk.value);

    xml_reader_callback_init(h, XML_READER_CB_ATTR, &cbp);
    xml_tokenbuf_setcbtoken(h, &h->svtk.name, &cbp.attr.name);
    xml_tokenbuf_setcbtoken(h, &h->svtk.value, &cbp.attr.value);
    xml_reader_callback_invoke(h, &cbp);

    // Prepare for the next parser
    h->attr_ws = xml_parse_whitespace(h) == PR_OK;
    return PR_OK;
}

/**
    Handler for the case when during attribute parser recovery none of the possible
    markup strings is recognized.

    @param h Reader handle
    @return PR_OK if recovery succeeded
*/
static prodres_t
xml_parse_attr_recovery(xml_reader_t *h)
{
    // If we are here, we didn't match > or /> tokens. Thus, any slash that immediately
    // follows is stray - consume it so as not to stall the recovery.
    xml_read_string(h, "/", XMLERR_NOERROR);
    if (xml_read_recover(h, "/>") == PR_OK) {
        return PR_OK; // Found what appears to be STag/EmptyElemTag closure (or we'll get back here)
    }

    // Failed and cannot advance while recovering. Switch back to content/document
    // context, without error (already complained when the failure was detected).
    // Since we cannot advance, it is because the input was locked by start of the
    // tag - so unlock it.
    xml_reader_input_unlock_assert(h);
    h->ctx = SLIST_EMPTY(&h->active_locks) ? &parser_document_entity : &parser_content;
    return PR_OK;
}

/**
    Parse closing markup for STag.

    @verbatim
    STag         ::= '<' Name (S Attribute)* S? '>'
    @endverbatim

    @param h Reader handle
    @return PR_OK on success or recovery
*/
static prodres_t
xml_parse_closing_STag(xml_reader_t *h)
{
    // Just read the mark-up and restore the context. Since we just opened
    // a tag, we're in the content context.
    xml_read_string_assert(h, ">");
    h->ctx = &parser_content;
    return PR_OK;
}

/**
    Parse closing markup for EmptyElemTag.

    @verbatim
    EmptyElemTag ::= '<' Name (S Attribute)* S? '/>'
    @endverbatim

    @param h Reader handle
    @return PR_OK on success or recovery
*/
static prodres_t
xml_parse_closing_EmptyElemTag(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;

    // Event with name unset == used empty element tag.
    xml_read_string_assert(h, "/>");
    xml_reader_callback_init(h, XML_READER_CB_ETAG, &cbp);
    xml_reader_callback_invoke(h, &cbp);

    // Entities are only allowed in attribute value literals, which do their own locking
    xml_reader_input_unlock_assert(h);
    h->ctx = SLIST_EMPTY(&h->active_locks) ? &parser_document_entity : &parser_content;
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
    xml_reader_lock_token_t *l;

    xml_read_string_assert(h, "</");
    // Locked by STag
    if (xml_read_Name(h) != PR_OK) {
        // No valid name - try to recover by skipping until closing bracket.
        // Does not look like a closing tag, so do not unlock the input.
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_ETag),
                "Expected element type");
        return PR_FAIL;
    }
    xml_tokenbuf_save(h, &h->svtk.name);

    (void)xml_parse_whitespace(h); // optional whitespace
    if (xml_read_string(h, ">", XMLERR(ERROR, XML, P_ETag)) != PR_OK) {
        // Not well-formed; do not consider this a closing tag (and skip unlocking)
        return PR_FAIL;
    }

    if ((l = xml_reader_input_is_locked(h)) != NULL) {
        // Check if the name ("element type") is matching with the start tag
        if (l->name_len != h->svtk.name.len
                || memcmp(h->namestorage.start + l->name_offset,
                    h->tokenbuf.start + h->svtk.name.offset, l->name_len)) {
            xml_reader_message_lastread(h, XMLERR(ERROR, XML, WFC_ELEMENT_TYPE_MATCH),
                    "ETag element type does not match STag element type");
            xml_reader_message(h, &l->where, XMLERR_NOTE,
                    "This is the location of the STag");
        }
        xml_reader_input_unlock_assert(h);
        xml_reader_callback_init(h, XML_READER_CB_ETAG, &cbp);
        xml_tokenbuf_setcbtoken(h, &h->svtk.name, &cbp.tag.name);
        xml_reader_callback_invoke(h, &cbp);
    }
    else {
        xml_reader_message_lastread(h, XMLERR(ERROR, XML, P_element),
                "ETag without matching STag");
    }

    // Exited to root level?
    if (SLIST_EMPTY(&h->active_locks)) {
        h->ctx = &parser_document_entity;
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
    return PR_FAIL;
}


/**
    Handler for contexts where EOF is acceptable (i.e. document entity or XMLDecl/TextDecl
    before the declaration start has been read).

    @param h Reader handle
    @return Always PR_STOP
*/
static prodres_t
on_end_stop(xml_reader_t *h)
{
    return PR_STOP;
}

/**
    Handler for EOF while reading the XMLDecl/TextDecl. This is immediate failure,
    as we don't want to end up reading the declaration, in whole or in part, from the
    including entity.

    @param h Reader handle
    @return Always PR_FAIL
*/
static prodres_t
on_end_xmldecl(xml_reader_t *h)
{
    xml_reader_message_current(h, XMLERR(ERROR, XML, P_XMLDecl),
            "Expect pseudo-attribute or ?> here");
    return PR_FAIL;
}

/**
    Handler for EOF in the internal subset.

    @param h Reader handle
    @return PR_FAIL (internal subset is part of document entity - EOF means
        end of parsing)
*/
static prodres_t
on_end_dtd_internal(xml_reader_t *h)
{
    // Only raise the error on completion of the document entity - which we know
    // is the last in the stack.
    xml_reader_message_current(h, XMLERR(ERROR, XML, P_intSubset),
            "Missing closing ] for internal subset");
    xml_reader_input_unlock_assert(h);
    return PR_FAIL;
}

/**
    Handler for EOF while parsing external subset or external parameter entity.

    @param h Reader handle
    @return PR_OK
*/
static prodres_t
on_end_dtd_external(xml_reader_t *h)
{
    xml_reader_lock_token_t *l;

    while ((l = xml_reader_input_is_locked(h)) != NULL) {
        // Some included conditional section has not been closed. If the end-of-input
        // happens before we can determine included/ignored section, or inside the
        // ignored section, it will be handled in other end-of-input handlers
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_includeSect),
                "Unterminated included conditional section");
        xml_reader_message(h, &l->where, XMLERR_NOTE,
                "This is the start of the section");
        xml_reader_input_unlock_ignore(h);
        h->condsects_all--;
    }
    return PR_OK;
}

/**
    Handler for EOF while parsing tags.

    @param h Reader handle
    @return PR_OK
*/
static prodres_t
on_end_tag(xml_reader_t *h)
{
    xml_reader_cbparam_t cbp;
    xml_reader_lock_token_t *l;

    // Input may be locked more than once if more than one tag is not closed
    while ((l = xml_reader_input_is_locked(h)) != NULL) {
        OOPS_ASSERT(l->locker == LOCKER_ELEMENT);
        xml_reader_message_current(h, XMLERR(ERROR, XML, P_element),
                "STag without matching ETag");
        xml_reader_message(h, &l->where, XMLERR_NOTE,
                "This is the location of the STag");
        // Issue "implied ETag" event
        xml_reader_callback_init(h, XML_READER_CB_ETAG, &cbp);
        cbp.loc = STAILQ_FIRST(&h->active_input)->curloc;
        xml_reader_callback_invoke(h, &cbp);
        xml_reader_input_unlock_assert(h);
    }
    h->ctx = SLIST_EMPTY(&h->active_locks) ? &parser_document_entity : &parser_content;
    return PR_OK;
}

/**
    Handler for EOF while reading attributes in STag/EmptyElemTag production.
    Return to content/document parser and forcibly break locks on a locked
    input.

    @param h Reader handle
    @return PR_OK (recovers to content/document parser)
*/
static prodres_t
on_end_attr(xml_reader_t *h)
{
    // Should've switched back to content/document due to closing markup
    xml_reader_message_current(h, XMLERR(ERROR, XML, P_STag),
            "Expect %s, or >, or /> here",
            h->attr_ws ? "attribute name" : "whitespace");

    // Revert to content parsing. Do not unlock (assumes it was STag); the content
    // parser's EOF handler will handle the unlocking.
    h->ctx = &parser_content;
    return on_end_tag(h);
}

/**
    Handler for EOF while parsing conditional section's start markup.

    @param h Reader handle
    @return PR_OK (recovers to content/document parser)
*/
static prodres_t
on_end_conditional_section(xml_reader_t *h)
{
    // This section has been locked but counter is not incremented yet
    xml_reader_message_current(h, XMLERR(ERROR, XML, P_conditionalSect),
            "Expect IGNORE or INCLUDE token here");
    xml_reader_input_unlock_ignore(h);
    h->ctx = &parser_external_subset; // It will handle enclosing sections if any
    return PR_OK;
}

/**
    Handler for EOF while parsing ignored conditional section content.

    @param h Reader handle
    @return PR_OK (recovers to content/document parser)
*/
static prodres_t
on_end_ignored_section(xml_reader_t *h)
{
    xml_reader_lock_token_t *l;

    // Section was locked
    l = xml_reader_input_is_locked(h);
    OOPS_ASSERT(l);

    xml_reader_message_current(h, XMLERR(ERROR, XML, P_ignoreSect),
            "Unterminated ignored conditional section");
    xml_reader_message(h, &l->where, XMLERR_NOTE,
            "This is the start of the section");
    xml_reader_input_unlock_ignore(h);
    h->ctx = &parser_external_subset; // It will handle enclosing sections if any
    h->condsects_ign = 0;
    return PR_OK;
}

/**
    Trivial function: no recovery, this failure is semi-fatal (current entity
    fails to parse).

    @param h Reader handle
    @return Always PR_FAIL
*/
static prodres_t
on_fail_fail(xml_reader_t *h)
{
    return PR_FAIL;
}

/**
    Recovery function searching for closing/opening angle bracket to resync.

    @param h Reader handle
    @return PR_OK if recovery succeeded
*/
static prodres_t
on_fail_resync_bracket(xml_reader_t *h)
{
    // Recovery: stop after closing bracket or before the opening one. Ok if
    // the closing bracket followed right away - xml_read_recover() will skip it
    // so check this condition first
    if (xml_read_recover(h, "><") == PR_OK) {
        if (ucs4_cheq(h->rejected, '>')) {
            (void)xml_read_string(h, ">", XMLERR_NOERROR);
        }
    }

    // Consider this a successful recovery: if xml_read_recover did not
    // find a bracket (i.e. hit the end of input), we'll check the end-of-input
    // next.
    return PR_OK;
}

/**
    Failure while reading conditional section keyword.

    @param h Reader handle
    @return PR_OK if recovery succeeded
*/
static prodres_t
on_fail_conditional_section(xml_reader_t *h)
{
    xml_reader_input_unlock_ignore(h);
    h->ctx = &parser_external_subset;
    return on_fail_resync_bracket(h);
}

/**
    Recovery function if parsing an attribute fails.

    @param h Reader handle
    @return PR_OK if recovery succeeded
*/
static prodres_t
on_fail_attr(xml_reader_t *h)
{
    // Switch to special parser context for recovery
    h->ctx = &parser_attr_recovery;
    return PR_OK;
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
        LOOKAHEAD("<!ELEMENT", xml_parse_elementdecl, 0),
        LOOKAHEAD("<!ATTLIST", xml_parse_AttlistDecl, 0),
        LOOKAHEAD("<!ENTITY", xml_parse_EntityDecl, 0),
        LOOKAHEAD("<!NOTATION", xml_parse_NotationDecl, 0),
        LOOKAHEAD("<?", xml_parse_PI, 0),
        LOOKAHEAD("<!--", xml_parse_Comment, 0),
        LOOKAHEAD("]", xml_end_internal_subset, 0),
        LOOKAHEAD("", xml_parse_whitespace_peref_or_recover, 0),
    },
    .whitespace = xml_parse_whitespace,
    .on_fail = on_fail_resync_bracket,
    .on_end = on_end_dtd_internal,
    .declinfo = NULL,                   // Not used for reading any external entity
    .entity_value_parser = &reference_ops_EntityValue_internal,
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
*/
static const xml_reader_context_t parser_external_subset = {
    .lookahead = {
        LOOKAHEAD("<!ELEMENT", xml_parse_elementdecl, 0),
        LOOKAHEAD("<!ATTLIST", xml_parse_AttlistDecl, 0),
        LOOKAHEAD("<!ENTITY", xml_parse_EntityDecl, 0),
        LOOKAHEAD("<!NOTATION", xml_parse_NotationDecl, 0),
        LOOKAHEAD("<![", xml_parse_conditionalSect, 0),
        LOOKAHEAD("<?", xml_parse_PI, 0),
        LOOKAHEAD("<!--", xml_parse_Comment, 0),
        LOOKAHEAD("]]>", xml_parse_include_section_closure, 0),
        LOOKAHEAD("", xml_parse_whitespace_peref_or_recover, 0),
    },
    .whitespace = xml_parse_whitespace_peref,
    .on_fail = on_fail_resync_bracket,
    .on_end = on_end_dtd_external,
    .declinfo = &declinfo_textdecl,
    .entity_value_parser = &reference_ops_EntityValue_external,
};

/**
    Context for parsing conditional sections.

    @verbatim
    conditionalSect    ::= includeSect | ignoreSect
    includeSect        ::= '<![' S? 'INCLUDE' S? '[' extSubsetDecl ']]>'
    ignoreSect         ::= '<![' S? 'IGNORE' S? '[' ignoreSectContents* ']]>'
    ignoreSectContents ::= Ignore ('<![' ignoreSectContents ']]>' Ignore)*
    Ignore             ::= Char* - (Char* ('<![' | ']]>') Char*)
    @endverbatim
*/
static const xml_reader_context_t parser_conditional_section = {
    .lookahead = {
        LOOKAHEAD("INCLUDE", xml_parse_includeSect, 0),
        LOOKAHEAD("IGNORE", xml_parse_ignoreSect, 0),
        LOOKAHEAD("", xml_parse_bad_ignoreSect, 0),
    },
    .on_fail = on_fail_conditional_section,
    .on_end = on_end_conditional_section,
};

/**
    Context for parsing ignored section's content.

    @verbatim
    ignoreSect         ::= '<![' S? 'IGNORE' S? '[' ignoreSectContents* ']]>'
    ignoreSectContents ::= Ignore ('<![' ignoreSectContents ']]>' Ignore)*
    Ignore             ::= Char* - (Char* ('<![' | ']]>') Char*)
    @endverbatim
*/
static const xml_reader_context_t parser_ignored_section = {
    .lookahead = {
        LOOKAHEAD("]]>", xml_parse_ignored_dec, 0),
        LOOKAHEAD("<![", xml_parse_ignored_inc, 0),
        LOOKAHEAD("", xml_parse_ignored_skip, 0),
    },
    .on_fail = on_fail_fail, // last parser always recovers
    .on_end = on_end_ignored_section,
};

/**
    Expected tokens/handlers for parsing content production.

    Note that content is a recursive production: it may contain element, which in turn
    may contain content. We are processing this in a flat way (substituting loop for
    recursion); instead, we just track the nesting level (to keep track if we're at
    the root level or not). The proper nesting of STag/ETag cannot be checked with
    this approach; it needs to be verified by a higher level, SAX or DOM. Higher level
    is also responsible for checking that both STag/ETag belong to the same input by
    keeping track when entity parsing started and ended.

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
        LOOKAHEAD("<![CDATA[", xml_parse_CDSect, L_NOFLUSHTEXT),
        LOOKAHEAD("<?", xml_parse_PI, 0),
        LOOKAHEAD("<!--", xml_parse_Comment, 0),
        LOOKAHEAD("</", xml_parse_ETag, 0),
        LOOKAHEAD("<", xml_parse_STag_EmptyElemTag, 0),
        LOOKAHEAD("", xml_parse_CharData, L_NOFLUSHTEXT),
    },
    .on_fail = on_fail_resync_bracket,
    .on_end = on_end_tag,
    .declinfo = &declinfo_textdecl,
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
        LOOKAHEAD("<!DOCTYPE", xml_parse_doctypedecl, 0),
        LOOKAHEAD("<?", xml_parse_PI, 0),
        LOOKAHEAD("<!--", xml_parse_Comment, 0),
        LOOKAHEAD("</", xml_parse_ETag, 0),
        LOOKAHEAD("<", xml_parse_STag_EmptyElemTag, 0),
        LOOKAHEAD("", xml_parse_whitespace_or_recover, 0),
    },
    .whitespace = xml_parse_whitespace, // Needed when parsing ExternalID in <!DOCTYPE
    .on_fail = on_fail_resync_bracket,
    .on_end = on_end_tag,
    .declinfo = &declinfo_xmldecl,
};

/**
    Context for parsing attributes and closing markup of the STag/EmptyElemTag
    production.

    @verbatim
    STag         ::= '<' Name (S Attribute)* S? '>'
    EmptyElemTag ::= '<' Name (S Attribute)* S? '/>'
    Attribute    ::= Name Eq AttValue
    AttValue     ::= '"' ([^<&"] | Reference)* '"' | "'" ([^<&'] | Reference)* "'"
    Eq           ::= S? '=' S?
    @endverbatim
*/
static const xml_reader_context_t parser_attributes = {
    .lookahead = {
        LOOKAHEAD("/>", xml_parse_closing_EmptyElemTag, 0),
        LOOKAHEAD(">", xml_parse_closing_STag, 0),
        LOOKAHEAD("", xml_parse_attribute, 0),
    },
    .on_fail = on_fail_attr,
    .on_end = on_end_attr,
};

/**
    Recovery context when parsing fails while parsing attributes
*/
static const xml_reader_context_t parser_attr_recovery = {
    .lookahead = {
        LOOKAHEAD("/>", xml_parse_closing_EmptyElemTag, 0),
        LOOKAHEAD(">", xml_parse_closing_STag, 0),
        LOOKAHEAD("", xml_parse_attr_recovery, 0),
    },
    .on_fail = on_fail_fail, // last parser always recovers
    .on_end = xml_parse_attr_recovery,
};

/**
    Context for parsing the XMLDecl/TextDecl productions.

    @verbatim
    XMLDecl  ::= '<?xml' VersionInfo EncodingDecl? SDDecl? S? '?>'
    TextDecl ::= '<?xml' VersionInfo? EncodingDecl S? '?>'
    @endverbatim
*/
static const xml_reader_context_t parser_decl = {
    .lookahead = {
        LOOKAHEAD("<?xml", xml_parse_decl_start, 0),
        LOOKAHEAD("", xml_parse_nomatch, 0),
    },
    .on_fail = on_fail_fail,
    .on_end = on_end_stop,
};

/**
    Context for parsing the pseudo-attributes in the XMLDecl/TextDecl productions.

    @verbatim
    XMLDecl  ::= '<?xml' VersionInfo EncodingDecl? SDDecl? S? '?>'
    TextDecl ::= '<?xml' VersionInfo? EncodingDecl S? '?>'
    @endverbatim
*/
static const xml_reader_context_t parser_decl_attributes = {
    .lookahead = {
        LOOKAHEAD("?>", xml_parse_decl_end, 0),
        LOOKAHEAD("", xml_parse_decl_attr, 0),
    },
    .on_fail = on_fail_fail,
    .on_end = on_end_xmldecl,
};

/**
    Process entities in input queue.

    @param h Reader handle
    @return Nothing
*/
static prodres_t
xml_reader_process(xml_reader_t *h)
{
    const void *begin, *end;
    const xml_reader_pattern_t *pat;
    size_t tokenbuf_reserved;
    prodres_t rv;

    tokenbuf_reserved = h->tokenbuf.used;

    do {
        memset(&h->svtk, 0, sizeof(h->svtk));
        h->tokenbuf.used = tokenbuf_reserved;
        if (!xml_lookahead(h)) {
            // Handle end-of-input and collect any completed inputs
            xml_tokenbuf_flush_text(h);
            rv = h->ctx->on_end(h);
        }
        else {
            xml_reader_input_complete_notify(h);
            // Look for matching production in this context.
            // xml_lookahead removed completed inputs; can now save location for production start.
            rv = PR_NOMATCH;
            for (pat = h->ctx->lookahead;; pat++) {
                // Last pattern must accept the input
                OOPS_ASSERT(pat < h->ctx->lookahead + MAX_LA_PAIRS);
                OOPS_ASSERT(pat->func);
                if (!pat->patlen || (pat->patlen <= h->labuf.len
                            && !memcmp(h->labuf.start, pat->pattern, pat->patlen))) {
                    if ((pat->flags & L_NOFLUSHTEXT) == 0) {
                        xml_tokenbuf_flush_text(h);
                    }
                    if (!h->tokenbuf.len) {
                        // Starting a new production, set location & prepare
                        h->prodloc = STAILQ_FIRST(&h->active_input)->curloc;
                        h->cdata_ws = true;
                    }
                    rv = pat->func(h);
                    break;
                }
            }
            if (rv == PR_FAIL) {
                // Remove stray token and attempt to recover. If recovery fails,
                // mark the current external input as aborted (didn't consume it all,
                // so certain normal end-of-input checks will not be performed).
                h->tokenbuf.len = 0;
                if ((rv = h->ctx->on_fail(h)) != PR_OK) {
                    h->current_external->aborted = true;
                }
            }
        }
        // Remove completed inputs
        if (xml_reader_input_rptr(h, &begin, &end) == XRU_EOF) {
            break;
        }
    } while (rv == PR_OK && !h->stopping);

    xml_reader_input_complete_notify(h);

    // Restore handle state
    h->tokenbuf.used = tokenbuf_reserved;
    return rv;
}

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

    // Only if input was parsed fully (i.e. not aborted during addition). Use
    // the location in the input - h->prodloc refers to where the last production
    // that used this entity started.
    if (!ex->aborted && !encoding_clean(ex->enc)) {
        xml_reader_message(h, &inp->curloc, XMLERR(ERROR, XML, ENCODING_ERROR),
                "Partial character at the end of input");
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
    if (ex->on_complete) {
        ex->on_complete(h, ex->aborted ? NULL : &inp->curloc);
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
    const xml_reader_context_t *saved_ctx;
    xml_reader_tokens_t saved_svtk;
    xmlerr_loc_t saved_prodloc;
    size_t saved_tlen;
    uint32_t saved_flags;
    xml_reader_external_t *ex;
    xml_reader_input_t *inp;
    xml_reader_initial_xcode_t xc;
    utf8_t adbuf[4];       // 4 bytes for encoding detection, per XML spec suggestion
    size_t bom_len, adsz;
    const encoding_t *enc;
    enum encoding_endian_e endian;
    prodres_t decl_rv;
    bool rv, stopping;

    ex = xmalloc(sizeof(xml_reader_external_t));
    memset(ex, 0, sizeof(xml_reader_external_t));
    ex->buf = buf;
    ex->location = xstrdup(location);
    ex->norm_unicode = NULL;
    ex->aborted = true; // Until we know otherwise
    ex->on_complete = ha->on_complete;

    if (ha->ctx) {
        // Switch context for this external
        ex->saved_ctx = h->ctx;
        h->ctx = ha->ctx;
    }

    STAILQ_INSERT_TAIL(&h->external, ex, link);
    h->current_external = ex;

    inp = xml_reader_input_new(h, ex->location);

    // Immediately lock the input, so that it is not removed even if it is empty.
    // Since declaration parser does not recognize any entities, this is sufficient
    // to prevent the declaration parser from escaping into the including entity.
    xml_reader_input_lock(h, LOCKER_DECLARATION);

    // Try to get the encoding from stream and check for BOM
    memset(adbuf, 0, sizeof(adbuf));
    adsz = strbuf_lookahead(buf, adbuf, sizeof(adbuf));
    if ((enc = encoding_detect(adbuf, adsz, &bom_len)) != NULL) {
        rv = xml_reader_set_encoding(ex, enc);
        OOPS_ASSERT(rv); // This external has no encoding yet, so it cannot fail to switch
        ex->enc_detected = xstrdup(enc->name);
        if (bom_len) {
            strbuf_radvance(buf, bom_len);
        }
    }

    // Transport encoding must follow autodetection: if transport encoding
    // does not specify endianness, we must rely on BOM to get the right handle.
    if (transport_encoding) {
        endian = ex->enc ? encoding_get(ex->enc)->endian : ENCODING_E_ANY;
        if ((enc = encoding_search(transport_encoding, endian)) == NULL) {
            xml_reader_message_current(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                    "Unsupported transport encoding '%s'", transport_encoding);
            goto failed;
        }
        if (!xml_reader_set_encoding(ex, enc)) {
            // Replacing with an incompatible encoding is not possible;
            // the data that has been read previously cannot be trusted.
            xml_reader_message_current(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                    "Transport encoding '%s' incompatible with auto-detected '%s'",
                    transport_encoding, encoding_get(ex->enc)->name);
            goto failed;
        }
        ex->enc_transport = xstrdup(transport_encoding);
    }

    // If no encoding passed from the transport layer, and autodetect didn't help,
    // try UTF-8. UTF-8 is built-in, so it should always work.
    if (!ex->enc) {
        enc = encoding_search("UTF-8", ENCODING_E_ANY);
        OOPS_ASSERT(enc);
        rv = xml_reader_set_encoding(ex, enc);
        OOPS_ASSERT(rv);
    }

    // When we get here, ex->enc has some encoding (autodetect, transport or fallback)
    OOPS_ASSERT(ex->enc);

    // Temporary reader state
    xc.ex = ex;
    xc.la_start = xc.initial;
    xc.la_size = sizeof(xc.initial);
    xc.la_avail = 0;
    xc.la_offs = 0;
    memset(&xc.la_pos, 0, sizeof(xc.la_pos));
    xc.la_pos_idx = 0;
    xc.la_pos_set = false;

    strbuf_realloc(inp->buf, INITIAL_DECL_LOOKAHEAD_SIZE * sizeof(ucs4_t));
    strbuf_setops(inp->buf, &xml_reader_initial_ops, &xc);

    // This field is really per-entity, but we only add entities one at a time
    // and this field is not used after the initial parsing. So, store them
    // in the reader handle instead. Note that for parsing the declaration,
    // the context will be switched, so we won't have the access to it via h->ctx.
    // Only ASCII is allowed in declaration; if run into EOF, do not attempt to
    // go back to the including input.
    // TBD move to hidden_loader_arg and set in invoke_loader?
    OOPS_ASSERT(h->ctx->declinfo); // External entity context must have it
    h->declinfo = h->ctx->declinfo;

    // We're interrupting normal processing; save & restore the relevant parts
    saved_flags = h->flags;
    saved_ctx = h->ctx;
    saved_svtk = h->svtk;
    saved_tlen = h->tokenbuf.len;
    saved_prodloc = h->prodloc;

    // This may be a nested invocation. If that's the case, we may not stop-and-restart;
    // doing so will restart the parser outside of this context - and will produce
    // incorrect tokens.
    /// @todo ideally, this should be reworked to avoid nested call to xml_reader_process:
    /// - Store the saved_* variables above in the xml_reader_t
    /// - Instead of hidden_loader_arg, have this function save the input buffer and metadata
    /// to the handle and perform the initial parsing preparation in invoke_loader.
    /// - Have literals and chardata recognize the entities via pattern matcher rather than
    /// via flags in xml_read_until
    /// - xml_whitespace_peref should then recognize and handle PE references
    /// - Then move the XML declaration parsing into the main loop - start the document entity
    /// (and switch to when parsing included entities) in the declaration context and have it
    /// switch back to saved context afterwards.
    stopping = false;

    // Declaration is supposed to contain only ASCII; replacement text does not include
    // the declaration.
    h->flags = R_ASCII_ONLY | R_NO_INC_NORM;
    h->ctx = &parser_decl;
    do {
        // Defer stopping until after the initial loading - see above
        if (h->stopping) {
            h->stopping = false;
            stopping = true;
        }
        decl_rv = xml_reader_process(h);
    } while (decl_rv == PR_OK); // On completion, PR_STOP is returned. PR_OK means continue.

    if (stopping) {
        h->stopping = true;
    }

    // After processing the declaration, skip over it in the source buffer. The position
    // recorded in transcoder state is the offset of the first non-consumed character.
    strbuf_radvance(buf, xc.la_pos[0]);

    /// Restore
    h->ctx = saved_ctx;
    h->svtk = saved_svtk;
    h->tokenbuf.len = saved_tlen;
    h->prodloc = saved_prodloc;
    h->flags = saved_flags;
    h->declinfo = NULL;

    if (decl_rv == PR_FAIL) {
        // Entity failed to parse in the declaration. Parsing the declaration
        // shouldn't have created any new inputs or loaded new external entities.
        // Keep the entity on the list of inputs which have been parsed.
        goto failed;
    }

    // Done with the temporary buffer: free the memory buffer if it was reallocated
    if (xc.la_start != xc.initial) {
        xfree(xc.la_start);
    }
    strbuf_clear(inp->buf);

    // If a part of the character is stored in the encoding buffer, clean it up. We're
    // going to re-read the content, possibly with a different transcoder - where it may
    // be valid. Even if it is not the case, we don't want the 'invalid character' notification
    // once we start reading the content.
    encoding_reopen(ex->enc);

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
    /// @todo if preloading a DTD, need to avoid triggering this (or preload DTD after this check?)
    if (h->opt.normalization == XML_READER_NORM_DEFAULT) {
        h->opt.normalization = (ex->version == XML_INFO_VERSION_1_0) ?
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
    if (h->opt.normalization == XML_READER_NORM_ON) {
        // Normalization requested. Allocate this external entity's handle (for Unicode
        // normalization check) and, for document entity, global handle (for include
        // normalization check).
        ex->norm_unicode = nfc_create();
        if (!h->norm_include) {
            h->norm_include = nfc_create();
        }
    }

    if (ex->enc_declared) {
        if ((enc = encoding_search(ex->enc_declared, encoding_get(ex->enc)->endian)) == NULL) {
            xml_reader_message_current(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                    "Unsupported declared encoding '%s'", ex->enc_declared);
            // Recover by keeping whatever we used so far
        }
        else if (!xml_reader_set_encoding(ex, enc)) {
            // Encoding should be in clean state - if not, need to fix encoding to not consume
            // excess data.
            xml_reader_message_current(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                    "Declared encoding '%s' incompatible with current encoding '%s'",
                    ex->enc_declared, encoding_get(ex->enc)->name);
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
    if (!bom_len && ex->enc_declared
            && !strcmp(ex->enc_declared, "UTF-16")) {
        // Non-fatal: managed to detect the encoding somehow
        xml_reader_message_current(h, XMLERR(ERROR, XML, ENCODING_ERROR),
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
    enc = encoding_get(ex->enc);
    if (!ex->enc_declared && !ex->enc_transport
            && strcmp(enc->name, "UTF-16")
            && strcmp(enc->name, "UTF-8")) {
        // Non-fatal: recover by using whatever encoding we detected
        xml_reader_message_current(h, XMLERR(ERROR, XML, ENCODING_ERROR),
                "No external encoding information, no encoding in %s, content in %s encoding",
                h->ctx->declinfo->name, enc->name);
    }

    // Set up permanent transcoder
    strbuf_setops(inp->buf, &xml_reader_transcode_ops, ex);
    inp->entity = e;
    inp->external = ex;
    inp->complete = external_entity_end;
    inp->complete_arg = inp;
    inp->inc_in_literal = ha->inc_in_literal;

    // Loaded successfully
    xml_reader_input_unlock_assert(h);
    h->hidden_loader_arg = NULL;
    ex->aborted = false;
    return;

failed:
    // Keep the external in the list of entities we attempted to read, so that
    // the locations for events remain valid. Remove the "completed" input if
    // it is still on the active list (i.e. if it has not been removed due to
    // being empty (with or without declaration), or having a truncated declaration.
    xml_reader_input_unlock_assert(h);
    xml_reader_input_complete(h, inp);
}

/**
    Final checks after completion of the document entity.

    @param h Reader handle
    @param loc Location to be used for end-of-document events, or NULL if document
        entity was not loaded
    @return Nothing
*/
static void
xml_document_on_complete(xml_reader_t *h, const xmlerr_loc_t *loc)
{
    if (loc && !(h->flags & R_HAS_ROOT)) {
        xml_reader_message(h, loc, XMLERR(ERROR, XML, P_document),
                "No root element");
    }
}

/**
    Higher-level interface for loading document entity.

    @param h Reader handle
    @param pubid Entity's public ID
    @param sysid Entity's system ID
    @return Nothing
*/
void
xml_reader_set_document_entity(xml_reader_t *h, const char *pubid, const char *sysid)
{
    // TBD switch to utf8_t in external interfaces?
    if ((h->flags & R_STARTED) == 0) {
        if (sysid) {
            xml_loader_info_set_system_id(&h->ent_document.loader_info,
                    (const utf8_t *)sysid, strlen(sysid));
        }
        if (pubid) {
            xml_loader_info_set_public_id(&h->ent_document.loader_info,
                    (const utf8_t *)pubid, strlen(pubid));
        }
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
xml_reader_message(xml_reader_t *h, const xmlerr_loc_t *loc, xmlerr_info_t info,
        const char *fmt, ...)
{
    xml_reader_cbparam_t cbp;
    xml_reader_input_t *inp;
    va_list ap;

    xml_reader_callback_init(h, XML_READER_CB_MESSAGE, &cbp);
    if (loc) {
        cbp.loc = *loc;
    }
    else if ((inp = STAILQ_FIRST(&h->active_input)) != NULL) {
        /// @todo use prodloc as default (i.e. when NULL is passed)? It is already initialized in cbp
        cbp.loc = inp->curloc;
    }
    cbp.message.info = info;
    va_start(ap, fmt);
    cbp.message.msg = xvasprintf(fmt, ap);
    va_end(ap);
    xml_reader_callback_invoke(h, &cbp);
    xfree(cbp.message.msg);
}

/**
    Process entities in input queue.

    @param h Reader handle
    @return Nothing
*/
void
xml_reader_run(xml_reader_t *h)
{
    prodres_t rv;

    if ((h->flags & R_STARTED) == 0) {
        h->flags |= R_STARTED;
        // @todo when support for DTD preloading is added, load it here as well
        // Load the document entity
        entity_include(h, &h->ent_document, false, &parser_document_entity,
                xml_document_on_complete);
    }

    h->stopping = false; // If stopped previously, we can resume now.
    rv = xml_reader_process(h);

    // In each context, the last parser must catch all and recover
    OOPS_ASSERT(rv != PR_NOMATCH);

    /// @todo Return the parsing success/failure? i.e. if we produced
    /// something (PR_STOP) or failed completely (PR_FAIL)
}

/**
    Stop processing after handling the current production.

    @param h Reader handle
    @return Nothing
*/
void
xml_reader_stop(xml_reader_t *h)
{
    h->stopping = true;
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

    STAILQ_FOREACH(inp, &h->active_input, link) {
        func(arg, &inp->curloc);
    }
}
