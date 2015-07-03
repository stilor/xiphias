/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Handle for reading an XML entity.
*/

#ifndef __xml_reader_h_
#define __xml_reader_h_

#include <stddef.h>
#include <stdint.h>

#include "util/strbuf.h"
#include "unicode/unicode.h"

#include "xml/infoset.h"
#include "xml/loader.h"
#include "xml/xmlerr.h"

// Forward declarations
struct strbuf_s;

/**
    Callback types; discriminates the union for the extra data to the callback
    and defines the meaning of the string contained in .token, if any.
*/
enum xml_reader_cbtype_e {
    // TBD update comments
    /// No message (placeholder/terminator)
    XML_READER_CB_NONE,

    /// Note/warning/error message (extra data in .message)
    XML_READER_CB_MESSAGE,

    /// Encountered unknown entity name (extra data in .entity)
    XML_READER_CB_ENTITY_UNKNOWN,

    /// Entity was not loaded (extra data in .entity)
    XML_READER_CB_ENTITY_NOT_LOADED,

    /// Started parsing an entity (extra data in .entity)
    XML_READER_CB_ENTITY_PARSE_START,

    /// Finished parsing an entity (extra data in .entity)
    XML_READER_CB_ENTITY_PARSE_END,

    /// XML declaration (extra data in .xmldecl)
    XML_READER_CB_XMLDECL,

    /// Beginning of the DTD (extra data in .dtd)
    XML_READER_CB_DTD_BEGIN,

    /// End of the internal subset in DTD (no extra data)
    XML_READER_CB_DTD_END_INTERNAL,

    /// End of the DTD (no extra data)
    XML_READER_CB_DTD_END,

    /// Comment (extra data in .comment)
    XML_READER_CB_COMMENT,

    /// PI target (extra data in .pi)
    XML_READER_CB_PI,

    /// Definition of an entity (extra data in .entity)
    XML_READER_CB_ENTITY_DEF,

    /// Definition of a notation (extra data in .notation)
    XML_READER_CB_NOTATION_DEF,

    /// Append text to current node (extra data in .text)
    XML_READER_CB_TEXT,

    /// Start of element (extra data in .tag)
    XML_READER_CB_STAG,

    /// End of element (extra data in .tag)
    XML_READER_CB_ETAG,

    /// Attribute in an element (extra data in .attr)
    XML_READER_CB_ATTR,

    XML_READER_CB_MAX,             ///< Maximum number of callback types
};

// TBD rename to _ENT_ (these are no longer just references)? but char references are not entities...
/// Types of references
enum xml_reader_reference_e {
    XML_READER_REF_NONE,           ///< Indicates unset reference type
    XML_READER_REF_PE,             ///< Any parameter entity reference (internal/external)
    XML_READER_REF_PE_INTERNAL,    ///< Internal parameter entity reference
    XML_READER_REF_PE_EXTERNAL,    ///< External parameter entity reference
    XML_READER_REF_GENERAL,        ///< Any general entity reference (internal/external/unparsed)
    XML_READER_REF_INTERNAL,       ///< General internal parsed entity reference
    XML_READER_REF_EXTERNAL,       ///< General external parsed entity reference
    XML_READER_REF_UNPARSED,       ///< General unparsed entity reference
    XML_READER_REF_CHARACTER,      ///< Character reference
    XML_READER_REF__MAXREF,        ///< Array size for per-reference-type handlers

    // Entities not loaded by references
    XML_READER_REF_DOCUMENT,       ///< Document entity reference
    XML_READER_REF_EXT_SUBSET,     ///< External subset
};

/// Token (string) associated with event
typedef struct {
    const utf8_t *str;             ///< Token string
    size_t len;                    ///< String length
} xml_reader_token_t;

/**
    Test if token is set

    @param tk Token
    @return true if set
*/
static inline bool
xml_reader_token_isset(const xml_reader_token_t *tk)
{
    return tk->str != NULL;
}

/// Parameter for message callback
typedef struct {
    xmlerr_info_t info;            ///< Error info
    const char *msg;               ///< Error message
} xml_reader_cbparam_message_t;

/// Entity information
typedef struct {
    enum xml_reader_reference_e type;   ///< Entity type
    xml_reader_token_t name;            ///< Entity name
    xml_reader_token_t text;            ///< Replacement text
    xml_reader_token_t system_id;       ///< System ID for external entities
    xml_reader_token_t public_id;       ///< Public ID for external entities
    xml_reader_token_t ndata;           ///< Notation data: name
    xml_reader_token_t nsystem_id;      ///< Notation data: system ID
    xml_reader_token_t npublic_id;      ///< Notation data: public ID
} xml_reader_cbparam_entity_t;

/// Parameter for XML or text declaration callback
typedef struct {
    const char *encoding;                    ///< Encoding from the declaration
    enum xml_info_version_e version;         ///< XML version
    enum xml_info_standalone_e standalone;   ///< Is the document is declared standalone
} xml_reader_cbparam_xmldecl_t;

/// Parameter for start of the DTD callback
typedef struct {
    xml_reader_token_t root;            ///< Root element type
    xml_reader_token_t system_id;       ///< System ID for external entities
    xml_reader_token_t public_id;       ///< Public ID for external entities
} xml_reader_cbparam_dtd_t;

/// Parameter for comment callback
typedef struct {
    xml_reader_token_t text;            ///< Comment text
} xml_reader_cbparam_comment_t;

/// Parameter for processing instruction callback
typedef struct {
    xml_reader_token_t target;          ///< PI target
    xml_reader_token_t content;         ///< PI content
    xml_reader_token_t nsystem_id;      ///< Notation data: system ID
    xml_reader_token_t npublic_id;      ///< Notation data: public ID
} xml_reader_cbparam_pi_t;

/// Parameter for notation definition callback
typedef struct {
    xml_reader_token_t name;            ///< Entity name
    xml_reader_token_t system_id;       ///< System ID for external entities
    xml_reader_token_t public_id;       ///< Public ID for external entities
} xml_reader_cbparam_notation_t;

/// Parameter for text node callback
typedef struct {
    xml_reader_token_t text;            ///< Text value
    bool ws;                            ///< True if this text is pure whitespace
} xml_reader_cbparam_text_t;

/// Parameter for tag start/end callback
typedef struct {
    xml_reader_token_t name;            ///< Element type
} xml_reader_cbparam_tag_t;

/// Parameter for attribute callback
typedef struct {
    xml_reader_token_t name;            ///< Attribute name
    xml_reader_token_t value;           ///< Attribute value
} xml_reader_cbparam_attr_t;

/// Combined callback parameter type
typedef struct {
    enum xml_reader_cbtype_e cbtype;              ///< Callback type
    xmlerr_loc_t loc;                             ///< Location of the event
    union {
        xml_reader_cbparam_message_t message;     ///< Error/warning message
        xml_reader_cbparam_entity_t entity;       ///< Entity info
        xml_reader_cbparam_xmldecl_t xmldecl;     ///< XML or text declaration
        xml_reader_cbparam_dtd_t dtd;             ///< DTD start
        xml_reader_cbparam_comment_t comment;     ///< Comment
        xml_reader_cbparam_pi_t pi;               ///< Processing instruction
        xml_reader_cbparam_notation_t notation;   ///< Attribute
        xml_reader_cbparam_tag_t tag;             ///< Tag start/end
        xml_reader_cbparam_attr_t attr;           ///< Attribute
        xml_reader_cbparam_text_t text;           ///< Text node
    };
} xml_reader_cbparam_t;

/// Normalization check setting
enum xml_reader_normalization_e {
    XML_READER_NORM_DEFAULT,       ///< Default (off for 1.0, on for 1.1)
    XML_READER_NORM_OFF,           ///< Force normalization check off
    XML_READER_NORM_ON,            ///< Force normalization check on
};

/// Opaque handle for reading XML entity
typedef struct xml_reader_s xml_reader_t;

/// Reader callback function type
typedef void (*xml_reader_cb_t)(void *arg, xml_reader_cbparam_t *cbparam);

/// Options for XML reader
typedef struct {
    /// Unicode normalization behavior
    enum xml_reader_normalization_e normalization;
    bool normalization_accept_unknown;  ///< Do not warn about unassigned characters
    bool loctrack;                      ///< Whether location tracking is enabled
    bool load_externals;                ///< Load external entities
    size_t tabsize;                     ///< Tabulation size for location tracking
    size_t entity_hash_order;           ///< Log2(number of hash buckets for entities)
    size_t notation_hash_order;         ///< Log2(number of hash buckets for notations)
    size_t initial_tokenbuf;            ///< Initial size of the token buffer
    size_t initial_namestorage;         ///< Initial size of the namestorage buffer
} xml_reader_options_t;

void xml_reader_opts_default(xml_reader_options_t *opts);

xml_reader_t *xml_reader_new(const xml_reader_options_t *opts);
void xml_reader_delete(xml_reader_t *h);
void xml_reader_set_callback(xml_reader_t *h, xml_reader_cb_t func, void *arg);
void xml_reader_set_loader(xml_reader_t *h, xml_loader_t func, void *arg);

void xml_reader_message(xml_reader_t *h, const xmlerr_loc_t *loc, xmlerr_info_t info,
        const char *fmt, ...) __printflike(4,5);

void xml_reader_set_document_entity(xml_reader_t *h, const char *pubid, const char *sysid);
void xml_reader_add_parsed_entity(xml_reader_t *h, strbuf_t *buf,
        const char *location, const char *transport_encoding);

void xml_reader_run(xml_reader_t *h);
void xml_reader_stop(xml_reader_t *h);

void xml_reader_stack(xml_reader_t *h, void (*func)(void *, const xmlerr_loc_t *), void *arg);

#endif
