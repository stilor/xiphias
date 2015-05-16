/* vi: set ts=5 sw=4 et : */
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
    /// No message (placeholder/terminator)
    XML_READER_CB_NONE,

    /// Note/warning/error message (no token; extra data in .message)
    XML_READER_CB_MESSAGE,

    /// Encountered unknown entity name (token: entity name; extra data in .entity)
    XML_READER_CB_ENTITY_UNKNOWN,

    /// Entity was not loaded (token: entity name; extra data in .entity)
    XML_READER_CB_ENTITY_NOT_LOADED,

    /// Started parsing an entity (token: entity name; extra data in .entity)
    XML_READER_CB_ENTITY_START,

    /// Finished parsing an entity (no token; extra data in .entity)
    XML_READER_CB_ENTITY_END,

    /// Public ID (DTD, entity or notation) (token: public ID; no extra data)
    XML_READER_CB_PUBID,

    /// System ID (DTD, entity or notation) (token: system ID; no extra data)
    XML_READER_CB_SYSID,

    /// Notation data (entity) (token: notation name; no extra data)
    XML_READER_CB_NDATA,

    /// Append text to current node (token: appended string; extra data in .append)
    XML_READER_CB_APPEND,

    /// Append text via CDATA (token: appended string; extra data in .append)
    XML_READER_CB_CDSECT,

    /// XML declaration (no token; extra data in .xmldecl)
    XML_READER_CB_XMLDECL,

    /// Comment (token: content; no extra data)
    XML_READER_CB_COMMENT,

    /// PI target (token: target; extra data in .ndata)
    XML_READER_CB_PI_TARGET,

    /// PI content (token: content; no extra data)
    XML_READER_CB_PI_CONTENT,

    /// Beginning of the DTD (token: root element type; no extra data)
    XML_READER_CB_DTD_BEGIN,

    /// Start of the internal subset in DTD (no token; no extra data)
    XML_READER_CB_DTD_INTERNAL,

    /// End of the DTD (no token; no extra data)
    XML_READER_CB_DTD_END,

    /// Definition of an entity started (token: entity name; extra data in .entitydef)
    XML_READER_CB_ENTITY_DEF_START,

    /// Definition of an entity finished (no token; no extra data)
    XML_READER_CB_ENTITY_DEF_END,

    /// Definition of a notation started (token: entity name; no extra data)
    XML_READER_CB_NOTATION_DEF_START,

    /// Definition of a notation finished (no token; no extra data)
    XML_READER_CB_NOTATION_DEF_END,

    /// Start of element (token: element type; no extra data)
    XML_READER_CB_STAG,

    /// Attribute in an element (token: atttribute name; extra data in .attr)
    XML_READER_CB_ATTR,

    /// Finished element start (no token; extra data in .stag_end)
    XML_READER_CB_STAG_END,

    /// End of element (token: element type; no extra data)
    XML_READER_CB_ETAG,

    XML_READER_CB_MAX,             ///< Maximum number of callback types
};

/// Types of references
enum xml_reader_reference_e {
    // Up to _MAX: references for which rules are defined in XML spec
    // (some of them may be split in subgroups below)
    XML_READER_REF_PE,             ///< Any parameter entity reference (internal/external)
    XML_READER_REF_PE_INTERNAL,    ///< Internal parameter entity reference
    XML_READER_REF_PE_EXTERNAL,    ///< External parameter entity reference
    XML_READER_REF_GENERAL,        ///< Any general entity reference (internal/external/unparsed)
    XML_READER_REF_INTERNAL,       ///< General internal parsed entity reference
    XML_READER_REF_EXTERNAL,       ///< General external parsed entity reference
    XML_READER_REF_UNPARSED,       ///< General unparsed entity reference
    XML_READER_REF_CHARACTER,      ///< Character reference
    XML_READER_REF__MAX,           ///< Array size for per-type handlers

    // Internal values
    XML_READER_REF_DOCUMENT,       ///< Document entity reference
    XML_READER_REF_EXT_SUBSET,     ///< External subset
    XML_READER_REF_NONE,           ///< To indicate unset reference type
};

/// Normalization type for an attribute
enum xml_reader_attrnorm_e {
    XML_READER_ATTRNORM_CDATA,     ///< CDATA attribute (basic normalization)
    XML_READER_ATTRNORM_OTHER,     ///< Any other type (basic + whitespace collapsing)
};

/// Parameter for message callback
typedef struct {
    xmlerr_info_t info;            ///< Error info
    const char *msg;               ///< Error message
} xml_reader_cbparam_message_t;

/// Unexpanded entity, either unknown or external
typedef struct {
    enum xml_reader_reference_e type;   ///< Entity type
    const char *system_id;              ///< System ID for external entities
    const char *public_id;              ///< Public ID for external entities
    void *baton;                        ///< (in) Baton from ENTITY_START to ENTITY_END
} xml_reader_cbparam_entity_t;

/// Parameter for "adding text to a node" callback
typedef struct {
    bool ws;                         ///< True if this text is pure whitespace
} xml_reader_cbparam_append_t;

/// Parameter for XML or text declaration callback
typedef struct {
    enum xml_info_version_e version;         ///< XML version
    const char *encoding;                    ///< Encoding from the declaration
    enum xml_info_standalone_e standalone;   ///< Is the document is declared standalone
} xml_reader_cbparam_xmldecl_t;

/// Parameter for PI target
typedef struct {
    const char *system_id;              ///< System ID for notation, if any
    const char *public_id;              ///< Public ID for notation, if any
} xml_reader_cbparam_ndata_t;

/// Parameter for entity definition start
typedef struct {
    bool parameter;                          ///< True if this is a parameter entity
} xml_reader_cbparam_entitydef_t;

/// Parameter for completion of the start of the element callback
typedef struct {
    bool is_empty;                           ///< Whether this was STag or EmptyElemTag production
} xml_reader_cbparam_stag_end_t;

/// Parameter for attribute name callback
typedef struct {
    enum xml_reader_attrnorm_e attrnorm;     ///< Requested attribute normalization
} xml_reader_cbparam_attr_t;

/// Dummy structure for events with no extra parameters
typedef struct {
} xml_reader_cbparam___dummy_t;

/// Combined callback parameter type
typedef struct {
    enum xml_reader_cbtype_e cbtype;              ///< Callback type
    xmlerr_loc_t loc;                             ///< Location of the event
    struct {
        const utf8_t *str;                        ///< Token associated with the event
        size_t len;                               ///< Length of the token
    } token;                                      ///< Associated token
    union {
        xml_reader_cbparam_message_t message;     ///< Error/warning message
        xml_reader_cbparam_entity_t entity;       ///< Reference to an entity
        xml_reader_cbparam_append_t append;       ///< Text appended to a node
        xml_reader_cbparam_xmldecl_t xmldecl;     ///< XML or text declaration
        xml_reader_cbparam_ndata_t ndata;         ///< XML or text declaration
        xml_reader_cbparam_entitydef_t entitydef; ///< XML or text declaration
        xml_reader_cbparam_stag_end_t stag_end;   ///< Start of element (STag) complete
        xml_reader_cbparam_attr_t attr;           ///< Attribute name
        xml_reader_cbparam___dummy_t __dummy;     ///< Dummy structure
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
    bool loctrack;                      ///< Whether location tracking is enabled
    size_t tabsize;                     ///< Tabulation size for location tracking
    size_t entity_hash_order;           ///< Log2(number of hash buckets for entities)
    size_t notation_hash_order;         ///< Log2(number of hash buckets for notations)
    size_t initial_tokenbuf;            ///< Initial size of the token buffer
} xml_reader_options_t;

void xml_reader_opts_default(xml_reader_options_t *opts);

xml_reader_t *xml_reader_new(const xml_reader_options_t *opts);
void xml_reader_delete(xml_reader_t *h);
void xml_reader_set_callback(xml_reader_t *h, xml_reader_cb_t func, void *arg);
void xml_reader_set_loader(xml_reader_t *h, xml_loader_t func, void *arg);

void xml_reader_message(xml_reader_t *h, xmlerr_loc_t *loc, xmlerr_info_t info,
        const char *fmt, ...) __printflike(4,5);

void xml_reader_load_document_entity(xml_reader_t *h, const char *pubid, const char *sysid);
void xml_reader_add_parsed_entity(xml_reader_t *h, strbuf_t *buf,
        const char *location, const char *transport_encoding);

void xml_reader_process(xml_reader_t *h);

void xml_reader_stack(xml_reader_t *h, void (*func)(void *, const xmlerr_loc_t *), void *arg);

#endif
