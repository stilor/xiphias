/* vi: set ts=5 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Handle for reading an XML entity.
*/

#ifndef __xml_reader_h_
#define __xml_reader_h_

#include <stddef.h>
#include <stdint.h>

#include "util/unicode.h"

#include "infoset.h"
#include "xmlerr.h"

// Forward declarations
struct strbuf_s;

/// Callback types
enum xml_reader_cbtype_e {
    XML_READER_CB_NONE,            ///< No message (placeholder/terminator)
    XML_READER_CB_MESSAGE,         ///< Note/warning/error message
    XML_READER_CB_ENTITY_UNKNOWN,  ///< Encountered unknown entity name
    XML_READER_CB_ENTITY_START,    ///< Started parsing an entity
    XML_READER_CB_ENTITY_END,      ///< Finished parsing an entity
    XML_READER_CB_APPEND,          ///< Append text to current node (text/attribute)
    XML_READER_CB_CDSECT,          ///< Identical to APPEND, in case caller cares
    XML_READER_CB_XMLDECL,         ///< XML declaration
    XML_READER_CB_COMMENT,         ///< Comment
    XML_READER_CB_PI_TARGET,       ///< Processing instruction: target
    XML_READER_CB_PI_CONTENT,      ///< Processing instruction: content
    XML_READER_CB_DTD_BEGIN,       ///< Beginning of a document type declaration
    XML_READER_CB_DTD_END,         ///< End of a document type declaration
    XML_READER_CB_STAG,            ///< Start of element (STag)
    XML_READER_CB_STAG_END,        ///< Start of element (STag) terminated
    XML_READER_CB_ETAG,            ///< End of element (ETag)
    XML_READER_CB_ATTR,            ///< Name of an attribute in an element

    XML_READER_CB_MAX,             ///< Maximum number of callback types
};

/// Types of references
enum xml_reader_reference_e {
    XML_READER_REF_PARAMETER,      ///< Parameter entity reference
    XML_READER_REF_INTERNAL,       ///< Internal parsed entity reference
    XML_READER_REF_EXTERNAL,       ///< External parsed entity reference
    XML_READER_REF_UNPARSED,       ///< Unparsed entity reference
    XML_READER_REF__CHAR,          ///< Internal value: not an entity, character reference
    XML_READER_REF__MAX,           ///< Internal value: array size for per-type handlers
    XML_READER_REF_GENERAL,        ///< Any general entity reference (internal/external/unparsed)
    XML_READER_REF__UNKNOWN,       ///< Internal value: character or general (not yet determined)
};

/// Parameter for message callback
typedef struct {
    xmlerr_info_t info;            ///< Error info
    const char *msg;               ///< Error message
} xml_reader_cbparam_message_t;

/// Unexpanded entity, either unknown or external
typedef struct {
    enum xml_reader_reference_e type;   ///< Entity type
    const utf8_t *name;                 ///< Entity name
    size_t namelen;                     ///< Length of the entity name
    const char *system_id;              ///< System ID for external entities
    const char *public_id;              ///< Public ID for external entities
    void *baton;                        ///< (in) Baton from ENTITY_START to ENTITY_END
} xml_reader_cbparam_entity_t;

/// Parameter for "adding text to a node" callback
typedef struct {
    const utf8_t *text;                      ///< Element type (may not match STag for malformed docs)
    size_t textlen;                          ///< Element type length
} xml_reader_cbparam_append_t;

/// Parameter for XML or text declaration callback
typedef struct {
    enum xml_info_version_e version;         ///< XML version
    const char *encoding;                    ///< Encoding from the declaration
    enum xml_info_standalone_e standalone;   ///< Is the document is declared standalone
} xml_reader_cbparam_xmldecl_t;

/// Comment callback
typedef struct {
    const utf8_t *content;                   ///< Content of the comment
    size_t contentlen;                       ///< Content length
} xml_reader_cbparam_comment_t;

/// PI target
typedef struct {
    const utf8_t *name;                      ///< Content of the comment
    size_t namelen;                          ///< Content length
} xml_reader_cbparam_pi_target_t;

/// PI content
typedef struct {
    const utf8_t *content;                   ///< Content of the comment
    size_t contentlen;                       ///< Content length
} xml_reader_cbparam_pi_content_t;

/// Parameter for start of the element callback
typedef struct {
    const utf8_t *type;                      ///< Element type (name)
    size_t typelen;                          ///< Element type length
} xml_reader_cbparam_stag_t;

/// Parameter for completion of the start of the element callback
typedef struct {
    bool is_empty;                           ///< Whether this was STag or EmptyElemTag production
} xml_reader_cbparam_stag_end_t;

/// Parameter for end of the element callback
typedef struct {
    const utf8_t *type;                      ///< Element type
    size_t typelen;                          ///< Element type length
} xml_reader_cbparam_etag_t;

/// Parameter for attribute name callback
/// @todo Need (in) normalization type, CDATA (default) or NMTOKENS
typedef struct {
    const utf8_t *name;                      ///< Element type (may not match STag for malformed docs)
    size_t namelen;                          ///< Element type length
} xml_reader_cbparam_attr_t;

/// Combined callback parameter type
typedef struct {
    enum xml_reader_cbtype_e cbtype;              ///< Callback type
    xmlerr_loc_t loc;                             ///< Location of the event
    union {
        xml_reader_cbparam_message_t message;     ///< Error/warning message
        xml_reader_cbparam_entity_t entity;       ///< Reference to an entity
        xml_reader_cbparam_append_t append;       ///< Attribute value
        xml_reader_cbparam_xmldecl_t xmldecl;     ///< XML or text declaration
        xml_reader_cbparam_comment_t comment;     ///< Comment
        xml_reader_cbparam_pi_target_t pi_target;      ///< PI target
        xml_reader_cbparam_pi_content_t pi_content;    ///< PI content
        xml_reader_cbparam_stag_t stag;           ///< Start of element (STag)
        xml_reader_cbparam_stag_end_t stag_end;   ///< Start of element (STag) complete
        xml_reader_cbparam_etag_t etag;           ///< End of element (ETag)
        xml_reader_cbparam_attr_t attr;           ///< Attribute name
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

xml_reader_t *xml_reader_new(struct strbuf_s *buf, const char *location);
void xml_reader_delete(xml_reader_t *h);
bool xml_reader_set_transport_encoding(xml_reader_t *h, const char *encname);
bool xml_reader_set_normalization(xml_reader_t *h, enum xml_reader_normalization_e norm);
bool xml_reader_set_location_tracking(xml_reader_t *h, bool onoff, size_t tabsz);
void xml_reader_set_callback(xml_reader_t *h, xml_reader_cb_t func, void *arg);

void xml_reader_message(xml_reader_t *h, xmlerr_loc_t *loc, xmlerr_info_t info,
        const char *fmt, ...) __printflike(4,5);

void xml_reader_process_document_entity(xml_reader_t *h);
void xml_reader_process_external_entity(xml_reader_t *h);
void xml_reader_process_external_subset(xml_reader_t *h);

#endif
