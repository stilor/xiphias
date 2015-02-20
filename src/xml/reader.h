/* vi: set ts=5 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Handle for reading an XML entity.
*/

#ifndef __xml_reader_h_
#define __xml_reader_h_

#include <stddef.h>
#include <stdint.h>

#include "infoset.h"
#include "xmlerr.h"

// Forward declarations
struct strbuf_s;

/// Callback types
enum xml_reader_cbtype_e {
    XML_READER_CB_NONE,            ///< No message (placeholder/terminator)
    XML_READER_CB_MESSAGE,         ///< Note/warning/error message
    XML_READER_CB_XMLDECL,         ///< XML declaration
    XML_READER_CB_DTD_BEGIN,       ///< Beginning of a document type declaration
    XML_READER_CB_DTD_END,         ///< End of a document type declaration
    XML_READER_CB_STAG,            ///< Start of element (STag)
    XML_READER_CB_ETAG,            ///< End of element (ETag)
    XML_READER_CB_COMMENT,         ///< Comment
    XML_READER_CB_PI,              ///< Processing instruction

    XML_READER_CB_MAX
};

/// Parameter for message callback
typedef struct {
    xmlerr_info_t info;            ///< Error info
    const char *msg;               ///< Error message
} xml_reader_cbparam_message_t;

/// Parameter for XML or text declaration callback
typedef struct {
    enum xml_info_version_e version;         ///< XML version
    const char *encoding;                    ///< Encoding from the declaration
    enum xml_info_standalone_e standalone;   ///< Is the document is declared standalone
} xml_reader_cbparam_xmldecl_t;

/// Parameter for start of the element callback
typedef struct {
    const char *type;                        ///< Element type (name)
    size_t typelen;                          ///< Element type length
    void *parent;                            ///< Parent element baton
    void *baton;                             ///< (in) baton to use for child nodes and etag
} xml_reader_cbparam_stag_t;

/// Parameter for end of the element callback
typedef struct {
    const char *type;                        ///< Element type (may not match STag for malformed docs)
    size_t typelen;                          ///< Element type length
    void *baton;                             ///< Baton passed by STag callback
    bool is_empty;                           ///< True if EmptyElemTag production was used
} xml_reader_cbparam_etag_t;

/// Combined callback parameter type
typedef struct {
    enum xml_reader_cbtype_e cbtype;              ///< Callback type
    xmlerr_loc_t loc;              ///< Location of the error
    union {
        xml_reader_cbparam_message_t message;     ///< Error/warning message
        xml_reader_cbparam_xmldecl_t xmldecl;     ///< XML or text declaration
        xml_reader_cbparam_stag_t stag;           ///< Start of element (STag)
        xml_reader_cbparam_etag_t etag;           ///< End of element (ETag)
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
typedef void (*xml_reader_cb_t)(void *arg, const xml_reader_cbparam_t *cbparam);

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
