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

// Forward declarations
struct strbuf_s;

/// Parameter for XML or text declaration callback
typedef struct {
    bool has_decl;                           ///< True: had explicit XML declaration
    const char *encoding;                    ///< Encoding from the declaration
    enum xml_info_standalone_e standalone;   ///< Is the document is declared standalone
    enum xml_info_version_e version;         ///< XML version
} xml_reader_cbparam_xmldecl_t;

/// Combined callback parameter type
typedef union {
    xml_reader_cbparam_xmldecl_t xmldecl;    ///< XML or text declaration
} xml_reader_cbparam_t;

/// Opaque handle for reading XML entity
typedef struct xml_reader_s xml_reader_t;

/// Reader callback function type
typedef void (*xml_reader_cb_t)(void *arg, const xml_reader_cbparam_t *cbparam);

/// Callback types (in parentheses: field in the callback parameter union)
enum xml_reader_cbtype_e {
    XML_READER_CB_XMLDECL,         ///< XML declaration (xmldecl)

    XML_READER_CB_MAX
};

/**
    Create an XML reading handle.

    @return Handle
*/
xml_reader_t *xml_reader_new(struct strbuf_s *buf);

/**
    Destroy an XML reading handle.

    @param h Handle to be destroyed.
    @return None
*/
void xml_reader_delete(xml_reader_t *h);

/**
    Set transport encoding.

    @param h Reader handle
    @param enc Encoding reported by higher-level protocol
               (e.g. Content-Type header in HTTP).
    @return None
*/
void xml_reader_set_transport_encoding(xml_reader_t *h, const char *encname);

/**
    Set callback functions for the reader.

    @param h Reader handle
    @param evt Event for which callback is set
    @param func Function to be called
    @param arg Argument to callback function
    @return None
*/
void xml_reader_set_callback(xml_reader_t *h, enum xml_reader_cbtype_e evt,
        xml_reader_cb_t func, void *arg);

/**
    Read in the XML content and emit the callbacks as necessary.

    @param h Reader handle
    @param is_document_entity True if the content belongs to the document entity,
          false if external parsed entity
    @return None
*/
void xml_reader_process_xml(xml_reader_t *h, bool is_document_entity);

#endif
