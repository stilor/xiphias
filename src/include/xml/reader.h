/* vi: set ts=5 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Handle for reading an XML entity.
*/

#ifndef __xml_reader_h_
#define __xml_reader_h_

#include <stdint.h>

// Forward declarations
struct strbuf_s;

/// Opaque handle for reading XML entity
typedef struct xml_reader_s xml_reader_t;

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
    Start parsing an input stream: read the XML/text declaration, determine final
    encodings (or err out).

    @param h Reader handle
    @param xmldeclattr Allowed attributes on an XML/text declaration
    @return None
*/
void xml_reader_start(xml_reader_t *h, const char *const *xmldeclattr);

#endif
