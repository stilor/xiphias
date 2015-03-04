/* vi: set ts=5 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Handle for reading an XML entity.
*/

#ifndef __xmltest_xmlreader_event_h_
#define __xmltest_xmlreader_event_h_

#include <stdbool.h>
#include "xml/reader.h"

bool xmlreader_event_equal(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2);
void xmlreader_event_print(const xml_reader_cbparam_t *cbparam);

#endif
