/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Supporting routines for testing XML reader.
*/

#ifndef __test_xml_reader_event_h_
#define __test_xml_reader_event_h_

#include <stdbool.h>
#include "xml/reader.h"

bool xmlreader_event_equal(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2);
void xmlreader_event_print(const xml_reader_cbparam_t *cbparam);
void xmlreader_event_gencode(const xml_reader_cbparam_t *cbparam);

// Some macro magic for declaring event (which is a discriminated union)
#define FL_NONE               __no_extra_data
#define FL_MESSAGE            message
#define FL_ENTITY_UNKNOWN     entity
#define FL_ENTITY_NOT_LOADED  entity
#define FL_ENTITY_PARSE_START entity
#define FL_ENTITY_PARSE_END   entity
#define FL_XMLDECL            xmldecl
#define FL_DTD_BEGIN          dtd
#define FL_DTD_END_INTERNAL   __no_extra_data
#define FL_DTD_END            __no_extra_data
#define FL_COMMENT            comment
#define FL_PI                 pi
#define FL_ENTITY_DEF         entity
#define FL_NOTATION_DEF       notation
#define FL_TEXT               text
#define FL_STAG               tag
#define FL_ETAG               tag
#define FL_ATTR               attr
#define FL(t)                 FL_##t

#define EV(t, l, ...)   { .cbtype = XML_READER_CB_##t, l, .FL(t) = { __VA_ARGS__ }, }
#define E0(t, l)        { .cbtype = XML_READER_CB_##t, l, }
#define END             { .cbtype = XML_READER_CB_NONE, }

/// Initializer for location info
#define LOC(s,l,p)      .loc = { .src = (s), .line = (l), .pos = (p), }

/// No location (e.g. failed to load document entity)
#define NOLOC           .loc = { .src = NULL, .line = 0, .pos = 0, }

/// Initializer for a token string
#define TOK(s)          { .str = U s, .len = sizeof(s) - 1 }

/// Initializer for absense of token string
#define NOTOK           { .str = NULL, .len = 0 }

#endif
