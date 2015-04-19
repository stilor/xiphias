/* vi: set ts=5 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Supporting routines for testing XML reader.
*/

#ifndef __xmltest_xmlreader_event_h_
#define __xmltest_xmlreader_event_h_

#include <stdbool.h>
#include "xml/reader.h"

bool xmlreader_event_equal(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2);
void xmlreader_event_print(const xml_reader_cbparam_t *cbparam);
void xmlreader_event_gencode(const xml_reader_cbparam_t *cbparam);

// Some macro magic for declaring event (which is a disciminated union)
#define FL_NONE               __dummy
#define FL_MESSAGE            message
#define FL_XMLDECL            xmldecl
#define FL_PUBID              __dummy
#define FL_SYSID              __dummy
#define FL_NDATA              ndata
#define FL_APPEND             append
#define FL_CDSECT             append
#define FL_COMMENT            __dummy
#define FL_PI_TARGET          ndata
#define FL_PI_CONTENT         __dummy
#define FL_DTD_BEGIN          __dummy
#define FL_DTD_INTERNAL       __dummy
#define FL_DTD_END            __dummy
#define FL_ENTITY_DEF_START   entitydef
#define FL_ENTITY_DEF_END     __dummy
#define FL_NOTATION_DEF_START __dummy
#define FL_NOTATION_DEF_END   __dummy
#define FL_STAG               __dummy
#define FL_STAG_END           stag_end
#define FL_ETAG               __dummy
#define FL_ATTR               attr
#define FL_ENTITY_UNKNOWN     entity
#define FL_ENTITY_START       entity
#define FL_ENTITY_END         entity
#define FL(t)                 FL_##t

#define E(t, l, tok, ...)   { .cbtype = XML_READER_CB_##t, l, tok, .FL(t) = { __VA_ARGS__ }, }
#define END                 { .cbtype = XML_READER_CB_NONE, }

/// Initializer for location info
#define LOC(s,l,p)      .loc = { .src = (s), .line = (l), .pos = (p), }

/// Initializer for a token string
#define TOK(s)          .token = { .str = U s, .len = sizeof(s) - 1 }

/// Initializer for absense of token string
#define NOTOK           .token = { .str = NULL, .len = 0 }

#endif
