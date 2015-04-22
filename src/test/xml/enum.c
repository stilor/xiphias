/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */
#include "xml/reader.h"

#include "test/xml/enum.h"

static const enumval_t enumval_xml_version[] = {
    ENUM_VAL(XML_INFO_VERSION_NO_VALUE, "not specified")
    ENUM_VAL(XML_INFO_VERSION_1_0, "1.0")
    ENUM_VAL(XML_INFO_VERSION_1_1, "1.1")
};
ENUM_DECLARE(xml_version);

static const enumval_t enumval_xml_standalone[] = {
    ENUM_VAL(XML_INFO_STANDALONE_NO_VALUE, "not specified")
    ENUM_VAL(XML_INFO_STANDALONE_YES, "yes")
    ENUM_VAL(XML_INFO_STANDALONE_NO, "no")
};
ENUM_DECLARE(xml_standalone);

static const enumval_t enumval_cbtype[] = {
    ENUM_VAL(XML_READER_CB_MESSAGE, "Message")
    ENUM_VAL(XML_READER_CB_ENTITY_UNKNOWN, "Unknown entity")
    ENUM_VAL(XML_READER_CB_ENTITY_START, "Entity parsing start")
    ENUM_VAL(XML_READER_CB_ENTITY_END, "Entity parsing end")
    ENUM_VAL(XML_READER_CB_PUBID, "Public ID")
    ENUM_VAL(XML_READER_CB_SYSID, "System ID")
    ENUM_VAL(XML_READER_CB_NDATA, "Notation data")
    ENUM_VAL(XML_READER_CB_APPEND, "Append text")
    ENUM_VAL(XML_READER_CB_CDSECT, "CDATA section")
    ENUM_VAL(XML_READER_CB_XMLDECL, "XML declaration")
    ENUM_VAL(XML_READER_CB_COMMENT, "Comment")
    ENUM_VAL(XML_READER_CB_PI_TARGET, "PI target")
    ENUM_VAL(XML_READER_CB_PI_CONTENT, "PI content")
    ENUM_VAL(XML_READER_CB_DTD_BEGIN, "DTD begin")
    ENUM_VAL(XML_READER_CB_DTD_INTERNAL, "DTD internal subset")
    ENUM_VAL(XML_READER_CB_DTD_END, "DTD end")
    ENUM_VAL(XML_READER_CB_ENTITY_DEF_START, "Start entity definition")
    ENUM_VAL(XML_READER_CB_ENTITY_DEF_END, "End entity definition")
    ENUM_VAL(XML_READER_CB_NOTATION_DEF_START, "Start notation definition")
    ENUM_VAL(XML_READER_CB_NOTATION_DEF_END, "End notation definition")
    ENUM_VAL(XML_READER_CB_STAG, "Start tag")
    ENUM_VAL(XML_READER_CB_STAG_END, "Start tag complete")
    ENUM_VAL(XML_READER_CB_ETAG, "End tag")
    ENUM_VAL(XML_READER_CB_ATTR, "Attribute")
};
ENUM_DECLARE(cbtype);

static const enumval_t enumval_reftype[] = {
	ENUM_VAL(XML_READER_REF_PARAMETER, "Parameter entity")
	ENUM_VAL(XML_READER_REF_INTERNAL, "Internal general entity")
	ENUM_VAL(XML_READER_REF_EXTERNAL, "External parsed general entity")
	ENUM_VAL(XML_READER_REF_UNPARSED, "External unparsed general entity")
	ENUM_VAL(XML_READER_REF__CHAR, "Bad value (CHAR)")
	ENUM_VAL(XML_READER_REF__MAX, "Bad value (MAX)")
	ENUM_VAL(XML_READER_REF_GENERAL, "Undetermined general entity")
	ENUM_VAL(XML_READER_REF__UNKNOWN, "Bad value (UNKNOWN)")
};
ENUM_DECLARE(reftype);

static const enumval_t enumval_attrnorm[] = {
    ENUM_VAL(XML_READER_ATTRNORM_CDATA, "Basic normalization")
    ENUM_VAL(XML_READER_ATTRNORM_OTHER, "Collapse whitespace")
};
ENUM_DECLARE(attrnorm);

static const enumval_t enumval_xmlerr_severity[] = {
	ENUM_VAL(XMLERR_INFO, "INFO")
	ENUM_VAL(XMLERR_WARN, "WARN")
	ENUM_VAL(XMLERR_ERROR, "ERROR")
};
ENUM_DECLARE(xmlerr_severity);

static const enumval_t enumval_xmlerr_spec[] = {
	ENUM_VAL(XMLERR_SPEC_NONE, "<internal>")
	ENUM_VAL(XMLERR_SPEC_XML, "XML")
	ENUM_VAL(XMLERR_SPEC_XMLNS, "XMLNS")
};
ENUM_DECLARE(xmlerr_spec);

#undef XMLERR_DEF
#define XMLERR_DEF(a,b) { .val = XMLERR(_NONE, a, b), .str = #b, .id = #b },
static const enumval_t enumval_xmlerr_code[] = {
    XMLERR_XML
};
ENUM_DECLARE(xmlerr_code);
#undef XMLERR_DEF
