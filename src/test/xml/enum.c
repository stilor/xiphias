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
    ENUM_VAL(XML_READER_CB_ENTITY_NOT_LOADED, "Entity not loaded")
    ENUM_VAL(XML_READER_CB_ENTITY_PARSE_START, "Entity parsing start")
    ENUM_VAL(XML_READER_CB_ENTITY_PARSE_END, "Entity parsing end")
    ENUM_VAL(XML_READER_CB_XMLDECL, "XML declaration")
    ENUM_VAL(XML_READER_CB_DTD_BEGIN, "DTD begin")
    ENUM_VAL(XML_READER_CB_DTD_END_INTERNAL, "DTD end of internal subset")
    ENUM_VAL(XML_READER_CB_DTD_END, "DTD end")
    ENUM_VAL(XML_READER_CB_COMMENT, "Comment")
    ENUM_VAL(XML_READER_CB_PI, "PI")
    ENUM_VAL(XML_READER_CB_ENTITY_DEF, "Entity definition")
    ENUM_VAL(XML_READER_CB_NOTATION_DEF, "Notation definition")
    ENUM_VAL(XML_READER_CB_TEXT, "Text node")
    ENUM_VAL(XML_READER_CB_STAG, "Start tag")
    ENUM_VAL(XML_READER_CB_ETAG, "End tag")
    ENUM_VAL(XML_READER_CB_ATTR, "Attribute")
};
ENUM_DECLARE(cbtype);

static const enumval_t enumval_reftype[] = {
	ENUM_VAL(XML_READER_REF_PE, "Unknown parameter entity")
	ENUM_VAL(XML_READER_REF_PE_INTERNAL, "Internal parameter entity")
	ENUM_VAL(XML_READER_REF_PE_EXTERNAL, "External parameter entity")
	ENUM_VAL(XML_READER_REF_GENERAL, "Undetermined general entity")
	ENUM_VAL(XML_READER_REF_INTERNAL, "Internal general entity")
	ENUM_VAL(XML_READER_REF_EXTERNAL, "External parsed general entity")
	ENUM_VAL(XML_READER_REF_UNPARSED, "External unparsed general entity")
	ENUM_VAL(XML_READER_REF_CHARACTER, "Character")
	ENUM_VAL(XML_READER_REF__MAXREF, "Bad value (MAXREF)")
	ENUM_VAL(XML_READER_REF_DOCUMENT, "Document entity")
	ENUM_VAL(XML_READER_REF_EXT_SUBSET, "External subset")
	ENUM_VAL(XML_READER_REF_NONE, "Bad value (unset)")
};
ENUM_DECLARE(reftype);

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
