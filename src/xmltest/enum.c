/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */
#include "util/xutil.h"
#include "xml/reader.h"

#include "enum.h"

const char *
enum2str(unsigned int val, const enumtbl_t *tbl)
{
    const enumval_t *v;
    size_t i;

    for (i = 0, v = tbl->vals; i < tbl->nvals; i++, v++) {
        if (v->val == val) {
            return v->str;
        }
    }
    return "???";
}

const char *
enum2id(unsigned int val, const enumtbl_t *tbl, const char *strip)
{
    const enumval_t *v;
    const char *p;
    size_t i, slen;

    for (i = 0, v = tbl->vals; i < tbl->nvals; i++, v++) {
        if (v->val == val) {
            p = v->id;
            if (strip) {
                slen = strlen(strip);
                if (!strncmp(p, strip, slen)) {
                    p += slen;
                }
                else {
                    p = "??? (invalid prefix)";
                }
            }
            return p;
        }
    }
    return "???";
}

#define DECLARE_ENUM(x) \
        const enumtbl_t enum_##x = { \
            .vals = enumval_##x, \
            .nvals = sizeofarray(enumval_##x), \
        }

#define E(a,s)  { .val = a, .id = #a, .str = s },

static const enumval_t enumval_xml_version[] = {
    E(XML_INFO_VERSION_NO_VALUE, "not specified")
    E(XML_INFO_VERSION_1_0, "1.0")
    E(XML_INFO_VERSION_1_1, "1.1")
};
DECLARE_ENUM(xml_version);

static const enumval_t enumval_xml_standalone[] = {
    E(XML_INFO_STANDALONE_NO_VALUE, "not specified")
    E(XML_INFO_STANDALONE_YES, "yes")
    E(XML_INFO_STANDALONE_NO, "no")
};
DECLARE_ENUM(xml_standalone);

static const enumval_t enumval_cbtype[] = {
    E(XML_READER_CB_MESSAGE, "Message")
    E(XML_READER_CB_ENTITY_UNKNOWN, "Unknown entity")
    E(XML_READER_CB_ENTITY_START, "Entity parsing start")
    E(XML_READER_CB_ENTITY_END, "Entity parsing end")
    E(XML_READER_CB_PUBID, "Public ID")
    E(XML_READER_CB_SYSID, "System ID")
    E(XML_READER_CB_NDATA, "Notation data")
    E(XML_READER_CB_APPEND, "Append text")
    E(XML_READER_CB_CDSECT, "CDATA section")
    E(XML_READER_CB_XMLDECL, "XML declaration")
    E(XML_READER_CB_COMMENT, "Comment")
    E(XML_READER_CB_PI_TARGET, "PI target")
    E(XML_READER_CB_PI_CONTENT, "PI content")
    E(XML_READER_CB_DTD_BEGIN, "DTD begin")
    E(XML_READER_CB_DTD_INTERNAL, "DTD internal subset")
    E(XML_READER_CB_DTD_END, "DTD end")
    E(XML_READER_CB_ENTITY_DEF_START, "Start entity definition")
    E(XML_READER_CB_ENTITY_DEF_END, "End entity definition")
    E(XML_READER_CB_STAG, "Start tag")
    E(XML_READER_CB_STAG_END, "Start tag complete")
    E(XML_READER_CB_ETAG, "End tag")
    E(XML_READER_CB_ATTR, "Attribute")
};
DECLARE_ENUM(cbtype);

static const enumval_t enumval_reftype[] = {
	E(XML_READER_REF_PARAMETER, "Parameter entity")
	E(XML_READER_REF_INTERNAL, "Internal general entity")
	E(XML_READER_REF_EXTERNAL, "External parsed general entity")
	E(XML_READER_REF_UNPARSED, "External unparsed general entity")
	E(XML_READER_REF__CHAR, "Bad value (CHAR)")
	E(XML_READER_REF__MAX, "Bad value (MAX)")
	E(XML_READER_REF_GENERAL, "Undetermined general entity")
	E(XML_READER_REF__UNKNOWN, "Bad value (UNKNOWN)")
};
DECLARE_ENUM(reftype);

static const enumval_t enumval_attrnorm[] = {
    E(XML_READER_ATTRNORM_CDATA, "Basic normalization")
    E(XML_READER_ATTRNORM_OTHER, "Collapse whitespace")
};
DECLARE_ENUM(attrnorm);

static const enumval_t enumval_xmlerr_severity[] = {
	E(XMLERR_INFO, "INFO")
	E(XMLERR_WARN, "WARN")
	E(XMLERR_ERROR, "ERROR")
};
DECLARE_ENUM(xmlerr_severity);

static const enumval_t enumval_xmlerr_spec[] = {
	E(XMLERR_SPEC_NONE, "<internal>")
	E(XMLERR_SPEC_XML, "XML 1.x")
	E(XMLERR_SPEC_XMLNS, "Namespaces in XML")
};
DECLARE_ENUM(xmlerr_spec);

#undef XMLERR_DEF
#define XMLERR_DEF(a,b) { .val = XMLERR(_NONE, a, b), .str = #b, .id = #b },
static const enumval_t enumval_xmlerr_code[] = {
    XMLERR_XML
};
DECLARE_ENUM(xmlerr_code);
#undef XMLERR_DEF
