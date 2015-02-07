/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/**
    Tests for XMLDecl conditions all use dummy <a/> element as document
    content.
*/
#define E_XMLDECL_A \
        E(STAG, \
                .type = "a", \
                .typelen = 1, \
                .parent = NULL, \
                .baton = NULL, \
        ), \
        E(ETAG, \
                .type = "a", \
                .typelen = 1, \
                .baton = NULL, \
                .is_empty = true, \
        )

static const testcase_t testcases[] = {
    {
        .desc = "No declaration in UTF-8, with BOM",
        .input = "simple-no-decl.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL,
                    .has_decl = false,
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_NO_VALUE,
                    .initial_encoding = "UTF-8",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "No declaration in UTF-8, without BOM",
        .input = "simple-no-decl.xml",
        .use_bom = false,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL,
                    .has_decl = false,
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_NO_VALUE,
                    .initial_encoding = "UTF-8",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "No declaration in UTF-16BE, with BOM",
        .input = "simple-no-decl.xml",
        .use_bom = true,
        .encoding = "UTF-16BE",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("simple-no-decl.xml", 1, 0),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "No external encoding information, no encoding in XMLDecl, content in UTF-16BE encoding",
            ),
            E(XMLDECL,
                    .has_decl = false,
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_NO_VALUE,
                    .initial_encoding = "UTF-16BE",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "No declaration in UTF-16BE, without BOM",
        .input = "simple-no-decl.xml",
        .use_bom = false,
        .encoding = "UTF-16BE",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("simple-no-decl.xml", 1, 0),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "No external encoding information, no encoding in XMLDecl, content in UTF-16BE encoding",
            ),
            E(XMLDECL,
                    .has_decl = false,
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_NO_VALUE,
                    .initial_encoding = "UTF-16BE",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "No declaration in UTF-16LE, with BOM",
        .input = "simple-no-decl.xml",
        .use_bom = true,
        .encoding = "UTF-16LE",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("simple-no-decl.xml", 1, 0),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "No external encoding information, no encoding in XMLDecl, content in UTF-16LE encoding",
            ),
            E(XMLDECL,
                    .has_decl = false,
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_NO_VALUE,
                    .initial_encoding = "UTF-16LE",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "No declaration in UTF-16LE, without BOM",
        .input = "simple-no-decl.xml",
        .use_bom = false,
        .encoding = "UTF-16LE",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("simple-no-decl.xml", 1, 0),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "No external encoding information, no encoding in XMLDecl, content in UTF-16LE encoding",
            ),
            E(XMLDECL,
                    .has_decl = false,
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_NO_VALUE,
                    .initial_encoding = "UTF-16LE",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "Simple XML in UTF-8, with BOM",
        .input = "simple-utf8.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL,
                    .has_decl = true,
                    .encoding = "UTF-8",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
                    .initial_encoding = "UTF-8",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "Simple XML in UTF-8, without BOM",
        .input = "simple-utf8.xml",
        .use_bom = false,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL,
                    .has_decl = true,
                    .encoding = "UTF-8",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
                    .initial_encoding = "UTF-8",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "Simple XML in UTF-16BE, with BOM",
        .input = "simple-utf16.xml",
        .use_bom = true,
        .encoding = "UTF-16BE",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL,
                    .has_decl = true,
                    .encoding = "UTF-16",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
                    .initial_encoding = "UTF-16BE",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "Simple XML in UTF-16LE, with BOM",
        .input = "simple-utf16.xml",
        .use_bom = true,
        .encoding = "UTF-16LE",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL,
                    .has_decl = true,
                    .encoding = "UTF-16",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
                    .initial_encoding = "UTF-16LE",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "Simple XML in UTF-16 (BE), without BOM",
        .input = "simple-utf16.xml",
        .use_bom = false,
        .encoding = "UTF-16BE",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("simple-utf16.xml", 1, 39),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "UTF-16 encoding without byte-order mark",
            ),
            E(XMLDECL,
                    .has_decl = true,
                    .encoding = "UTF-16",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
                    .initial_encoding = "UTF-16BE",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "Simple XML in UTF-16 (LE), without BOM",
        .input = "simple-utf16.xml",
        .use_bom = false,
        .encoding = "UTF-16LE",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("simple-utf16.xml", 1, 39),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "UTF-16 encoding without byte-order mark",
            ),
            E(XMLDECL,
                    .has_decl = true,
                    .encoding = "UTF-16",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
                    .initial_encoding = "UTF-16LE",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "Simple XML in UTF-16BE, invalid transport encoding",
        .input = "simple-utf16.xml",
        .use_bom = true,
        .encoding = "UTF-16BE",
        .transport_encoding = "INVALID_ENCODING",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("simple-utf16.xml", 1, 0),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "Unsupported encoding 'INVALID_ENCODING'",
            ),
            E(XMLDECL,
                    .has_decl = true,
                    .encoding = "UTF-16",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
                    .initial_encoding = "UTF-16BE",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "Simple XML with invalid encoding declaration",
        .input = "simple-invalid-encoding.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("simple-invalid-encoding.xml", 1, 151),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "Unsupported encoding 'INVALID_ENCODING_WITH_A_VERY_LONG_NAME_THAT_IS_GOING_TO_SPAN_A_FEW_LINES_AND_PROBABLY_REQUIRE_REALLOCATION_OF_THE_BUFFER'",
            ),
            E(MESSAGE,
                    .loc = LOC("simple-invalid-encoding.xml", 1, 151),
                    .info = XMLERR_NOTE,
                    .msg = "(encoding from XML declaration)",
            ),
            E(XMLDECL,
                    .has_decl = true,
                    .encoding = "INVALID_ENCODING_WITH_A_VERY_LONG_NAME_THAT_IS_GOING_TO_SPAN_A_FEW_LINES_AND_PROBABLY_REQUIRE_REALLOCATION_OF_THE_BUFFER",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
                    .initial_encoding = "UTF-8",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "Incompatible encodings from transport layer and from autodetection",
        .input = "simple-utf8.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = "UTF-16BE",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("simple-utf8.xml", 1, 0),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "Incompatible encodings: 'UTF-16BE' and 'UTF-8'",
            ),
            E(MESSAGE,
                    .loc = LOC("simple-utf8.xml", 1, 0),
                    .info = XMLERR_NOTE,
                    .msg = "(autodetected from Byte-order Mark)",
            ),
            END,
        },
    },
    {
        .desc = "Incompatible encodings from autodetection and from declaration",
        .input = "simple-utf16.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("simple-utf16.xml", 1, 37),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "Incompatible encodings: 'UTF-8' and 'UTF-16'",
            ),
            E(MESSAGE,
                    .loc = LOC("simple-utf16.xml", 1, 37),
                    .info = XMLERR_NOTE,
                    .msg = "(encoding from XML declaration)",
            ),
            E(XMLDECL,
                    .has_decl = true,
                    .encoding = "UTF-16",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
                    .initial_encoding = "UTF-8",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "Truncated declaration #1",
        .input = "truncated-decl1.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("truncated-decl1.xml", 1, 24),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "XMLDecl truncated",
            ),
            END,
        },
    },
    {
        .desc = "Truncated declaration #2",
        .input = "truncated-decl2.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("truncated-decl2.xml", 1, 34),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "XMLDecl truncated",
            ),
            END,
        },
    },
    {
        .desc = "Truncated declaration #3",
        .input = "truncated-decl3.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("truncated-decl3.xml", 1, 38),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "XMLDecl truncated",
            ),
            END,
        },
    },
    {
        .desc = "Non-ASCII character in declaration",
        .input = "nonascii-decl.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("nonascii-decl.xml", 4, 2),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "XMLDecl contains non-ASCII or restricted characters",
            ),
            END,
        },
    },
    {
        .desc = "No mandatory attribute #1",
        .input = "decl-no-version1.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("decl-no-version1.xml", 1, 8),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Mandatory pseudo-attribute 'version' missing in XMLDecl",
            ),
            E(XMLDECL,
                    .has_decl = true,
                    .encoding = "UTF-8",
                    .standalone = XML_INFO_STANDALONE_NO,
                    .version = XML_INFO_VERSION_NO_VALUE,
                    .initial_encoding = "UTF-8",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "No mandatory attribute #2",
        .input = "decl-no-version2.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("decl-no-version2.xml", 1, 8),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Mandatory pseudo-attribute 'version' missing in XMLDecl",
            ),
            E(XMLDECL,
                    .has_decl = true,
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_NO_VALUE,
                    .initial_encoding = "UTF-8",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "Wrong order of pseudo-attributes",
        .input = "decl-wrong-order.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("decl-wrong-order.xml", 1, 8),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Mandatory pseudo-attribute 'version' missing in XMLDecl",
            ),
            E(MESSAGE,
                    .loc = LOC("decl-wrong-order.xml", 1, 25),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Unexpected pseudo-attribute",
            ),
            END,
        },
    },
    {
        .desc = "Extra pseudo-attribute at the end",
        .input = "decl-extra-attr1.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("decl-extra-attr1.xml", 1, 55),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Unexpected pseudo-attribute",
            ),
            END,
        },
    },
    {
        .desc = "Malformed declaration #1",
        .input = "decl-malformed1.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("decl-malformed1.xml", 1, 21),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Malformed XMLDecl",
            ),
            END,
        },
    },
    {
        .desc = "Pseudo-attribute without = #1",
        .input = "decl-no-equal1.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("decl-no-equal1.xml", 1, 29),
                    .info = XMLERR(ERROR, XML, P_EncodingDecl),
                    .msg = "No equal sign in pseudo-attribute",
            ),
            END,
        },
    },
    {
        .desc = "Pseudo-attribute without = #2",
        .input = "decl-no-equal2.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("decl-no-equal2.xml", 1, 14),
                    .info = XMLERR(ERROR, XML, P_VersionInfo),
                    .msg = "No equal sign in pseudo-attribute",
            ),
            END,
        },
    },
    {
        .desc = "Pseudo-attribute without quotes",
        .input = "decl-no-quote.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("decl-no-quote.xml", 1, 32),
                    .info = XMLERR(ERROR, XML, P_SDDecl),
                    .msg = "Pseudo-attribute value does not start with a quote",
            ),
            END,
        },
    },
    {
        .desc = "Future XML 1.x version",
        .input = "decl-xml-1.2.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("decl-xml-1.2.xml", 1, 19),
                    .info = XMLERR(WARN, XML, FUTURE_VERSION),
                    .msg = "Document specifies unknown 1.x XML version",
            ),
            E(XMLDECL,
                    .has_decl = true,
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
                    .initial_encoding = "UTF-8",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "Unsupported XML version",
        .input = "decl-xml-2.0.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("decl-xml-2.0.xml", 1, 19),
                    .info = XMLERR(ERROR, XML, P_VersionInfo),
                    .msg = "Unsupported XML version",
            ),
            E(XMLDECL,
                    .has_decl = true,
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_NO_VALUE,
                    .initial_encoding = "UTF-8",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "Invalid encoding value",
        .input = "decl-invalid-encoding.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("decl-invalid-encoding.xml", 1, 34),
                    .info = XMLERR(ERROR, XML, P_EncodingDecl),
                    .msg = "Invalid encoding name",
            ),
            E(XMLDECL,
                    .has_decl = true,
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_1,
                    .initial_encoding = "UTF-8",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "Invalid standalone value",
        .input = "decl-invalid-standalone.xml",
        .use_bom = true,
        .encoding = "UTF-8",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("decl-invalid-standalone.xml", 1, 38),
                    .info = XMLERR(ERROR, XML, P_SDDecl),
                    .msg = "Unsupported standalone status",
            ),
            E(XMLDECL,
                    .has_decl = true,
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
                    .initial_encoding = "UTF-8",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "Document with no declaration in non-UTF8/UTF16 encoding",
        .input = "simple-no-decl.xml",
        .use_bom = false,
        .encoding = "IBM037",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE,
                    .loc = LOC("simple-no-decl.xml", 1, 0),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "No external encoding information, no encoding in XMLDecl, content in IBM500 encoding",
            ),
            E(XMLDECL,
                    .has_decl = false,
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_NO_VALUE,
                    .initial_encoding = "IBM500",
            ),
            E_XMLDECL_A,
            END,
        },
    },
    {
        .desc = "Document with no declaration in non-UTF8/UTF16 encoding (has transport encoding)",
        .input = "simple-no-decl.xml",
        .use_bom = false,
        .encoding = "IBM037",
        .transport_encoding = "IBM500",
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL,
                    .has_decl = false,
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_NO_VALUE,
                    .initial_encoding = "IBM500",
            ),
            E_XMLDECL_A,
            END,
        },
    },
};
