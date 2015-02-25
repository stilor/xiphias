/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

static result_t
set_reader_options_pre(xml_reader_t *h, const void *arg)
{
    if (!xml_reader_set_transport_encoding(h, "UTF-8")) {
        printf("Failed to set transport encoding\n");
        return FAIL;
    }
    if (!xml_reader_set_normalization(h, XML_READER_NORM_OFF)) {
        printf("Failed to disable normalization checks\n");
        return FAIL;
    }
    if (!xml_reader_set_location_tracking(h, true, 4)) {
        printf("Failed to configure tabstop size to 4\n");
        return FAIL;
    }
    printf("Pre-parsing configuration set\n");
    return PASS;
}

static result_t
set_reader_options_post(xml_reader_t *h, xml_reader_cbparam_t *e, const void *arg)
{
    if (e->cbtype == XML_READER_CB_XMLDECL) {
        if (xml_reader_set_transport_encoding(h, "UTF-8")) {
            printf("Succeeded to set transport encoding\n");
            return FAIL;
        }
        if (xml_reader_set_normalization(h, XML_READER_NORM_ON)) {
            printf("Succeeded to disable normalization checks\n");
            return FAIL;
        }
        if (xml_reader_set_location_tracking(h, true, 2)) {
            printf("Succeeded to configure tabstop size to 2\n");
            return FAIL;
        }
        printf("Configuration immutable during parsing.\n");
    }
    else if (e->cbtype == XML_READER_CB_STAG) {
        xml_reader_set_callback(h, NULL, NULL);
    }
    return PASS;
}

static result_t
disable_location_tracking(xml_reader_t *h, const void *arg)
{
    if (!xml_reader_set_location_tracking(h, false, 0)) {
        printf("Failed to disable location tracking\n");
        return FAIL;
    }
    return PASS;
}

static const testcase_t testcases_api[] = {
    {
        .desc = "Setting reader options before/after parsing start",
        .input = "simple-utf8.xml",
        .pretest = set_reader_options_pre,
        .checkevt = set_reader_options_post,
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL, LOC("simple-utf8.xml", 1, 1),
                    .encoding = "UTF-8",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            E(STAG, LOC("simple-utf8.xml", 3, 5),
                    .type = U"a",
                    .typelen = 1,
                    .parent = NULL,
                    .baton = NULL
            ),
            END,
        },
    },
    {
        .desc = "Disable location tracking",
        .input = "simple-utf8.xml",
        .pretest = disable_location_tracking,
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL, LOC("simple-utf8.xml", 1, 1),
                    .encoding = "UTF-8",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            E(STAG, LOC("simple-utf8.xml", 1, 1),
                    .type = U"a",
                    .typelen = 1,
                    .parent = NULL,
                    .baton = NULL,
            ),
            E(ETAG, LOC("simple-utf8.xml", 1, 1),
                    .type = U"a",
                    .typelen = 1,
                    .baton = NULL,
                    .is_empty = true,
            ),
            END,
        },
    },
};

/**
    Tests for XMLDecl conditions all use dummy <a/> element as document
    content.
*/
#define E_XMLDECL_A(s, l, p) \
        E(STAG, LOC(s, l, p), \
                .type = U"a", \
                .typelen = 1, \
                .parent = NULL, \
                .baton = NULL, \
        ), \
        E(ETAG, LOC(s, l, p), \
                .type = U"a", \
                .typelen = 1, \
                .baton = NULL, \
                .is_empty = true, \
        )

struct test_set_transport_encoding_s {
    const char *enc;
    bool expected;
};

static result_t
test_set_transport_encoding(xml_reader_t *h, const void *arg)
{
    const struct test_set_transport_encoding_s *sts = arg;

    printf("- Setting transport encoding to '%s'\n", sts->enc);
    return xml_reader_set_transport_encoding(h, sts->enc) == sts->expected ?
            PASS : FAIL;
}

#define TEST_TRANSPORT_ENCODING(e, r) \
        .pretest = test_set_transport_encoding, \
        .pretest_arg = &(const struct test_set_transport_encoding_s){ \
            .enc = (e), \
            .expected = (r), \
        },

static const testcase_t testcases_encoding[] = {
    {
        .desc = "No declaration in UTF-8, with BOM",
        .input = "simple-no-decl.xml",
        .use_bom = true,
        .events = (const xml_reader_cbparam_t[]){
            E_XMLDECL_A("simple-no-decl.xml", 1, 1),
            END,
        },
    },
    {
        .desc = "No declaration in UTF-8, without BOM",
        .input = "simple-no-decl.xml",
        .events = (const xml_reader_cbparam_t[]){
            E_XMLDECL_A("simple-no-decl.xml", 1, 1),
            END,
        },
    },
    {
        .desc = "No declaration in UTF-16BE, with BOM",
        .input = "simple-no-decl.xml",
        .use_bom = true,
        .encoding = "UTF-16BE",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("simple-no-decl.xml", 1, 1),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "No external encoding information, no encoding in "
                    "XMLDecl, content in UTF-16BE encoding",
            ),
            E_XMLDECL_A("simple-no-decl.xml", 1, 1),
            END,
        },
    },
    {
        .desc = "No declaration in UTF-16BE, without BOM",
        .input = "simple-no-decl.xml",
        .encoding = "UTF-16BE",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("simple-no-decl.xml", 1, 1),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "No external encoding information, no encoding "
                    "in XMLDecl, content in UTF-16BE encoding",
            ),
            E_XMLDECL_A("simple-no-decl.xml", 1, 1),
            END,
        },
    },
    {
        .desc = "No declaration in UTF-16LE, with BOM",
        .input = "simple-no-decl.xml",
        .use_bom = true,
        .encoding = "UTF-16LE",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("simple-no-decl.xml", 1, 1),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "No external encoding information, no encoding "
                    "in XMLDecl, content in UTF-16LE encoding",
            ),
            E_XMLDECL_A("simple-no-decl.xml", 1, 1),
            END,
        },
    },
    {
        .desc = "No declaration in UTF-16LE, without BOM",
        .input = "simple-no-decl.xml",
        .encoding = "UTF-16LE",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("simple-no-decl.xml", 1, 1),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "No external encoding information, no encoding "
                    "in XMLDecl, content in UTF-16LE encoding",
            ),
            E_XMLDECL_A("simple-no-decl.xml", 1, 1),
            END,
        },
    },
    {
        .desc = "Simple XML in UTF-8, with BOM",
        .input = "simple-utf8.xml",
        .use_bom = true,
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL, LOC("simple-utf8.xml", 1, 1),
                    .encoding = "UTF-8",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            E_XMLDECL_A("simple-utf8.xml", 3, 9),
            END,
        },
    },
    {
        .desc = "Simple XML in UTF-8, without BOM",
        .input = "simple-utf8.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL, LOC("simple-utf8.xml", 1, 1),
                    .encoding = "UTF-8",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            E_XMLDECL_A("simple-utf8.xml", 3, 9),
            END,
        },
    },
    {
        .desc = "Simple XML in UTF-16BE, with BOM",
        .input = "simple-utf16.xml",
        .use_bom = true,
        .encoding = "UTF-16BE",
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL, LOC("simple-utf16.xml", 1, 1),
                    .encoding = "UTF-16",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            E_XMLDECL_A("simple-utf16.xml", 2, 1),
            END,
        },
    },
    {
        .desc = "Simple XML in UTF-16LE, with BOM",
        .input = "simple-utf16.xml",
        .use_bom = true,
        .encoding = "UTF-16LE",
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL, LOC("simple-utf16.xml", 1, 1),
                    .encoding = "UTF-16",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            E_XMLDECL_A("simple-utf16.xml", 2, 1),
            END,
        },
    },
    {
        .desc = "Simple XML in UTF-16 (BE), without BOM",
        .input = "simple-utf16.xml",
        .encoding = "UTF-16BE",
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL, LOC("simple-utf16.xml", 1, 1),
                    .encoding = "UTF-16",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            E(MESSAGE, LOC("simple-utf16.xml", 1, 1),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "UTF-16 encoding without byte-order mark",
            ),
            E_XMLDECL_A("simple-utf16.xml", 2, 1),
            END,
        },
    },
    {
        .desc = "Simple XML in UTF-16 (LE), without BOM",
        .input = "simple-utf16.xml",
        .encoding = "UTF-16LE",
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL, LOC("simple-utf16.xml", 1, 1),
                    .encoding = "UTF-16",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            E(MESSAGE, LOC("simple-utf16.xml", 1, 1),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "UTF-16 encoding without byte-order mark",
            ),
            E_XMLDECL_A("simple-utf16.xml", 2, 1),
            END,
        },
    },
    {
        .desc = "Simple XML in UTF-16BE, invalid transport encoding",
        .input = "simple-utf16.xml",
        .use_bom = true,
        .encoding = "UTF-16BE",
        TEST_TRANSPORT_ENCODING("INVALID_ENCODING", false)
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("simple-utf16.xml", 1, 1),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "Unsupported encoding 'INVALID_ENCODING'",
            ),
            E(XMLDECL, LOC("simple-utf16.xml", 1, 1),
                    .encoding = "UTF-16",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            E_XMLDECL_A("simple-utf16.xml", 2, 1),
            END,
        },
    },
    {
        .desc = "Simple XML with invalid encoding declaration",
        .input = "simple-invalid-encoding.xml",
        .use_bom = true,
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL, LOC("simple-invalid-encoding.xml", 1, 1),
                    .encoding = "INVALID_ENCODING_WITH_A_VERY_LONG_NAME_THAT"
                    "_IS_GOING_TO_SPAN_A_FEW_LINES_AND_PROBABLY_REQUIRE_"
                    "REALLOCATION_OF_THE_BUFFER",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            E(MESSAGE, LOC("simple-invalid-encoding.xml", 1, 1),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "Unsupported encoding 'INVALID_ENCODING_WITH_A_VERY"
                    "_LONG_NAME_THAT_IS_GOING_TO_SPAN_A_FEW_LINES_AND_PROBABLY"
                    "_REQUIRE_REALLOCATION_OF_THE_BUFFER'",
            ),
            E(MESSAGE, LOC("simple-invalid-encoding.xml", 1, 1),
                    .info = XMLERR_NOTE,
                    .msg = "(encoding from XML declaration)",
            ),
            E_XMLDECL_A("simple-invalid-encoding.xml", 2, 1),
            END,
        },
    },
    {
        .desc = "Incompatible encodings from transport layer and from autodetection",
        .input = "simple-utf8.xml",
        .use_bom = true,
        TEST_TRANSPORT_ENCODING("UTF-16BE", true)
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("simple-utf8.xml", 1, 1),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "Incompatible encodings: 'UTF-16BE' and 'UTF-8'",
            ),
            E(MESSAGE, LOC("simple-utf8.xml", 1, 1),
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
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL, LOC("simple-utf16.xml", 1, 1),
                    .encoding = "UTF-16",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            E(MESSAGE, LOC("simple-utf16.xml", 1, 1),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "Incompatible encodings: 'UTF-8' and 'UTF-16'",
            ),
            E(MESSAGE, LOC("simple-utf16.xml", 1, 1),
                    .info = XMLERR_NOTE,
                    .msg = "(encoding from XML declaration)",
            ),
            E_XMLDECL_A("simple-utf16.xml", 2, 1),
            END,
        },
    },
    {
        .desc = "Partial character at end of input",
        .input = "partial-chars.xml",
        .events = (const xml_reader_cbparam_t[]){
            E_XMLDECL_A("partial-chars.xml", 1, 1),
            E(MESSAGE, LOC("partial-chars.xml", 3, 2),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "Partial characters at end of input",
            ),
            END,
        },
    },
    {
        .desc = "Invalid character at top level",
        .input = "invalid-chars-top-level.xml",
        .events = (const xml_reader_cbparam_t[]){
            E_XMLDECL_A("invalid-chars-top-level.xml", 1, 1),
            E(MESSAGE, LOC("invalid-chars-top-level.xml", 1, 5),
                    .info = XMLERR(ERROR, XML, P_document),
                    .msg = "Invalid content at root level",
            ),
            END,
        },
    },
};

static const testcase_t testcases_xmldecl[] = {
    {
        .desc = "Truncated declaration #1",
        .input = "truncated-decl1.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("truncated-decl1.xml", 1, 21),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Unexpected pseudo-attribute",
            ),
            E(MESSAGE, LOC("truncated-decl1.xml", 1, 25),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Expected string: '='",
            ),
            E(MESSAGE, LOC("truncated-decl1.xml", 1, 25),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Malformed XMLDecl",
            ),
            END,
        },
    },
    {
        .desc = "Truncated declaration #2",
        .input = "truncated-decl2.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("truncated-decl2.xml", 1, 30),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Unterminated literal",
            ),
            E(MESSAGE, LOC("truncated-decl2.xml", 1, 35),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Malformed XMLDecl",
            ),
            END,
        },
    },
    {
        .desc = "Truncated declaration #3",
        .input = "truncated-decl3.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("truncated-decl3.xml", 1, 38),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Expected string: '?>'",
            ),
            E(MESSAGE, LOC("truncated-decl3.xml", 1, 39),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Malformed XMLDecl",
            ),
            END,
        },
    },
    {
        .desc = "Non-ASCII character in declaration",
        .input = "nonascii-decl.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("nonascii-decl.xml", 4, 9),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Non-ASCII characters in XMLDecl",
            ),
            E(MESSAGE, LOC("nonascii-decl.xml", 4, 9),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Unexpected pseudo-attribute",
            ),
            E(XMLDECL, LOC("nonascii-decl.xml", 1, 1),
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_YES,
                    .version = XML_INFO_VERSION_1_1,
            ),
            E_XMLDECL_A("nonascii-decl.xml", 5, 1),
            END,
        },
    },
    {
        .desc = "No mandatory attribute #1",
        .input = "decl-no-version1.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("decl-no-version1.xml", 1, 7),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Mandatory pseudo-attribute 'version' missing in XMLDecl",
            ),
            E(XMLDECL, LOC("decl-no-version1.xml", 1, 1),
                    .encoding = "UTF-8",
                    .standalone = XML_INFO_STANDALONE_NO,
                    .version = XML_INFO_VERSION_NO_VALUE,
            ),
            E_XMLDECL_A("decl-no-version1.xml", 1, 41),
            END,
        },
    },
    {
        .desc = "No mandatory attribute #2",
        .input = "decl-no-version2.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("decl-no-version2.xml", 1, 7),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Mandatory pseudo-attribute 'version' missing in XMLDecl",
            ),
            E(XMLDECL, LOC("decl-no-version2.xml", 1, 1),
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_NO_VALUE,
            ),
            E_XMLDECL_A("decl-no-version2.xml", 1, 9),
            END,
        },
    },
    {
        .desc = "Wrong order of pseudo-attributes",
        .input = "decl-wrong-order.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("decl-wrong-order.xml", 1, 7),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Mandatory pseudo-attribute 'version' missing in XMLDecl",
            ),
            E(MESSAGE, LOC("decl-wrong-order.xml", 1, 24),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Unexpected pseudo-attribute",
            ),
            E(XMLDECL, LOC("decl-wrong-order.xml", 1, 1),
                    .encoding = "UTF-8",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_NO_VALUE,
            ),
            E_XMLDECL_A("decl-wrong-order.xml", 1, 39),
            END,
        },
    },
    {
        .desc = "Extra pseudo-attribute at the end",
        .input = "decl-extra-attr1.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("decl-extra-attr1.xml", 1, 55),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Unexpected pseudo-attribute",
            ),
            E(XMLDECL, LOC("decl-extra-attr1.xml", 1, 1),
                    .encoding = "UTF-8",
                    .standalone = XML_INFO_STANDALONE_YES,
                    .version = XML_INFO_VERSION_1_0,
            ),
            E_XMLDECL_A("decl-extra-attr1.xml", 1, 70),
            END,
        },
    },
    {
        .desc = "Malformed declaration #1",
        .input = "decl-malformed1.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("decl-malformed1.xml", 1, 20),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Expected string: '?>'",
            ),
            E(MESSAGE, LOC("decl-malformed1.xml", 1, 21),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Malformed XMLDecl",
            ),
            END,
        },
    },
    {
        .desc = "Pseudo-attribute without = #1",
        .input = "decl-no-equal1.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("decl-no-equal1.xml", 1, 29),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Expected string: '='",
            ),
            E(MESSAGE, LOC("decl-no-equal1.xml", 1, 29),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Malformed XMLDecl",
            ),
            END,
        },
    },
    {
        .desc = "Pseudo-attribute without = #2",
        .input = "decl-no-equal2.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("decl-no-equal2.xml", 1, 14),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Expected string: '='",
            ),
            E(MESSAGE, LOC("decl-no-equal2.xml", 1, 14),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Malformed XMLDecl",
            ),
            END,
        },
    },
    {
        .desc = "Pseudo-attribute without quotes",
        .input = "decl-no-quote.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("decl-no-quote.xml", 1, 32),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Quoted literal expected",
            ),
            E(MESSAGE, LOC("decl-no-quote.xml", 1, 32),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Malformed XMLDecl",
            ),
            END,
        },
    },
    {
        .desc = "Future XML 1.x version",
        .input = "decl-xml-1.2.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("decl-xml-1.2.xml", 1, 15),
                    .info = XMLERR(WARN, XML, FUTURE_VERSION),
                    .msg = "Document specifies unknown 1.x XML version",
            ),
            E(XMLDECL, LOC("decl-xml-1.2.xml", 1, 1),
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            E_XMLDECL_A("decl-xml-1.2.xml", 1, 22),
            END,
        },
    },
    {
        .desc = "Unsupported XML version #1",
        .input = "decl-xml-1.A.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("decl-xml-1.A.xml", 1, 15),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Unsupported XML version",
            ),
            E(XMLDECL, LOC("decl-xml-1.A.xml", 1, 1),
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_NO_VALUE,
            ),
            E_XMLDECL_A("decl-xml-1.A.xml", 1, 22),
            END,
        },
    },
    {
        .desc = "Unsupported XML version #2",
        .input = "decl-xml-2.0.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("decl-xml-2.0.xml", 1, 15),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Unsupported XML version",
            ),
            E(XMLDECL, LOC("decl-xml-2.0.xml", 1, 1),
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_NO_VALUE,
            ),
            E_XMLDECL_A("decl-xml-2.0.xml", 1, 22),
            END,
        },
    },
    {
        .desc = "Invalid encoding value #1",
        .input = "decl-invalid-encoding.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("decl-invalid-encoding.xml", 1, 30),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Invalid encoding name",
            ),
            E(XMLDECL, LOC("decl-invalid-encoding.xml", 1, 1),
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_1,
            ),
            E_XMLDECL_A("decl-invalid-encoding.xml", 1, 37),
            END,
        },
    },
    {
        .desc = "Invalid encoding value #2",
        .input = "decl-invalid-encoding2.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("decl-invalid-encoding2.xml", 1, 30),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Invalid encoding name",
            ),
            E(XMLDECL, LOC("decl-invalid-encoding2.xml", 1, 1),
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_1,
            ),
            E_XMLDECL_A("decl-invalid-encoding2.xml", 1, 41),
            END,
        },
    },
    {
        .desc = "Invalid standalone value",
        .input = "decl-invalid-standalone.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("decl-invalid-standalone.xml", 1, 32),
                    .info = XMLERR(ERROR, XML, P_XMLDecl),
                    .msg = "Unsupported standalone status",
            ),
            E(XMLDECL, LOC("decl-invalid-standalone.xml", 1, 1),
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            E_XMLDECL_A("decl-invalid-standalone.xml", 1, 41),
            END,
        },
    },
    {
        .desc = "Document with no declaration in non-UTF8/UTF16 encoding",
        .input = "simple-no-decl.xml",
        .encoding = "IBM037",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("simple-no-decl.xml", 1, 1),
                    .info = XMLERR(ERROR, XML, ENCODING_ERROR),
                    .msg = "No external encoding information, "
                    "no encoding in XMLDecl, content in IBM500 encoding",
            ),
            E_XMLDECL_A("simple-no-decl.xml", 1, 1),
            END,
        },
    },
    {
        .desc = "Document with no declaration in non-UTF8/UTF16 encoding "
                "(has transport encoding)",
        .input = "simple-no-decl.xml",
        .encoding = "IBM037",
        TEST_TRANSPORT_ENCODING("IBM500", true)
        .events = (const xml_reader_cbparam_t[]){
            E_XMLDECL_A("simple-no-decl.xml", 1, 1),
            END,
        },
    },
    {
        .desc = "Position updates with combining marks",
        .input = "combining-mark.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(STAG, LOC("combining-mark.xml", 1, 1),
                    .type = U"a\xCC\x81",
                    .typelen = 3,
                    .parent = NULL,
                    .baton = NULL,
            ),
            E(ETAG, LOC("combining-mark.xml", 1, 4),
                    .type = U"a\xCC\x81",
                    .typelen = 3,
                    .baton = NULL,
                    .is_empty = false,
            ),
            END,
        },
    },
    {
        .desc = "NUL/restricted characters in input (1.0)",
        .input = "nul-restricted-char-1.0.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("nul-restricted-char-1.0.xml", 1, 19),
                    .info = XMLERR(ERROR, XML, P_Char),
                    .msg = "NUL character encountered",
            ),
            E(XMLDECL, LOC("nul-restricted-char-1.0.xml", 1, 1),
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            E_XMLDECL_A("nul-restricted-char-1.0.xml", 2, 1),
            E(MESSAGE, LOC("nul-restricted-char-1.0.xml", 3, 6),
                    .info = XMLERR(ERROR, XML, P_Char),
                    .msg = "Restricted character U+0001",
            ),
            E(MESSAGE, LOC("nul-restricted-char-1.0.xml", 4, 6),
                    .info = XMLERR(ERROR, XML, P_Char),
                    .msg = "Restricted character U+001E",
            ),
            END,
        },
    },
    {
        .desc = "NUL/restricted characters in input (1.1)",
        .input = "nul-restricted-char-1.1.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("nul-restricted-char-1.1.xml", 1, 19),
                    .info = XMLERR(ERROR, XML, P_Char),
                    .msg = "NUL character encountered",
            ),
            E(XMLDECL, LOC("nul-restricted-char-1.1.xml", 1, 1),
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_1,
            ),
            E_XMLDECL_A("nul-restricted-char-1.1.xml", 2, 1),
            E(MESSAGE, LOC("nul-restricted-char-1.1.xml", 3, 6),
                    .info = XMLERR(ERROR, XML, P_Char),
                    .msg = "Restricted character U+0001",
            ),
            E(MESSAGE, LOC("nul-restricted-char-1.1.xml", 4, 6),
                    .info = XMLERR(ERROR, XML, P_Char),
                    .msg = "Restricted character U+001E",
            ),
            E(MESSAGE, LOC("nul-restricted-char-1.1.xml", 5, 6),
                    .info = XMLERR(ERROR, XML, P_Char),
                    .msg = "Restricted character U+007F",
            ),
            E(MESSAGE, LOC("nul-restricted-char-1.1.xml", 6, 6),
                    .info = XMLERR(ERROR, XML, P_Char),
                    .msg = "Restricted character U+009F",
            ),
            END,
        },
    },
};

// To avoid defining twice inline...
#define VERY_LONG_ELEMENT_NAME \
        "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh" \
        "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh" \
        "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh" \
        "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh" \
        "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh" \
        "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh" \
        "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh" \
        "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh" \
        "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh" \
        "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh" \
        "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh" \
        "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh" \
        "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh" \
        "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh" \
        "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh" \
        "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh" \
        "abcdefgh"


static const testcase_t testcases_structure[] = {
    {
        .desc = "Simple opening/closing tags",
        .input = "simple-open-close.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL, LOC("simple-open-close.xml", 1, 1),
                    .encoding = "UTF-8",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            E(STAG, LOC("simple-open-close.xml", 2, 1),
                    .type = U"a",
                    .typelen = 1,
                    .parent = NULL,
                    .baton = NULL,
            ),
            E(ETAG, LOC("simple-open-close.xml", 2, 4),
                    .type = U"a",
                    .typelen = 1,
                    .baton = NULL,
                    .is_empty = false,
            ),
            END,
        },
    },
    {
        .desc = "Invalid top-level content (no XMLDecl)",
        .input = "invalid-top-level-nodecl.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("invalid-top-level-nodecl.xml", 1, 1),
                    .info = XMLERR(ERROR, XML, P_document),
                    .msg = "Invalid content at root level",
            ),
            E(MESSAGE, LOC("invalid-top-level-nodecl.xml", 2, 1),
                    .info = XMLERR(ERROR, XML, P_document),
                    .msg = "No root element",
            ),
            END,
        },
    },
    {
        .desc = "Invalid top-level content (with XMLDecl)",
        .input = "invalid-top-level.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL, LOC("invalid-top-level.xml", 1, 1),
                    .encoding = "UTF-8",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_1,
            ),
            E(MESSAGE, LOC("invalid-top-level.xml", 2, 1),
                    .info = XMLERR(ERROR, XML, P_document),
                    .msg = "Invalid content at root level",
            ),
            E(MESSAGE, LOC("invalid-top-level.xml", 3, 1),
                    .info = XMLERR(ERROR, XML, P_document),
                    .msg = "No root element",
            ),
            END,
        },
    },
    {
        .desc = "Invalid top-level content (with XMLDecl & root element)",
        .input = "invalid-top-level-withroot.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL, LOC("invalid-top-level-withroot.xml", 1, 1),
                    .encoding = "UTF-8",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_1,
            ),
            E(MESSAGE, LOC("invalid-top-level-withroot.xml", 2, 1),
                    .info = XMLERR(ERROR, XML, P_document),
                    .msg = "Invalid content at root level",
            ),
            E_XMLDECL_A("invalid-top-level-withroot.xml", 3, 1),
            END,
        },
    },
    {
        .desc = "DTD specified twice",
        .input = "dtd-twice.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("dtd-twice.xml", 2, 1),
                    .info = XMLERR(ERROR, XML, P_document),
                    .msg = "Document type definition not allowed here",
            ),
            E_XMLDECL_A("dtd-twice.xml", 3, 1),
            END,
        },
    },
    {
        .desc = "DTD specified after root element",
        .input = "dtd-after-element.xml",
        .events = (const xml_reader_cbparam_t[]){
            E_XMLDECL_A("dtd-after-element.xml", 1, 1),
            E(MESSAGE, LOC("dtd-after-element.xml", 2, 1),
                    .info = XMLERR(ERROR, XML, P_document),
                    .msg = "Document type definition not allowed here",
            ),
            END,
        },
    },
    {
        .desc = "Root element specified twice",
        .input = "root-element-twice.xml",
        .events = (const xml_reader_cbparam_t[]){
            E_XMLDECL_A("root-element-twice.xml", 1, 1),
            E(MESSAGE, LOC("root-element-twice.xml", 2, 1),
                    .info = XMLERR(ERROR, XML, P_document),
                    .msg = "One root element allowed in a document",
            ),
            E_XMLDECL_A("root-element-twice.xml", 2, 1),
            END,
        },
    },
    {
        .desc = "No root element",
        .input = "no-root-element.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL, LOC("no-root-element.xml", 1, 1),
                    .encoding = NULL,
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_1,
            ),
            E(MESSAGE, LOC("no-root-element.xml", 4, 1),
                    .info = XMLERR(ERROR, XML, P_document),
                    .msg = "No root element",
            ),
            END,
        },
    },
    {
        .desc = "Bad element type in empty tag",
        .input = "bad-emptytag-name.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("bad-emptytag-name.xml", 1, 2),
                    .info = XMLERR(ERROR, XML, P_STag),
                    .msg = "Expected element type",
            ),
            END,
        },
    },
    {
        .desc = "Bad element type in start tag",
        .input = "bad-stag-name.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(MESSAGE, LOC("bad-stag-name.xml", 1, 2),
                    .info = XMLERR(ERROR, XML, P_STag),
                    .msg = "Expected element type",
            ),
            END,
        },
    },
    {
        .desc = "Truncated start tag",
        .input = "truncated-stag.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(STAG, LOC("truncated-stag.xml", 1, 1),
                    .type = U"a",
                    .typelen = 1,
                    .parent = NULL,
                    .baton = NULL
            ),
            E(MESSAGE, LOC("truncated-stag.xml", 2, 1),
                    .info = XMLERR(ERROR, XML, P_STag),
                    .msg = "Element start tag truncated",
            ),
            END,
        },
    },
    {
        .desc = "Bad character in start tag #1",
        .input = "stag-badchar1.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(STAG, LOC("stag-badchar1.xml", 1, 1),
                    .type = U"element",
                    .typelen = 7,
                    .parent = NULL,
                    .baton = NULL
            ),
            E(MESSAGE, LOC("stag-badchar1.xml", 1, 9),
                    .info = XMLERR(ERROR, XML, P_STag),
                    .msg = "Expect whitespace, or >, or />",
            ),
            END,
        },
    },
    {
        .desc = "Bad character in start tag #2",
        .input = "stag-badchar2.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(STAG, LOC("stag-badchar2.xml", 1, 1),
                    .type = U"element",
                    .typelen = 7,
                    .parent = NULL,
                    .baton = NULL
            ),
            E(MESSAGE, LOC("stag-badchar2.xml", 1, 10),
                    .info = XMLERR(ERROR, XML, P_STag),
                    .msg = "Expect whitespace, or >, or />",
            ),
            END,
        },
    },
    {
        .desc = "No name in end tag",
        .input = "etag-noname.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(STAG, LOC("etag-noname.xml", 1, 1),
                    .type = U"a",
                    .typelen = 1,
                    .parent = NULL,
                    .baton = NULL
            ),
            E(MESSAGE, LOC("etag-noname.xml", 1, 6),
                    .info = XMLERR(ERROR, XML, P_ETag),
                    .msg = "Expected element type",
            ),
            END,
        },
    },
    {
        .desc = "Bad name in end tag",
        .input = "etag-badname.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(STAG, LOC("etag-badname.xml", 1, 1),
                    .type = U"a",
                    .typelen = 1,
                    .parent = NULL,
                    .baton = NULL
            ),
            E(MESSAGE, LOC("etag-badname.xml", 1, 6),
                    .info = XMLERR(ERROR, XML, P_ETag),
                    .msg = "Expected element type",
            ),
            END,
        },
    },
    {
        .desc = "End tag mismatch to start tag",
        .input = "etag-mismatch.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(STAG, LOC("etag-mismatch.xml", 1, 1),
                    .type = U"a",
                    .typelen = 1,
                    .parent = NULL,
                    .baton = NULL
            ),
            E(MESSAGE, LOC("etag-mismatch.xml", 1, 6),
                    .info = XMLERR(ERROR, XML, WFC_ELEMENT_TYPE_MATCH),
                    .msg = "Closing element type mismatch: 'b'"
            ),
            E(MESSAGE, LOC("etag-mismatch.xml", 1, 2),
                    .info = XMLERR_NOTE,
                    .msg = "Opening element: 'a'",
            ),
            E(ETAG, LOC("etag-mismatch.xml", 1, 4),
                    .type = U"b",
                    .typelen = 1,
                    .baton = NULL,
                    .is_empty = false,
            ),
            END,
        },
    },
    {
        .desc = "Missing closing bracket in end tag",
        .input = "etag-missing-bracket.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(STAG, LOC("etag-missing-bracket.xml", 1, 1),
                    .type = U"a",
                    .typelen = 1,
                    .parent = NULL,
                    .baton = NULL
            ),
            E(ETAG, LOC("etag-missing-bracket.xml", 1, 4),
                    .type = U"a",
                    .typelen = 1,
                    .baton = NULL,
                    .is_empty = false,
            ),
            E(MESSAGE, LOC("etag-missing-bracket.xml", 2, 1),
                    .info = XMLERR(ERROR, XML, P_ETag),
                    .msg = "Expected string: '>'",
            ),
            END,
        },
    },
    {
        .desc = "Element immediately following XMLDecl in non-ASCII",
        .input = "element-nonutf8-name.xml",
        .encoding = "ISO-8859-1",
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL, LOC("element-nonutf8-name.xml", 1, 1),
                    .encoding = "ISO-8859-1",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            E(STAG, LOC("element-nonutf8-name.xml", 1, 44),
                    .type = U"é",
                    .typelen = 2,
                    .parent = NULL,
                    .baton = NULL
            ),
            E(ETAG, LOC("element-nonutf8-name.xml", 1, 47),
                    .type = U"é",
                    .typelen = 2,
                    .baton = NULL,
                    .is_empty = false,
            ),
            END,
        },
    },
    {
        .desc = "Comments & Processing instructions",
        .input = "comments-pis.xml",
        .events = (const xml_reader_cbparam_t[]){
            E_XMLDECL_A("comments-pis.xml", 3, 1),
            END,
        },
    },
    {
        .desc = "Very long element name",
        .input = "very-long-token.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(STAG, LOC("very-long-token.xml", 1, 1),
                    .type = U VERY_LONG_ELEMENT_NAME,
                    .typelen = sizeof(VERY_LONG_ELEMENT_NAME) - 1,
                    .parent = NULL,
                    .baton = NULL
            ),
            E(ETAG, LOC("very-long-token.xml", 1, 1),
                    .type = U VERY_LONG_ELEMENT_NAME,
                    .typelen = sizeof(VERY_LONG_ELEMENT_NAME) - 1,
                    .baton = NULL,
                    .is_empty = true,
            ),
            END,
        },
    },
    {
        .desc = "Attributes",
        .input = "attributes.xml",
        .events = (const xml_reader_cbparam_t[]){
            E(STAG, LOC("attributes.xml", 1, 1),
                    .type = U"a",
                    .typelen = 1,
                    .parent = NULL,
                    .baton = NULL,
            ),
            E(ATTRNAME, LOC("attributes.xml", 1, 4),
                    .name = U"attr1",
                    .namelen = 5,
                    .elem_baton = NULL,
                    .attr_baton = NULL,
            ),
            E(ATTRVAL, LOC("attributes.xml", 1, 10),
                    .value = U"foo",
                    .valuelen = 3,
                    .attr_baton = NULL,
            ),
            E(ATTRNAME, LOC("attributes.xml", 1, 16),
                    .name = U"attr2",
                    .namelen = 5,
                    .elem_baton = NULL,
                    .attr_baton = NULL,
            ),
            E(ATTRVAL, LOC("attributes.xml", 1, 22),
                    .value = U"bar",
                    .valuelen = 3,
                    .attr_baton = NULL,
            ),
            E(ETAG, LOC("attributes.xml", 1, 1),
                    .type = U"a",
                    .typelen = 1,
                    .baton = NULL,
                    .is_empty = true,
            ),
            END,
        },
    },
};

static const testset_t testsets[] = {
    TEST_SET(run_testcase, "Various API tests", testcases_api),
    TEST_SET(run_testcase, "Encoding tests", testcases_encoding),
    TEST_SET(run_testcase, "XML/Text declaration tests", testcases_xmldecl),
    TEST_SET(run_testcase, "XML structures", testcases_structure),
};

static const testsuite_t testsuite = TEST_SUITE("Tests for XML reader API", testsets);

