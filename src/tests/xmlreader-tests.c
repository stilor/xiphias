/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

static const testcase_t testcases[] = {
    {
        .desc = "Simple XML in UTF-16BE, with BOM",
        .input = "reader-000.xml",
        .use_bom = true,
        .encoding = "UTF-16BE",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL,
                    .has_decl = true,
                    .encoding = "UTF-16",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            END,
        },
    },
    {
        .desc = "Simple XML in UTF-16LE, with BOM",
        .input = "reader-000.xml",
        .use_bom = true,
        .encoding = "UTF-16LE",
        .transport_encoding = NULL,
        .events = (const xml_reader_cbparam_t[]){
            E(XMLDECL,
                    .has_decl = true,
                    .encoding = "UTF-16",
                    .standalone = XML_INFO_STANDALONE_NO_VALUE,
                    .version = XML_INFO_VERSION_1_0,
            ),
            END,
        },
    },
};
