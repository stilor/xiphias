/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

#include <stdio.h>
#include <string.h>

#include "util/strbuf.h"
#include "util/encoding.h"
#include "util/xutil.h"
#include "xml/reader.h"

#define C(x) ((x) ? "PASS" : "FAIL")

#define TO_UTF16LE(x) (x & 0xFF), ((x >> 8) & 0xFF)
#define TO_UTF16BE(x) ((x >> 8) & 0xFF), (x & 0xFF)

#define SAMPLE_TEXT_WITHOUT_BOM \
    _('<'), _('?'), _('x'), _('m'), _('l'), _(' '), \
    _('v'), _('e'), _('r'), _('s'), _('i'), _('o'), _('n'), _('='), \
    _('"'), _('1'), _('.'), _('0'), _('"'), _(' '), \
    _('e'), _('n'), _('c'), _('o'), _('d'), _('i'), _('n'), _('g'), _('='), \
    _('"'), _('U'), _('T'), _('F'), _('-'), _('1'), _('6'), _('"'), \
    _('?'), _('>'), _('<'), _('a'), _('/'), _('>')

#define SAMPLE_TEXT_WITH_BOM \
    _(0xFEFF), SAMPLE_TEXT_WITHOUT_BOM

const uint8_t text_utf16be_bom[] = {
#define _ TO_UTF16BE
    SAMPLE_TEXT_WITH_BOM
#undef _
};

// TBD
static void
xmldecl_cb(void *arg, const xml_reader_cbparam_t *cbparam)
{
    static const char * const stdalone[] = {
        [XML_INFO_STANDALONE_NO_VALUE] = "???",
        [XML_INFO_STANDALONE_YES] = "yes",
        [XML_INFO_STANDALONE_NO] = "no",
    };
    static const char * const xmlversion[] = {
        [XML_INFO_VERSION_NO_VALUE] = "???",
        [XML_INFO_VERSION_1_0] = "1.0",
        [XML_INFO_VERSION_1_1] = "1.1",
    };
    const xml_reader_cbparam_xmldecl_t *x = &cbparam->xmldecl;

    printf("%s: %s, encoding '%s', standalone '%s', version '%s'\n",
            __func__,
            x->has_decl ? "has declaration" : "implied declaration",
            x->encoding ? x->encoding : "<unknown>",
            stdalone[x->standalone],
            xmlversion[x->version]);
}

int
main(int argc, char *argv[])
{
    xml_reader_t *reader;
    strbuf_t *buf;
    uint8_t xxx[sizeof(text_utf16be_bom)];
    const char *enc;
    bool had_bom;

    // Basic strbuf
    buf = strbuf_new_from_memory(text_utf16be_bom, sizeof(text_utf16be_bom), false);
    printf("%s %p\n", C(buf != NULL), buf);
    memset(xxx, 0, sizeof(xxx));
    strbuf_read(buf, xxx, sizeof(xxx), true);
    printf("%s\n", C(memcmp(xxx, text_utf16be_bom, sizeof(xxx)) == 0));
    enc = encoding_detect_byte_order(buf, &had_bom);
    printf("%s %s\n", C(enc && !strcmp(enc, "UTF-16BE")), enc ? enc : "<NULL>");
    printf("%s %s BOM\n", C(had_bom), had_bom ? "had" : "did not have");
    memset(xxx, 0, sizeof(xxx));
    strbuf_read(buf, xxx, sizeof(xxx), false);
    printf("%s\n", C(memcmp(xxx, text_utf16be_bom + 2, sizeof(xxx) - 2) == 0));
    strbuf_delete(buf);

    // Now via the XML reader
    buf = strbuf_new_from_memory(text_utf16be_bom, sizeof(text_utf16be_bom), false);
    reader = xml_reader_new(buf);
    xml_reader_set_callback(reader, XML_READER_CB_XMLDECL, xmldecl_cb, NULL);
    xml_reader_process_xml(reader, true);
    xml_reader_delete(reader);

    return 0;
}
