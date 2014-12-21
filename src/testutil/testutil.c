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
    _('e'), _('n'), _('c'), _('o'), _('d'), _('i'), _('n'), _('g'), _(' '), _('='), _('\a'), _('"'), _('U'), _('T'), _('F'), _('-'), _('8'), _('"'), \
    _('\t'), _('?'), _('>'),

#define SAMPLE_TEXT_WITH_BOM \
    _(0xFEFF), SAMPLE_TEXT_WITHOUT_BOM

const uint8_t text_utf16be_bom[] = {
#define _ TO_UTF16BE
    SAMPLE_TEXT_WITH_BOM
#undef _
};

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
    xml_reader_set_transport_encoding(reader, "UTF-8");
    xml_reader_start(reader, NULL);
    xml_reader_delete(reader);

    return 0;
}
