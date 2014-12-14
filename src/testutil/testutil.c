/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

#include <stdio.h>
#include <string.h>

#include "util/strbuf.h"
#include "util/xutil.h"

#define C(x) ((x) ? "PASS" : "FAIL")

const uint8_t text_utf16be_bom[] = {
    0xFE, 0xFF, 0x00, 0x3C, 0x00, 0x3F, 0x00, 0x78, 0x00, 0x6d,
};

int
main(int argc, char *argv[])
{
    strbuf_t *buf;
    uint8_t xxx[sizeof(text_utf16be_bom)];
    size_t readable;

    buf = strbuf_new_from_memory(text_utf16be_bom, sizeof(text_utf16be_bom));
    printf("%s %p\n", C(buf != NULL), buf);
    readable = strbuf_content_size(buf);
    printf("%s %zu\n", C(readable == sizeof(text_utf16be_bom)), readable);
    memset(xxx, 0, sizeof(xxx));
    strbuf_read(buf, xxx, sizeof(xxx), 1);
    printf("%s\n", C(memcmp(xxx, text_utf16be_bom, sizeof(xxx)) == 0));
    readable = strbuf_content_size(buf);
    printf("%s %zu\n", C(readable == sizeof(text_utf16be_bom)), readable);
    memset(xxx, 0, sizeof(xxx));
    strbuf_read(buf, xxx, sizeof(xxx), 0);
    printf("%s\n", C(memcmp(xxx, text_utf16be_bom, sizeof(xxx)) == 0));
    readable = strbuf_content_size(buf);
    printf("%s %zu\n", C(readable == 0), readable);
    strbuf_delete(buf);

    return 0;
}
