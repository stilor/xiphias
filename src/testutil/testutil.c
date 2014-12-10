/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

#include <stdio.h>

#include "strbuf.h"
#include "xutil.h"

const uint8_t text_utf16be_bom[] = {
    0xFE, 0xFF, 0x00, 0x3C, 0x00, 0x3F, 0x00, 0x78, 0x00, 0x6d,
};

int
main(int argc, char *argv[])
{
    strbuf_t *buf;

    buf = strbuf_new_from_memory(text_utf16be_bom, sizeof(text_utf16be_bom));
    printf("%p\n", buf);
    strbuf_delete(buf);

    return 0;
}
