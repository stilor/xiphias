/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */
#include "util/xutil.h"
#include "xml/reader.h"

#include "test/common/enum.h"

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
