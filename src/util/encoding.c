/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    String buffer implementation.
*/
#include <string.h>

#include "xutil.h"
#include "strbuf.h"
#include "encoding.h"

// FIXME: this is not thread-safe. Protect registration/search with a mutex? Or require
// that registration be done before using anything else in multithreaded context?
static STAILQ_HEAD(, encoding_s) encodings = STAILQ_HEAD_INITIALIZER(encodings);

void
encoding_register(encoding_t *enc)
{
    if (encoding_search(enc->name)) {
        OOPS;
    }
    STAILQ_INSERT_TAIL(&encodings, enc, link);
}

const encoding_t *
encoding_search(const char *name)
{
    const encoding_t *enc;

    STAILQ_FOREACH(enc, &encodings, link) {
        if (!strcasecmp(name, enc->name)) {
            return enc;
        }
    }
    return NULL;
}

/*
    Below, basic 1-, 2- and 4-byte encodings.
*/


// --- UTF-8 encoding: dummy functions, this library operates in UTF8 ---

static void *
init_utf8(strbuf_t **pbuf, const void *data)
{
    return NULL;
}

static void
destroy_utf8(strbuf_t **pbuf, void *baton)
{
}

///
static encoding_t enc_utf8 = {
    .name = "UTF-8",
    .codeunit = 1,
    .init = init_utf8,
    .destroy = destroy_utf8,
};

static void __constructor
encodings_autoinit(void)
{
    encoding_register(&enc_utf8);
}
