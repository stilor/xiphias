/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    String buffer operations for reading from a file.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/defs.h"
#include "util/xutil.h"

#include "util/strbuf.h"

/**
    Read more data from a file.

    @param arg File pointer
    @param begin Start of the destination buffer
    @param size Size of the destination buffer
    @return Number of bytes read
*/
static size_t
file_more(void *arg, void *begin, size_t sz)
{
    FILE *f = arg;

    return fread(begin, 1, sz, f);
}

/**
    Destroy file associated with a buffer.

    @param arg File pointer
    @return Nothing
*/
static void
file_destroy(void *arg)
{
    FILE *f = arg;

    fclose(f);
}

/// String buffer operations on a file
static const strbuf_ops_t file_ops = {
    .more = file_more,
    .destroy = file_destroy,
};

/**
    Create a new file-reading string buffer.

    @param path Path to the file being read
    @param sz Initial buffer size
    @return String buffer structure
*/
strbuf_t *
strbuf_file_read(const char *path, size_t sz)
{
    FILE *f;
    strbuf_t *buf;

    // TBD: fail-free xfopen()?
    if ((f = fopen(path, "r")) == NULL) {
        OOPS_ASSERT(0);
    }
    buf = strbuf_new(NULL, sz);
    strbuf_setops(buf, &file_ops, f);
    return buf;
}
