/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    String buffer implementation.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/defs.h"
#include "util/xutil.h"

#include "util/strbuf.h"

/// One block of text in a string buffer
struct strblk_s {
    STAILQ_ENTRY(strblk_s) link;        ///< List link pointers
    void *begin;                        ///< First byte of the buffer
    void *end;                          ///< Byte past the last one
    uint32_t data[];                    ///< Memory allocated along with the block
};

/// Linked list of text blocks - string buffer
struct strbuf_s {
    STAILQ_HEAD(, strblk_s) content;            ///< Current content
    void *readptr;                              ///< Read pointer (1st block)
    uint32_t readable;                          ///< Length of readable content
    uint32_t flags;                             ///< Buffer flags
    void *arg;                                  ///< Argument passed to ops
    const strbuf_ops_t *ops;                    ///< Operations vtable
};

/**
    Dummy input for a string buffer.

    @param buf Buffer
    @param arg Argument
    @param sz Desired input size
    @return None
*/
static void
null_input(strbuf_t *buf, void *arg, size_t sz)
{
    OOPS;
}

/**
    Dummy destructor; no-op.

    @param buf Buffer
    @param arg Argument
    @return None
*/
static void
null_destroy(strbuf_t *buf, void *arg)
{
    // No-op
}

static const strbuf_ops_t null_ops = {
    .input = null_input,
    .destroy = null_destroy,
};

// New block
strblk_t *
strblk_new(size_t payload_sz)
{
    strblk_t *blk;

    OOPS_ASSERT(payload_sz % sizeof(uint32_t) == 0);
    blk = xmalloc(sizeof(strblk_t) + payload_sz);
    if (payload_sz) {
        blk->begin = blk->data;
        blk->end = (uint8_t *)blk->begin + payload_sz;
    }
    else {
        blk->end = blk->begin = NULL;
    }
    return blk;
}

// Delete a block
void
strblk_delete(strblk_t *blk)
{
    free(blk);
}

// New buffer
strbuf_t *
strbuf_new(void)
{
    strbuf_t *buf;

    buf = xmalloc(sizeof(strbuf_t));
    STAILQ_INIT(&buf->content);
    buf->readptr = NULL;
    buf->flags = 0;
    buf->ops = &null_ops;
    buf->arg = NULL;
    return buf;
}

// Append empty block
void
strbuf_append_block(strbuf_t *buf, strblk_t *blk)
{
    OOPS_ASSERT(blk->end >= blk->begin);

    STAILQ_INSERT_TAIL(&buf->content, blk, link);
    if (!buf->readptr) {
        buf->readptr = blk->begin;
    }
    buf->readable += (uint8_t *)blk->end - (uint8_t *)blk->begin;
}

// New buffer for reading from memory
strbuf_t *
strbuf_new_from_memory(const void *start, size_t size)
{
    strbuf_t *buf = strbuf_new();
    strblk_t *blk = strblk_new(0);

    // Point the block to the memory passed in and append it
    blk->begin = DECONST(start);
    blk->end = (uint8_t *)blk->begin + size;
    strbuf_append_block(buf, blk);

    // Buffer has its one and only block
    buf->flags |= BUF_LAST;
    return buf;
}

// Delete a buffer
void
strbuf_delete(strbuf_t *buf)
{
    strblk_t *blk;

    buf->ops->destroy(buf, buf->arg);
    while ((blk = STAILQ_FIRST(&buf->content)) != NULL) {
        STAILQ_REMOVE_HEAD(&buf->content, link);
        strblk_delete(blk);
    }
    free(buf);
}

// Set flags
void
strbuf_setf(strbuf_t *buf, uint32_t flags, uint32_t mask)
{
    buf->flags &= ~mask;
    buf->flags |= flags;
}

// Get flags
void
strbuf_getf(strbuf_t *buf, uint32_t *flags)
{
    *flags = buf->flags;
}

// Readable amount
size_t
strbuf_content_size(strbuf_t *buf)
{
    return buf->readable;
}

// Lookahead/read
void
strbuf_read(strbuf_t *buf, uint8_t *dest, size_t nbytes, bool lookahead)
{
    strblk_t *blk, *next;
    uint8_t *begin, *end, *readptr;
    size_t avail;

    readptr = buf->readptr;
    next = STAILQ_FIRST(&buf->content);
    blk = NULL;
    do {
        if (!next) {
            // Not enough queued data, need to fetch
            buf->ops->input(buf, buf->arg, nbytes);
            next = blk ? STAILQ_NEXT(blk, link) : STAILQ_FIRST(&buf->content);
            if (!next) {
                OOPS; // TBD return partial read?
            }
        }
        // Have some queued data
        blk = next;
        begin = readptr ? readptr : blk->begin;
        end = blk->end;
        OOPS_ASSERT(begin <= end);
        avail = min(nbytes, (size_t)(end - begin));
        memcpy(dest, begin, avail);
        dest += avail;
        readptr = begin + avail;
        nbytes -= avail;
        if (!lookahead) {
            buf->readable -= avail;
        }
        OOPS_ASSERT((uint8_t *)readptr <= end);
        if (readptr == end) {
            next = NULL;
            readptr = NULL;
            if (!lookahead) {
                // This block is done; release it and advance
                STAILQ_REMOVE_HEAD(&buf->content, link);
                strblk_delete(blk);
                blk = NULL;
            }
        }
    } while (nbytes && !(buf->flags & BUF_LAST));

    if (!lookahead) {
        buf->readptr = readptr;
    }
}
