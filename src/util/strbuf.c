/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    String buffer implementation.
*/
#include <stdio.h>
#include <stdlib.h>

#include "xutil.h"
#include "strbuf.h"

/**
    Allocate a new string block with a given payload size.

    @param[in] payload_sz Size of the payload
    @return Allocated string block
*/
static strblk_t *
strblk_new(size_t payload_sz)
{
    strblk_t *blk;

    OOPS_ASSERT(payload_sz % sizeof(uint32_t) == 0);
    blk = xmalloc(sizeof(strblk_t) + payload_sz);
    if (payload_sz) {
        blk->begin = blk->allocated;
        blk->end = (uint8_t *)blk->begin + payload_sz;
    }
    else {
        blk->end = blk->begin = NULL;
    }
    return blk;
}

/**
    Destroy a string block.

    @param[in] blk Block being deleted.
    @return None
*/
static void
strblk_delete(strblk_t *blk)
{
    free(blk);
}

strbuf_t *
strbuf_new(void)
{
    strbuf_t *buf;

    buf = xmalloc(sizeof(strbuf_t));
    STAILQ_INIT(&buf->content);
    STAILQ_INIT(&buf->free);
    buf->write.block = NULL;
    buf->write.ptr = NULL;
    buf->read.block = NULL;
    buf->read.ptr = NULL;
    buf->flags = 0;
    return buf;
}

strbuf_t *
strbuf_new_from_memory(const void *start, size_t size)
{
    strbuf_t *buf = strbuf_new();
    strblk_t *blk = strblk_new(0);

    // Point the block to the memory passed in
    blk->begin = DECONST(start);
    blk->end = (uint8_t *)blk->begin + size;

    // Set read pointer to the beginning and write pointer to the end
    // of the only block in this list
    STAILQ_INSERT_TAIL(&buf->content, blk, link);
    buf->write.block = buf->read.block = blk;
    buf->read.ptr = blk->begin;
    buf->write.ptr = blk->end;
    buf->flags |= BUF_FIRST | BUF_LAST;
    return buf;
}

void
strbuf_delete(strbuf_t *buf)
{
    strblk_t *blk;

    while ((blk = STAILQ_FIRST(&buf->content)) != NULL) {
        STAILQ_REMOVE_HEAD(&buf->content, link);
        strblk_delete(blk);
    }
    while ((blk = STAILQ_FIRST(&buf->free)) != NULL) {
        STAILQ_REMOVE_HEAD(&buf->free, link);
        strblk_delete(blk);
    }
    free(buf);
}
