/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    String buffer implementation.
*/
#include <stdio.h>
#include <stdlib.h>

#include "xutil.h"
#include "strbuf.h"

strblk_t *
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

void
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
    buf->write.block = NULL;
    buf->write.ptr = NULL;
    buf->read.block = NULL;
    buf->read.ptr = NULL;
    buf->flags = 0;
    buf->arg = NULL;
    buf->io = NULL;
    buf->destroy = NULL;
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

    if (buf->destroy) {
        buf->destroy(buf);
    }
    while ((blk = STAILQ_FIRST(&buf->content)) != NULL) {
        STAILQ_REMOVE_HEAD(&buf->content, link);
        strblk_delete(blk);
    }
    free(buf);
}

size_t
strbuf_content_size(strbuf_t *buf)
{
    strblk_t *blk;
    uint8_t *begin, *end;
    size_t avail = 0;
    bool brk = false;

    OOPS_ASSERT(buf->read.block && buf->write.block);
    blk = buf->read.block;
    STAILQ_FOREACH_FROM(blk, &buf->content, link) {
        // Read cursor is always behind the write cursor
        begin = (blk == buf->read.block) ? buf->read.ptr : blk->begin;
        if (blk == buf->write.block) {
            end = buf->write.ptr;
            brk = true;
        }
        else {
            end = blk->end;
        }
        avail += (size_t)(end - begin);
        if (brk) {
            break;
        }
    }
    return avail;
}

size_t
strbuf_space_size(strbuf_t *buf)
{
    strblk_t *blk;
    uint8_t *begin;
    size_t avail = 0;

    OOPS_ASSERT(buf->write.block);
    blk = buf->write.block;
    STAILQ_FOREACH_FROM(blk, &buf->content, link) {
        begin = (blk == buf->write.block) ? buf->write.ptr : blk->begin;
        avail += (size_t)((uint8_t *)blk->end - begin);
    }
    return avail;
}

void
strbuf_advance_read(strbuf_t *buf, size_t nbytes)
{
    strblk_t *blk, *tmp;
    uint8_t *begin, *end;
    bool brk = false;

    OOPS_ASSERT(buf->read.block && buf->write.block);
    blk = buf->read.block;
    STAILQ_FOREACH_FROM_SAFE(blk, &buf->content, link, tmp) {
        begin = (blk == buf->read.block) ? buf->read.ptr : blk->begin;
        if (blk == buf->write.block) {
            end = buf->write.ptr;
            brk = true;
        }
        else {
            end = blk->end;
        }
        if (begin + nbytes <= end) {
            // Remains in the current block - advance and be done
            buf->read.block = blk;
            buf->read.ptr = begin + nbytes;
            return;
        }
        // nbytes covers all the available content and then maybe some
        OOPS_ASSERT(!brk); // advancing past the write cursor

        // this block goes away - both reader and writer are done with it
        OOPS_ASSERT(blk == STAILQ_FIRST(&buf->content));
        STAILQ_REMOVE_HEAD(&buf->content, link);
        strblk_delete(blk);
    }

    OOPS; // Advanced to the end and wanted some more
}

void
strbuf_advance_write(strbuf_t *buf, size_t nbytes)
{
    // TBD
}
