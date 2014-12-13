/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    String buffer implementation.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xutil.h"
#include "strbuf.h"

// New block
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
    buf->write.block = NULL;
    buf->write.ptr = NULL;
    buf->read.block = NULL;
    buf->read.ptr = NULL;
    buf->readable = 0;
    buf->writable = 0;
    buf->flags = 0;
    buf->arg = NULL;
    buf->io = NULL;
    buf->destroy = NULL;
    return buf;
}

// Append empty block
void
strbuf_append_block(strbuf_t *buf, strblk_t *blk)
{
    OOPS_ASSERT(blk->end >= blk->begin);

    if (STAILQ_EMPTY(&buf->content)) {
        buf->flags |= BUF_FIRST;
    }
    STAILQ_INSERT_TAIL(&buf->content, blk, link);
    if (!buf->read.block) {
        buf->read.block = blk;
        buf->read.ptr = blk->begin;
    }
    if (!buf->write.block) {
        buf->write.block = blk;
        buf->write.ptr = blk->begin;
    }
    buf->writable += (size_t)((uint8_t *)blk->end - (uint8_t *)blk->begin);
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

    // Advance the write pointer to the end of the block (no more writing)
    strbuf_write(buf, NULL, size);

    // Buffer has its one and only block
    buf->flags |= BUF_LAST;
    return buf;
}

// Delete a buffer
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

// Readable amount
size_t
strbuf_content_size(strbuf_t *buf)
{
    return buf->readable;
}

// Writable amount
size_t
strbuf_space_size(strbuf_t *buf)
{
    return buf->writable;
}

// Advance read cursor
void
strbuf_read(strbuf_t *buf, uint8_t *dest, size_t nbytes)
{
    strblk_t *blk, *tmp;
    uint8_t *begin, *end;
    size_t avail;
    bool brk;

    OOPS_ASSERT(nbytes <= buf->readable);
    buf->readable -= nbytes;
    blk = buf->read.block;
    STAILQ_FOREACH_FROM_SAFE(blk, &buf->content, link, tmp) {
restart:
        begin = (blk == buf->read.block) ? buf->read.ptr : blk->begin;
        if (blk == buf->write.block) {
            end = buf->write.ptr;
            brk = true;
        }
        else {
            end = blk->end;
            brk = false;
        }
        avail = end - begin;
        if (nbytes < avail) {
            avail = nbytes;
        }
        if (dest) {
            memcpy(dest, begin, avail);
            dest += avail;
        }
        buf->read.block = blk;
        buf->read.ptr = begin + avail;
        nbytes -= avail;
        if (!nbytes) {
            return;
        }

        if (brk && buf->io && !(buf->flags & BUF_LAST)) {
            // Hit the write cursor; see if we can get more
            buf->io(buf, nbytes);
            if (!(buf->flags & BUF_LAST)) {
                goto restart;
            }
        }

        // nbytes covers all the available content and then maybe some
        OOPS_ASSERT(!brk); // Would advance past the write cursor

        // this block goes away - both reader and writer are done with it
        OOPS_ASSERT(blk == STAILQ_FIRST(&buf->content));
        STAILQ_REMOVE_HEAD(&buf->content, link);
        strblk_delete(blk);
    }

    // May get here if the list is empty and nbytes was 0; otherwise, we advanced
    // to the end and wanted some more
    OOPS_ASSERT(nbytes == 0);
}

// Advance write cursor
void
strbuf_write(strbuf_t *buf, const uint8_t *src, size_t nbytes)
{
    strblk_t *blk;
    uint8_t *begin, *end;
    size_t avail;

    OOPS_ASSERT(nbytes <= buf->writable);
    buf->writable -= nbytes;
    buf->readable += nbytes;
    blk = buf->write.block;
    STAILQ_FOREACH_FROM(blk, &buf->content, link) {
        begin = (blk == buf->write.block) ? buf->write.ptr : blk->begin;
        end = blk->end;
        avail = end - begin;
        if (nbytes < avail) {
            avail = nbytes;
        }
        if (src) {
            memcpy(begin, src, avail);
            src += avail;
        }
        buf->write.block = blk;
        buf->write.ptr = begin + avail;
        nbytes -= avail;
        if (!nbytes) {
            return;
        }
        // completed writing this block - before advancing to the next, let the consumer process it
        if (buf->io) {
            // TBD - what would be the amount? Perhaps, change to 'fill a readv-style iov[]' API?
        }
    }

    // May get here if the list is empty and nbytes was 0; otherwise, we advanced
    // to the end and wanted some more
    OOPS_ASSERT(nbytes == 0);
}
