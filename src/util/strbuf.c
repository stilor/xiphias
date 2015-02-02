/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    String buffer implementation.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/defs.h"
#include "util/queue.h"
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
    // TBD: is readptr needed? Or just advance the beginning of the first block?
    void *readptr;                              ///< Read pointer (1st block)
    uint32_t flags;                             ///< Buffer flags
    void *arg;                                  ///< Argument passed to ops
    const strbuf_ops_t *ops;                    ///< Operations vtable
};

/**
    Dummy input for a string buffer.

    @param buf Buffer
    @param arg Argument
    @return None
*/
static void
null_input(strbuf_t *buf, void *arg)
{
    OOPS_ASSERT(0); // This function should never have been called
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

/**
    Allocate a new string block with a given payload size.

    @param payload_sz Size of the payload
    @return Allocated string block
*/
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

/**
    Destroy a string block.

    @param blk Block being deleted.
    @return None
*/
void
strblk_delete(strblk_t *blk)
{
    xfree(blk);
}

/**
    Get the pointer to the beginning of the block's memory.

    @param blk Block to get the pointer for
    @return Pointer value
*/
void *
strblk_getptr(strblk_t *blk)
{
    return blk->begin;
}

/**
    Set the size of a block (possibly losing some memory at the end of the block)

    @param blk Block being trimmed
    @param sz New size; must be less than the old size
    @return None
*/
void
strblk_trim(strblk_t *blk, size_t sz)
{
    void *new_end = (uint8_t *)blk->begin + sz;

    OOPS_ASSERT(new_end <= blk->end);
    blk->end = new_end;
}

/**
    Allocate a new empty string buffer.

    @return Allocated buffer.
*/
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

/**
    Destroy a string buffer along with associated blocks.

    @param buf String buffer to destroy
    @return None
*/
void
strbuf_delete(strbuf_t *buf)
{
    strblk_t *blk;

    buf->ops->destroy(buf, buf->arg);
    while ((blk = STAILQ_FIRST(&buf->content)) != NULL) {
        STAILQ_REMOVE_HEAD(&buf->content, link);
        strblk_delete(blk);
    }
    xfree(buf);
}

/**
    Set operations for a buffer.

    @param buf Buffer
    @param ops Operations vtable
    @param arg Argument passed to operation methods
    @return None
*/
void
strbuf_setops(strbuf_t *buf, const strbuf_ops_t *ops, void *arg)
{
    buf->ops = ops;
    buf->arg = arg;
}

/**
    Set flags on a buffer.

    @param buf Buffer
    @param flags Flags to set
    @param mask Mask being set
    @return None
*/
void
strbuf_setf(strbuf_t *buf, uint32_t flags, uint32_t mask)
{
    buf->flags &= ~mask;
    buf->flags |= flags;
}

/**
    Get flags on a buffer.

    @param buf Buffer
    @param flags Flags to set
    @return None
*/
void
strbuf_getf(strbuf_t *buf, uint32_t *flags)
{
    *flags = buf->flags;
}

/**
    Append an empty block to a buffer.

    @param buf Buffer
    @param blk Block to be appended
    @return None
*/
void
strbuf_append_block(strbuf_t *buf, strblk_t *blk)
{
    OOPS_ASSERT(blk->end >= blk->begin);

    STAILQ_INSERT_TAIL(&buf->content, blk, link);
}

/**
    Check if end of file is reached.

    @param buf Buffer
    @return true if the buffer is at the end of file, false otherwise
*/
bool
strbuf_eof(strbuf_t *buf)
{
    void *begin, *end;

    strbuf_getptr(buf, &begin, &end);
    return begin == NULL;
}

/**
    Read certain amount from the buffer.

    @param buf Buffer
    @param dest Destination memory
    @param nbytes Read amount
    @param lookahead If true, does not advance current read pointer
    @param func Read termination function; if not NULL and returns true, read will
        terminate at the current character. If this argument is non-NULL, the string
        blocks added to this buffer must be properly sized and aligned for 32-bit reads.
        Destination buffer must also be properly sized and aligned.
    @param arg Argument to @a func
    @return Number of characters read.
*/
size_t
strbuf_read_until(strbuf_t *buf, uint8_t *dest, size_t nbytes, bool lookahead,
        strbuf_condread_func_t func, void *arg)
{
    strblk_t *blk, *next;
    uint8_t *begin, *end, *readptr;
    uint32_t *tmp;
    size_t i, avail;
    bool earlybreak = false;

    readptr = buf->readptr;
    next = STAILQ_FIRST(&buf->content);
    blk = NULL;
    do {
        if (!next && !(buf->flags & BUF_LAST)) {
            // Not enough queued data, need to fetch
            buf->ops->input(buf, buf->arg);
            next = blk ? STAILQ_NEXT(blk, link) : STAILQ_FIRST(&buf->content);
        }
        if (!next) {
            OOPS_ASSERT(0); // TBD return partial read?
        }
        // Have some queued data
        blk = next;
        begin = readptr ? readptr : blk->begin;
        end = blk->end;
        OOPS_ASSERT(begin <= end);
        avail = min(nbytes, (size_t)(end - begin));
        if (dest) {
            if (func) {
                // If function is provided, strbuf must contain UCS-4 characters,
                // with properly aligned and sized blocks.
                OOPS_ASSERT(((avail | (uintptr_t)begin) & 3) == 0);
                for (i = 0, tmp = (uint32_t *)begin; i < avail / 4; i++, tmp++, dest += 4) {
                    if (func(arg, *tmp)) {
                        earlybreak = true;
                        break;
                    }
                    *(uint32_t *)dest = *tmp;
                }
                avail = i * 4; // May have terminated early
            }
            else {
                memcpy(dest, begin, avail);
                dest += avail;
            }
        }
        readptr = begin + avail;
        nbytes -= avail;
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
    } while (!earlybreak && nbytes && !(buf->flags & BUF_LAST));

    if (!lookahead) {
        buf->readptr = readptr;
    }
    return 0; // TBD size of read
}

/**
    Get pointers to start/end of a current contiguous block.

    @param buf Buffer
    @param pbegin Pointer to the beginning of a block will be stored here
    @param pend Pointer to the end of a block will be stored here
    @return None (if no more input available, *pbegin and *pend are both set to NULL)
*/
void
strbuf_getptr(strbuf_t *buf, void **pbegin, void **pend)
{
    strblk_t *blk;

    if (STAILQ_EMPTY(&buf->content) && !(buf->flags & BUF_LAST)) {
        // Nothing yet? Try to fetch
        buf->ops->input(buf, buf->arg);
    }
    if ((blk = STAILQ_FIRST(&buf->content)) == NULL) {
        // Tried and couldn't get anything
        buf->flags |= BUF_LAST;
        *pbegin = *pend = NULL;
    }
    else {
        *pbegin = buf->readptr ? buf->readptr : blk->begin;
        *pend = blk->end;
    }
}

/**
    Create a string buffer representing a single contiguous block
    of memory for reading.

    @param start Memory start address
    @param size Memory size
    @param copy Copy the provided buffer
    @return String buffer
*/
strbuf_t *
strbuf_new_from_memory(const void *start, size_t size, bool copy)
{
    strbuf_t *buf = strbuf_new();
    strblk_t *blk = strblk_new(copy ? size : 0);

    // Point the block to the memory passed in and append it
    if (copy) {
        memcpy(blk->data, start, size);
        blk->begin = blk->data;
    }
    else {
        blk->begin = DECONST(start);
    }
    blk->end = (uint8_t *)blk->begin + size;
    strbuf_append_block(buf, blk);

    // Buffer has its one and only block
    buf->flags |= BUF_LAST;
    return buf;
}
