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

/// Buffer flags
enum {
    BUF_NO_INPUT        = 0x0001,   ///< No (further) input
    BUF_STATIC          = 0x0002,   ///< Memory for ring buffer was provided by caller
};

/// Linked list of text blocks - string buffer
struct strbuf_s {
    uint8_t *mem;           ///< Actual storage
    size_t memsz;           ///< Size of the storage buffer
    size_t roffs;           ///< Offset to readable data
    size_t rsize;           ///< Size of readable data
    const strbuf_ops_t *ops;///< Operations on a buffer
    void *arg;              ///< Argument to operations
    uint32_t flags;         ///< Flags on the buffer
};

/**
    Allocate a new empty string buffer.

    @param mem Memory to read, or NULL if a new storage is to be allocated.
        No copy of this memory is made, so the caller must not modify it
        while it's being read.
    @param sz Size of the buffer storage
    @return Allocated buffer.
*/
strbuf_t *
strbuf_new(const void *mem, size_t sz)
{
    strbuf_t *buf;

    buf = xmalloc(sizeof(strbuf_t));
    memset(buf, 0, sizeof(strbuf_t));
    buf->memsz = sz;
    if (mem) {
        // Use provided memory area, no input so it is not overwritten
        buf->mem = DECONST(mem); // We'll treat it as const by virtue of BUF_NO_INPUT
        buf->rsize = sz;
        buf->flags |= BUF_NO_INPUT | BUF_STATIC;
    }
    else {
        // Allocate a new area, empty initially
        buf->mem = xmalloc(sz);
    }
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
    if (buf->ops && buf->ops->destroy) {
        buf->ops->destroy(buf->arg);
    }
    if ((buf->flags & BUF_STATIC) == 0) {
        xfree(buf->mem);
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
    if (buf->ops && buf->ops->destroy) {
        buf->ops->destroy(buf->arg);
    }
    buf->ops = ops;
    buf->arg = arg;
}

/**
    Clear the contents of a string buffer.

    @param buf Buffer to clear
    @return Nothing
*/
void
strbuf_clear(strbuf_t *buf)
{
    buf->roffs = buf->rsize = 0;
}

/**
    Get pointers to start/end of a current contiguous readable block.

    @param buf Buffer
    @param pbegin Pointer to the beginning of a block will be stored here
    @param pend Pointer to the end of a block will be stored here
    @return Number of bytes available for reading
*/
size_t
strbuf_rptr(strbuf_t *buf, const void **pbegin, const void **pend)
{
    size_t end;

    if (!buf->rsize && (buf->flags & BUF_NO_INPUT) == 0
            && buf->ops && buf->ops->more) {
        // Empty: reset the read offset (so that we could fetch as much as
        // possible in one go), then try to get more from input method
        buf->roffs = 0;
        buf->rsize = buf->ops->more(buf->arg, buf->mem, buf->memsz);
        if (!buf->rsize) {
            buf->flags |= BUF_NO_INPUT; // Will not try to read again
        }
    }
    if ((end = buf->roffs + buf->rsize) > buf->memsz) {
        end = buf->memsz;
    }
    *pbegin = buf->mem + buf->roffs;
    *pend = buf->mem + end;
    return end - buf->roffs;
}

/**
    Get pointers to start/end of a current contiguous readable block.

    @param buf Buffer
    @param pbegin Pointer to the beginning of a block will be stored here
    @param pend Pointer to the end of a block will be stored here
    @return Number of bytes available for writing
*/
size_t
strbuf_wptr(strbuf_t *buf, void **pbegin, void **pend)
{
    size_t offs;

    if ((offs = buf->roffs + buf->rsize) >= buf->memsz) {
        // Writable area is contiguous
        offs -= buf->memsz;
        *pbegin = buf->mem + offs;
        *pend = buf->mem + buf->roffs;
        return buf->roffs - offs;
    }
    else {
        // Writable area wraps around buffer end
        *pbegin = buf->mem + offs;
        *pend = buf->mem + buf->memsz;
        return buf->memsz - offs;
    }
}

/**
    Advance read pointer.

    @param buf Buffer
    @param sz Amount to advance by
    @return Nothing
*/
void
strbuf_radvance(strbuf_t *buf, size_t sz)
{
    OOPS_ASSERT(sz <= buf->rsize);
    buf->rsize -= sz;
    buf->roffs += sz;
    if (buf->roffs >= buf->memsz) {
        buf->roffs -= buf->memsz;
    }
}

/**
    Advance write pointer.

    @param buf Buffer
    @param sz Amount to advance by
    @return Nothing
*/
void
strbuf_wadvance(strbuf_t *buf, size_t sz)
{
    OOPS_ASSERT(sz <= buf->memsz - buf->rsize);
    buf->rsize += sz;
}

/**
    Read certain amount from the buffer without advancing the pointer.

    @param buf Buffer
    @param dest Destination memory
    @param nbytes Read amount
    @return Number of characters read
*/
size_t
strbuf_lookahead(strbuf_t *buf, void *dest, size_t nbytes)
{
    size_t offs, sz;

    // First, if needed, grow the buffer to accommodate the request.
    // Reallocate to double the size of the request, so that we don't
    // have to reallocate often.
    if (buf->memsz < nbytes && (buf->flags & BUF_STATIC) == 0) {
        buf->memsz = 2 * nbytes;
        buf->mem = xrealloc(buf->mem, buf->memsz);
    }

    // Then, pull the data from input method until either requested
    // amount is satisfied, or the input method reports EOF
    if (buf->rsize < nbytes && (buf->flags & BUF_NO_INPUT) == 0
            && buf->ops && buf->ops->more) {
        offs = buf->roffs + buf->rsize;
        do {
            // No need to check writable size - we've allocated enough above
            if (offs >= buf->memsz) {
                offs -= buf->memsz;
            }
            sz = buf->ops->more(buf->arg, buf->mem + offs,
                    min(buf->memsz - offs, buf->memsz - buf->rsize));
            buf->rsize += sz;
            offs += sz;
            if (!sz) {
                buf->flags |= BUF_NO_INPUT; // Will not try to read again
                break;
            }
        } while (buf->rsize < nbytes);
    }

    // Then copy the data to the caller's buffer, if requested and advance the
    // read pointer, again if requested.
    if ((nbytes = min(nbytes, buf->rsize)) == 0) {
        return 0; // No data to be copied
    }

    if (buf->roffs + nbytes <= buf->memsz) {
        // Readable data contiguous
        memcpy(dest, buf->mem + buf->roffs, nbytes);
    }
    else {
        // Readable data wraps around
        sz = buf->memsz - buf->roffs;
        memcpy(dest, buf->mem + buf->roffs, sz);
        memcpy((uint8_t *)dest + sz, buf->mem, nbytes - sz);
    }

    return nbytes;
}
