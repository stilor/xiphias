/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Operations on linked string buffers.

    String buffer is organized as a series of blocks, which store the actual data.
    The buffer maintains two cursors, for writing and reading. By definition, read
    cursor may never advance past the write cursor (or it would read uninitialized
    data). Read cursor always points somewhere in the first block on the list
    (once read cursor moves past the first block, the first block is no longer
    accessible and will be dequeued/freed).

    There are two modes of operation for a string buffer, pull and push. In pull mode
    the string buffer is read by the consumer. Whenever it becomes empty (no content
    to read), the io() function is called to put additional content into the buffer.
    In push mode, the content is written into the buffer; whenever a full block becomes
    available, the io() method is called to flush it. The selection of the mode is
    the responsibility of the caller/user of the interface; if the buffer is used in both
    ways at the same time, io() method will be called on both conditions.

    THe destroy() method is called right before the string buffer is destroyed.
*/

#ifndef __strbuf_h_
#define __strbuf_h_

#include <stdbool.h>
#include <stdint.h>
#include "queue.h"

/// Buffer flags
enum {
    BUF_FIRST       = 0x0001,           ///< First block in the list is the beginning of the document
    BUF_LAST        = 0x0002,           ///< Last block in the list is the final block of the document
};

/// One block of text in a string buffer
typedef struct strblk_s {
    STAILQ_ENTRY(strblk_s) link;        ///< List link pointers
    void *begin;                        ///< First byte of the buffer
    void *end;                          ///< Byte past the last one
    uint32_t allocated[];               ///< Memory allocated along with the block
} strblk_t;

/// Cursor in the buffer
typedef struct strcursor_s {
    strblk_t *block;                    ///< Current block
    void *ptr;                          ///< Pointer into the block
} strcursor_t;

/// Linked list of text blocks - string buffer
typedef struct strbuf_s {
    STAILQ_HEAD(, strblk_s) content;        ///< Current content
    strcursor_t write;                      ///< Write cursor
    strcursor_t read;                       ///< Read cursor
    uint32_t readable;                      ///< Length of readable content
    uint32_t writable;                      ///< Length of writable space
    uint32_t flags;                         ///< Buffer flags
    void *arg;                              ///< Argument for virtual methods
    void (*io)(struct strbuf_s *, size_t);  ///< Read more data into the buffer, or write from it
    void (*destroy)(struct strbuf_s *);     ///< Called when the string buffer is destroyed
} strbuf_t;

/**
    Allocate a new string block with a given payload size.

    @param[in] payload_sz Size of the payload
    @return Allocated string block
*/
strblk_t *strblk_new(size_t payload_sz);

/**
    Destroy a string block.

    @param[in] blk Block being deleted.
    @return None
*/
void strblk_delete(strblk_t *blk);

/**
    Allocate a new empty string buffer.

    @return Allocated buffer.
*/
strbuf_t *strbuf_new(void);

/**
    Append an empty block to a buffer.

    @param[in] buf Buffer
    @param[in] blk Block to be appended
    @return None
*/
void strbuf_append_block(strbuf_t *buf, strblk_t *blk);

/**
    Create a string buffer representing a single contiguous block
    of memory for reading.

    @param[in] start Memory start address
    @param[in] size Memory size
    @return String buffer
*/
strbuf_t *strbuf_new_from_memory(const void *start, size_t size);

/**
    Destroy a string buffer along with associated blocks.

    @param[in] buf String buffer to destroy
    @return None
*/
void strbuf_delete(strbuf_t *buf);

/**
    Calculate the size of the content available for reading in the buffer.

    @param[in] buf Buffer string
    @return Content size, in bytes
*/
size_t strbuf_content_size(strbuf_t *buf);

/**
    Calculate the size of the empty space available for writing in the buffer.

    @param[in] buf Buffer string
    @return Space size, in bytes
*/
size_t strbuf_space_size(strbuf_t *buf);

/**
    Read certain amount from the buffer.

    @param[in] buf Buffer
    @param[out] dest Destination memory, or NULL to advance the cursor
            without actually reading
    @param[in] nbytes Read amount
    @return None
*/
void strbuf_read(strbuf_t *buf, uint8_t *dest, size_t nbytes);

/**
    Advance write cursor by a number of bytes.

    @param[in] buf Buffer
    @param[in] src Source memory, or NULL to advance the cursor without
            actually writing
    @param[in] nbytes Write amount
    @return None
*/
void strbuf_write(strbuf_t *buf, const uint8_t *src, size_t nbytes);

#endif
