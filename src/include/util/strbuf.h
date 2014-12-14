/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Operations on linked string buffers.

    String buffer is organized as a series of blocks, which store the actual data.
    Data is written to the buffer by appending a new string block.
*/

#ifndef __strbuf_h_
#define __strbuf_h_

#include <stdbool.h>
#include <stdint.h>
#include "queue.h"

/// Buffer flags
enum {
    BUF_LAST        = 0x0001,           ///< Last block in the list is the final block of the document
};

/// One block of text in a string buffer
typedef struct strblk_s strblk_t;

/// Linked list of text blocks - string buffer
typedef struct strbuf_s strbuf_t;

/// Operations on a string buffer
typedef struct strbuf_opts_s {
    void (*input)(strbuf_t *, void *, size_t);  ///< Request add'l input
    void (*destroy)(strbuf_t *, void *);        ///< Destroy the buffer
} strbuf_ops_t;

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
    Destroy a string buffer.

    @param[in] buf Buffer being deleted.
    @return None
*/
void strbuf_delete(strbuf_t *buf);

/**
    Set operations for a buffer.

    @param[in] buf Buffer
    @param[in] ops Operations vtable
    @param[in] arg Argument passed to operation methods
    @return None
*/
void strbuf_setops(strbuf_t *buf, strbuf_ops_t *ops, void *arg);

/**
    Set flags on a buffer.

    @param[in] buf Buffer
    @param[in] flags Flags to set
    @param[in] mask Mask being set
    @return None
*/
void strbuf_setf(strbuf_t *buf, uint32_t flags, uint32_t mask);

/**
    Get flags on a buffer.

    @param[in] buf Buffer
    @param[out] flags Flags to set
    @return None
*/
void strbuf_getf(strbuf_t *buf, uint32_t *flags);

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
    Read certain amount from the buffer.

    @param[in] buf Buffer
    @param[out] dest Destination memory
    @param[in] nbytes Read amount
    @param[in] lookahead If true, does not advance current read pointer
    @return None
*/
void strbuf_read(strbuf_t *buf, uint8_t *dest, size_t nbytes, bool lookahead);

#endif
