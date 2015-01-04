/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Operations on linked string buffers.

    String buffer is organized as a series of blocks, which store the actual data.
    Data is written to the buffer by appending a new string block.
*/

#ifndef __util_strbuf_h_
#define __util_strbuf_h_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/// Buffer flags
enum {
    BUF_LAST        = 0x0001,           ///< Last block in the list is the final block of the document
};

/// One block of text in a string buffer
typedef struct strblk_s strblk_t;

/// Linked list of text blocks - string buffer
typedef struct strbuf_s strbuf_t;

/// Operations on a string buffer
typedef struct strbuf_ops_s {
    void (*input)(strbuf_t *, void *);          ///< Request add'l input
    void (*destroy)(strbuf_t *, void *);        ///< Destroy the buffer
} strbuf_ops_t;

/**
    Allocate a new string block with a given payload size.

    @param payload_sz Size of the payload
    @return Allocated string block
*/
strblk_t *strblk_new(size_t payload_sz);

/**
    Destroy a string block.

    @param blk Block being deleted.
    @return None
*/
void strblk_delete(strblk_t *blk);

/**
    Get the pointer to the beginning of the block's memory.

    @param blk Block to get the pointer for
    @return Pointer value
*/
void *strblk_getptr(strblk_t *blk);

/**
    Set the size of a block (possibly losing some memory at the end of the block)

    @param blk Block being trimmed
    @param sz New size; must be less than the old size
    @return None
*/
void strblk_trim(strblk_t *blk, size_t sz);

/**
    Allocate a new empty string buffer.

    @return Allocated buffer.
*/
strbuf_t *strbuf_new(void);

/**
    Destroy a string buffer.

    @param buf Buffer being deleted.
    @return None
*/
void strbuf_delete(strbuf_t *buf);

/**
    Set operations for a buffer.

    @param buf Buffer
    @param ops Operations vtable
    @param arg Argument passed to operation methods
    @return None
*/
void strbuf_setops(strbuf_t *buf, const strbuf_ops_t *ops, void *arg);

/**
    Set flags on a buffer.

    @param buf Buffer
    @param flags Flags to set
    @param mask Mask being set
    @return None
*/
void strbuf_setf(strbuf_t *buf, uint32_t flags, uint32_t mask);

/**
    Get flags on a buffer.

    @param buf Buffer
    @param flags Flags to set
    @return None
*/
void strbuf_getf(strbuf_t *buf, uint32_t *flags);

/**
    Append an empty block to a buffer.

    @param buf Buffer
    @param blk Block to be appended
    @return None
*/
void strbuf_append_block(strbuf_t *buf, strblk_t *blk);

/**
    Create a string buffer representing a single contiguous block
    of memory for reading.

    @param start Memory start address
    @param size Memory size
    @param copy Copy the provided buffer
    @return String buffer
*/
strbuf_t *strbuf_new_from_memory(const void *start, size_t size, bool copy);

/**
    Destroy a string buffer along with associated blocks.

    @param buf String buffer to destroy
    @return None
*/
void strbuf_delete(strbuf_t *buf);

/**
    Read certain amount from the buffer.

    @param buf Buffer
    @param dest Destination memory
    @param nbytes Read amount
    @param lookahead If true, does not advance current read pointer
    @return None
*/
void strbuf_read(strbuf_t *buf, uint8_t *dest, size_t nbytes, bool lookahead);

/**
    Get pointers to start/end of a current contiguous block.

    @param buf Buffer
    @param pbegin Pointer to the beginning of a block will be stored here
    @param pend Pointer to the end of a block will be stored here
    @return None (if no more input available, *pbegin and *pend are both set to NULL)
*/
void strbuf_getptr(strbuf_t *buf, void **pbegin, void **pend);

#endif
