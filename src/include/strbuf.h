/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Operations on linked string buffers.
*/

#ifndef __strbuf_h_
#define __strbuf_h_

#include <stdint.h>
#include "queue.h"

/// String buffer status codes
enum {
    STATUS_OK   = 0,        ///< OK
    STATUS_NEEDINPUT,       ///< Need more input data
};

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
    STAILQ_HEAD(, strblk_s) content;    ///< Current content
    STAILQ_HEAD(, strblk_s) free;       ///< Free blocks
    strcursor_t write;                  ///< Write cursor
    strcursor_t read;                   ///< Read cursor
    uint8_t flags;                      ///< Buffer flags
} strbuf_t;

/**
    Allocate a new empty string buffer.

    @return Allocated buffer.
*/
strbuf_t *strbuf_new(void);

/**
    Create a string buffer representing a single contiguous block
    of memory.

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
void strbuf_destroy(strbuf_t *buf);

#endif
