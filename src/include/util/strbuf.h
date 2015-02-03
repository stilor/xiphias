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

// Blocks in a buffer
strblk_t *strblk_new(size_t payload_sz);
void strblk_delete(strblk_t *blk);
void *strblk_getptr(strblk_t *blk);
void strblk_trim(strblk_t *blk, size_t sz);

// Creation/destruction
strbuf_t *strbuf_new(void);
void strbuf_delete(strbuf_t *buf);

// Modifications
void strbuf_setops(strbuf_t *buf, const strbuf_ops_t *ops, void *arg);
void strbuf_setf(strbuf_t *buf, uint32_t flags, uint32_t mask);
void strbuf_getf(strbuf_t *buf, uint32_t *flags);
void strbuf_append_block(strbuf_t *buf, strblk_t *blk);

// Reading
void strbuf_read(strbuf_t *buf, uint8_t *dest, size_t nbytes, bool lookahead);
bool strbuf_eof(strbuf_t *buf);
void strbuf_getptr(strbuf_t *buf, void **pbegin, void **pend);

// Specific constructors
strbuf_t *strbuf_new_from_memory(const void *start, size_t size, bool copy);

#endif
