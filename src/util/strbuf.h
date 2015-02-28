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

/// Linked list of text blocks - string buffer
typedef struct strbuf_s strbuf_t;

/// Operations on a string buffer
typedef struct strbuf_ops_s {
    /**
        Provide additional input for the buffer

        @param arg Argument set for callbacks
        @param begin Beginning of the next contiguous block in a buffer
        @param sz Size of the contiguous block
        @return Number of bytes placed into a buffer
    */
    size_t (*more)(void *arg, void *begin, size_t sz);

    /**
        Destroy arbitrary data associated with the buffer.

        @param arg Argument set for callbacks
        @return Nothing
    */
    void (*destroy)(void *arg);
} strbuf_ops_t;

// Creation/destruction
strbuf_t *strbuf_new(const void *mem, size_t sz);
void strbuf_realloc(strbuf_t *buf, size_t sz);
void strbuf_delete(strbuf_t *buf);
void strbuf_clear(strbuf_t *buf);

// Modifications
void strbuf_setops(strbuf_t *buf, const strbuf_ops_t *ops, void *arg);
void strbuf_defrag(strbuf_t *buf);

// Reading/writing
size_t strbuf_rptr(strbuf_t *buf, const void **pbegin, const void **pend);
size_t strbuf_wptr(strbuf_t *buf, void **pbegin, void **pend);
void strbuf_radvance(strbuf_t *buf, size_t sz);
void strbuf_wadvance(strbuf_t *buf, size_t sz);
size_t strbuf_lookahead(strbuf_t *buf, void *dest, size_t nbytes);

// String buffers for specific input methods
strbuf_t *strbuf_file_read(const char *path, size_t sz);
strbuf_t *strbuf_iconv_read(strbuf_t *input, const char *from, const char *to, size_t sz);

#endif
