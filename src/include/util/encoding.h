/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Encoding implementation interface and registry.
*/

#ifndef __encoding_h_
#define __encoding_h_

#include "queue.h"
#include "strbuf.h"

// FIXME: need to sets of init/destroy/xlate - for input and for output translations (from/to enc)

/// Encoding structure
typedef struct encoding_s {
    STAILQ_ENTRY(encoding_s) link;          ///< Linked list pointers
    const char *name;                       ///< Encoding name
    size_t codeunit;                        ///< Code unit size
    const void *data;                       ///< Encoding-specific data (e.g. equivalence chart)

    /**
        Initialize a translator.

        @param[in,out] pbuf Pointer to string buffer (may be replaced)
        @param[in] data Encoding-specific data
        @return Baton (argument passed to xlate/destroy methods)
    */
    void *(*init)(strbuf_t **pbuf, const void *data);

    /**
        Destroy a translator.

        @param[in,out] pbuf Pointer to string buffer (may be replaced)
        @param[in] baton Pointer returned by initializer
        @return Baton (argument passed to xlate/destroy methods)
    */
    void (*destroy)(strbuf_t **pbuf, void *baton);

    /**
        Perform the translation of some more content (up to the end of current
        block in the outbut buffer).

        @param[in] baton Pointer returned by initializer
        @param[in] nchars Number of characters to translate
        @return Baton (argument passed to xlate/destroy methods)
    */
    void (*xlate)(void *baton, size_t nchars);
} encoding_t;


/**
    Register an encoding.

    @param[in] enc Encoding being registered
    @return None
*/
void encoding_register(encoding_t *enc);

/**
    Search for an encoding by name

    @param[in] name Encoding name
    @return Encoding pointer, or NULL if not found
*/
const encoding_t *encoding_search(const char *name);

/**
    Check for byte order (via either byte order mark presence, or how
    the characters from a known start string are arranged). Assumes
    an XML document (which, aside from a possible byte order mark,
    must start with a "<?xml" string).

    @param[in] buf Buffer; must contain at least 4 characters
    @return Encoding name; or NULL if cannot be detected
*/
const char *encoding_detect_byte_order(strbuf_t *buf);

#endif
