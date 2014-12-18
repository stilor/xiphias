/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Encoding implementation interface and registry.
*/

#ifndef __util_encoding_h_
#define __util_encoding_h_

#include "queue.h"
#include "strbuf.h"

/// Types of encoding compatibility
enum encoding_compat_e {
    ENCODING_T_UNKNOWN,             ///< Unknown compatibility (always incompatible)
    ENCODING_T_UTF8,                ///< UTF-8 or other byte encoding with ASCII for 00..7e chars
    ENCODING_T_EBCDIC,              ///< Byte encodings compatible with EBCDIC
    ENCODING_T_UTF16LE,             ///< UTF-16, little endian
    ENCODING_T_UTF16BE,             ///< UTF-16, big endian
    ENCODING_T_UTF32LE,             ///< UTF-32, little endian
    ENCODING_T_UTF32BE,             ///< UTF-32, big endian
    ENCODING_T_UTF32_2143,          ///< UTF-32, unusual byte order (2143)
    ENCODING_T_UTF32_3412,          ///< UTF-32, unusual byte order (3412)
};

/// Encoding structure
typedef struct encoding_s {
    STAILQ_ENTRY(encoding_s) link;  ///< Linked list pointers
    const char *name;               ///< Encoding name
    enum encoding_compat_e enctype; ///< Encoding compatibility type
    const void *data;               ///< Encoding-specific data (e.g. equivalence chart)


    // TBD: need set of functions for output, too

    /**
        Initialize a translator.

        @param data Encoding-specific data
        @return Baton (argument passed to xlate/destroy methods)
    */
    void *(*init)(strbuf_t **pbuf, const void *data);

    /**
        Destroy a translator.

        @param pbuf Pointer to string buffer (may be replaced)
        @param baton Pointer returned by initializer
        @return Baton (argument passed to xlate/destroy methods)
    */
    void (*destroy)(strbuf_t **pbuf, void *baton);

    /**
        Perform the translation of some more content (up to the end of current
        block in the outbut buffer).

        @param baton Pointer returned by initializer
        @param nchars Number of characters to translate
        @return Baton (argument passed to xlate/destroy methods)
    */
    uint32_t (*xlate)(void *baton, size_t nchars);
} encoding_t;


/**
    Register an encoding.

    @param enc Encoding being registered
    @return None
*/
void encoding_register(encoding_t *enc);

/**
    Search for an encoding by name

    @param name Encoding name
    @return Encoding pointer, or NULL if not found
*/
const encoding_t *encoding_search(const char *name);

/**
    Check if two encodings are compatible.

    @param enc1 First encoding
    @param enc2 Second encoding
    @return true if encodings are compatible, false otherwise
*/
bool encoding_compatible(const encoding_t *enc1, const encoding_t *enc2);

/**
    Check for byte order (via either byte order mark presence, or how
    the characters from a known start string are arranged). Assumes
    an XML document (which, aside from a possible byte order mark,
    must start with a "<?xml" string).

    @param buf Buffer; must contain at least 4 characters
    @return Encoding name; or NULL if cannot be detected
*/
const char *encoding_detect_byte_order(strbuf_t *buf);

#endif
