/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Encoding implementation interface and registry.
*/

#ifndef __unicode_encoding_h_
#define __unicode_encoding_h_

#include "util/defs.h"
#include "util/queue.h"
#include "util/strbuf.h"
#include "unicode/unicode.h"

/// Types of encoding compatibility
enum encoding_form_e {
    ENCODING_FORM_UNKNOWN,          ///< Unknown compatibility (always incompatible)
    ENCODING_FORM_UTF8,             ///< UTF-8 or other byte encoding with ASCII for 00..7e chars
    ENCODING_FORM_UTF16,            ///< UTF-16
    ENCODING_FORM_UTF32,            ///< UTF-32
    ENCODING_FORM_EBCDIC,           ///< Byte encodings compatible with EBCDIC
};

/// Endianness of the encoding scheme
enum encoding_endian_e {
    ENCODING_E_ANY,                 ///< Don't care or not applicable
    ENCODING_E_LE,                  ///< Little-endian
    ENCODING_E_BE,                  ///< Big-endian
    ENCODING_E_2143,                ///< Unusual byte order (2143)
    ENCODING_E_3412,                ///< Unusual byte order (3412)
};

/// "Signatures" of the encodings - Byte-order marks + XML specific start strings
typedef struct encoding_sig_s {
    const uint8_t *sig;             ///< Byte signature
    size_t len;                     ///< Length of the signature
    bool bom;                       ///< Is this signature a byte-order mark?
} encoding_sig_t;

/// Initializer for a list of encoding signatures
#define ENCODING_SIG(b, ...) \
{ \
    .bom = (b), \
    .sig = (const uint8_t []){ __VA_ARGS__ }, \
    .len = sizeof((const uint8_t []){ __VA_ARGS__ }), \
}

/// Encoding structure
typedef struct encoding_s {
    const utf8_t *name;             ///< Encoding name
    enum encoding_form_e form;      ///< Character encoding form
    enum encoding_endian_e endian;  ///< Endianness
    const void *data;               ///< Encoding-specific data (e.g. equivalence chart)
    size_t baton_sz;                ///< Size of the baton data
    const encoding_sig_t *sigs;     ///< Signatures for encoding autodetection
    size_t nsigs;                   ///< Number of known signatures

    /**
        Initialize a translator.

        @param baton Baton (argument passed to in/destroy methods)
        @param data Encoding-specific data
        @return
    */
    void (*init)(void *baton, const void *data);

    /**
        Destroy a translator.

        @param baton Pointer returned by initializer
        @return None
    */
    void (*destroy)(void *baton);

    /**
        Perform the translation of some input.

        @todo Need a similar function for output.

        @param baton Pointer returned by initializer
        @param begin Start of the input buffer
        @param end End of the input buffer
        @param out Output UCS-4 buffer (adjusted to the next unused character)
        @param end_out Pointer at the next byte past the end of output buffer
        @return Number of bytes consumed in input buffer
    */
    size_t (*in)(void *baton, const uint8_t *begin, const uint8_t *end,
            ucs4_t **pout, ucs4_t *end_out);

    /**
        Check if the current state of baton is "clean" - i.e., contains
        no partially decoded characters.

        @todo Need a similar function for output.

        @param baton Pointer returned by initializer
        @return True if no mid-character in the runtime structure
    */
    bool (*in_clean)(void *baton);

} encoding_t;

/// Linking encodings into a list
typedef struct encoding_link_s {
    STAILQ_ENTRY(encoding_link_s) link;     ///< Link pointer
    const encoding_t *enc;                  ///< Pointer to actual encoding
} encoding_link_t;

/// Automatically register an encoding at the library load
#define ENCODING_REGISTER(e) \
static void __constructor \
e##_autoregister(void) \
{ \
    static encoding_link_t lnk; \
    lnk.enc = &e; \
    encoding__register(&lnk); \
}

/// Handle for an open encoding
typedef struct encoding_handle_s encoding_handle_t;

// General encoding database functions
void encoding__register(encoding_link_t *lnk);
const encoding_t *encoding_search(const utf8_t *name, enum encoding_endian_e endian);
const encoding_t *encoding_detect(const uint8_t *buf, size_t bufsz, size_t *pbom_len);

// Handling transcoding
encoding_handle_t *encoding_open(const encoding_t *);
void encoding_reopen(encoding_handle_t *hnd);
const encoding_t *encoding_get(encoding_handle_t *hnd);
bool encoding_switch(encoding_handle_t **hndcur, encoding_handle_t *hndnew);
void encoding_close(encoding_handle_t *hnd);
size_t encoding_in(encoding_handle_t *hnd, const uint8_t *begin, const uint8_t *end,
        uint32_t **pout, uint32_t *end_out);
size_t encoding_in_from_strbuf(encoding_handle_t *hnd, strbuf_t *buf,
        uint32_t **pout, uint32_t *end_out);
bool encoding_clean(encoding_handle_t *hnd);

/// Implementation of codepage-based encodings
typedef struct encoding_codepage_baton_s {
    const uint32_t *map;        ///< Mapping from single byte to UCS-4
} encoding_codepage_baton_t;

void encoding_codepage_init(void *baton, const void *data);
size_t encoding_codepage_in(void *baton, const uint8_t *begin, const uint8_t *end,
        ucs4_t **pout, ucs4_t *end_out);

#endif
