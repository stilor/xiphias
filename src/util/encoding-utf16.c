/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/// Helper macro to store next character; handles surrogate pairs
#define NEXTCHAR_UTF16(b, o, e) \
        do { \
            uint32_t surrogate_bits = b.val & 0xFC00; \
            if (b.surrogate) { \
                /* Expecting low surrogate */ \
                if (surrogate_bits == 0xDC00) { \
                    /* Found low surrogate; store combined value */ \
                    /* 0x360DC00 is ((0xD800 << 10) | 0xDC00) */ \
                    *o++ = 0x010000 + ((b.surrogate << 10) ^ b.val ^ 0x360DC00); \
                    b.surrogate = 0; \
                    break; \
                } \
                else { \
                    /* Invalid value: store replacement, will need to re-parse value normally */ \
                    *o++ = UNICODE_REPLACEMENT_CHARACTER; \
                    b.surrogate = 0; \
                    if (o == e) { \
                        /* No more space; will reparse b.val in the next call */ \
                        b.val_valid = true; \
                        break; \
                    } \
                } \
            } \
            if (surrogate_bits == 0xD800) { \
                /* high surrogate - store and expect low surrogate as next unit */ \
                b.surrogate = b.val; \
            } \
            else if (surrogate_bits == 0xDC00) { \
                *o++ = UNICODE_REPLACEMENT_CHARACTER; \
            } \
            else { \
                *o++ = b.val; \
            } \
        } while (0)

/** @file
    Helper for two flavors of UTF-16 implementation.
    Expects FUNC, TOHOST macros to be defined.

    @param baton Pointer to structure with mapping table
    @param begin Pointer to the start of the input buffer
    @param end Pointer to the end of the input buffer
    @param pout Start of the output buffer (updated to point to next unused dword)
    @param end_out Pointer to the end of the output buffer
    @return Number of bytes consumed from the input buffer
*/
static size_t
FUNC(void *baton, const uint8_t *begin, const uint8_t *end, uint32_t **pout, uint32_t *end_out)
{
    baton_utf16_t utf16b; // Local copy to avoid access via pointer
    uint32_t *out = *pout;
    const uint8_t *ptr = begin;

    memcpy(&utf16b, baton, sizeof(baton_utf16_t));

    // Re-parse value that did not fit on last call (in case of invalid surrogate pair,
    // e.g. <D800 0400>, we need to store 2 codepoints: U+FFFD U+0400. If the output buffer
    // only had space for one, the other is kept in utf16b.val, and utf16b.surrogate is
    // cleared, so this invocation of NEXTCHAR_UTF16 stores at most one codepoint.
    if (utf16b.val_valid && out < end_out) {
        utf16b.val_valid = false;
        NEXTCHAR_UTF16(utf16b, out, end_out);
    }
    // Finish incomplete unit from previous block, if needed
    if (utf16b.straddle && ptr < end && out < end_out) {
        utf16b.straddle = false;
        utf16b.tmp[1] = *ptr++;
        utf16b.val = TOHOST(utf16b.tmp);
        NEXTCHAR_UTF16(utf16b, out, end_out);
    }
    // Reads 2 characters at a time - thus 'end - 1'
    while (ptr < end - 1 && out < end_out) {
        utf16b.val = TOHOST(ptr);
        ptr += 2;
        NEXTCHAR_UTF16(utf16b, out, end_out);
    }
    // If stopped one byte short of end - store it for the next call
    if (ptr == end - 1) {
        utf16b.tmp[0] = *ptr++;
        utf16b.straddle = true;
    }
    memcpy(baton, &utf16b, sizeof(baton_utf16_t));
    *pout = out;
    return ptr - begin;
}

#undef NEXTCHAR_UTF16
#undef FUNC
#undef TOHOST
