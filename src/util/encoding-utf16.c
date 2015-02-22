/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

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
    const uint8_t *ptr = begin;

    memcpy(&utf16b, baton, sizeof(baton_utf16_t));

    // Re-parse value that did not fit on last call (in case of invalid surrogate pair,
    // e.g. <D800 0400>, we need to store 2 codepoints: U+FFFD U+0400. If the output buffer
    // only had space for one, the other is kept in utf16b.val, and utf16b.surrogate is
    // cleared, so this invocation of NEXTCHAR_UTF16 stores at most one codepoint.
    if (utf16b.val_valid && *pout < end_out) {
        utf16b.val_valid = false;
        nextchar_utf16(&utf16b, utf16b.val, pout, end_out);
    }
    // Finish incomplete unit from previous block, if needed
    if (utf16b.straddle && ptr < end && *pout < end_out) {
        utf16b.straddle = false;
        utf16b.tmp[1] = *ptr++;
        nextchar_utf16(&utf16b, TOHOST(utf16b.tmp), pout, end_out);
    }
    // Reads 2 characters at a time - thus 'end - 1'
    while (ptr < end - 1 && *pout < end_out) {
        nextchar_utf16(&utf16b, TOHOST(ptr), pout, end_out);
        ptr += 2;
    }
    // If stopped one byte short of end and have space - store it for the next call
    // (we may come here if we already have stored byte and we were not able to store
    // the next output character; in that case, do not store anything)
    if (ptr == end - 1 && !utf16b.straddle) {
        utf16b.tmp[0] = *ptr++;
        utf16b.straddle = true;
    }
    memcpy(baton, &utf16b, sizeof(baton_utf16_t));
    return ptr - begin;
}

#undef FUNC
#undef TOHOST
