/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Helper for two flavors of UTF-16 implementation.
    Expects FUNC, TOHOST macros to be defined.
*/

static void
FUNC(strbuf_t *buf, void *baton, uint32_t **pout, uint32_t *end_out)
{
    uint32_t *out = *pout;
    uint8_t tmp[2]; // Temporary buffer if a char straddles block boundary
    uint32_t surrogate, val;
    uint8_t *ptr, *begin, *end;
    size_t needmore;

    surrogate = 0;
    needmore = 0;
    do {
        strbuf_getptr(buf, (void **)&begin, (void **)&end);
        if (begin == end) {
            // No more input available. Check if we're in the middle of the sequence
            if (surrogate || needmore) {
                OOPS;
            }
            break;
        }
        ptr = begin;

        // 0x360DC00 is ((0xD800 << 10) | 0xDC00)
#define NEXTCHAR_UTF16 \
        if (surrogate) { \
            if ((val & 0xFC00) != 0xDC00) { \
                OOPS; /* invalid byte sequence */ \
            } \
            *out++ = 0x010000 + ((surrogate << 10) ^ val ^ 0x360DC00); \
            surrogate = 0; \
        } \
        else if ((val & 0xFC00) == 0xD800) { \
            surrogate = val; \
        } \
        else { \
            *out++ = val; \
        }

        if (needmore) { // incomplete character in previous block, finish it
            tmp[1] = *ptr++;
            needmore = 0;
            val = TOHOST(tmp);
            NEXTCHAR_UTF16;
        }
        // Reads 2 characters at a time - thus 'end - 1'
        while (out < end_out && ptr < end - 1) {
            val = TOHOST(ptr);
            NEXTCHAR_UTF16;
            ptr += 2;
        }
        if (out < end_out && ptr < end) {
            // Incomplete character remains in the block - save for next block
            tmp[0] = *ptr++;
            needmore = 1;
        }

#undef NEXTCHAR_UTF16

        // Mark the number of bytes we consumed as read
        strbuf_read(buf, NULL, ptr - begin, false);
    } while (out < end_out);

    *pout = out;
}

#undef FUNC
#undef TOHOST
