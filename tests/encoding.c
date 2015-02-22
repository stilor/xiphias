/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "util/strbuf.h"
#include "util/encoding.h"
#include "util/unicode.h"
#include "util/xutil.h"
#include "test/testlib.h"

static const encoding_t enc_fake_UTF8 = {
    .name = "UTF-8",
};

static const encoding_sig_t sig_UTF8X[] = {
    ENCODING_SIG(true,  0xEF, 0xBB, 0xBF),
};

static size_t
in_UTF8X(void *baton, const uint8_t *begin, const uint8_t *end,
        uint32_t **pout, uint32_t *end_out)
{
    return end - begin;
}

static const encoding_t enc_UTF8_by_other_name = {
    .name = "UTF-8X",
    .sigs = sig_UTF8X,
    .nsigs = sizeofarray(sig_UTF8X),
    .in = in_UTF8X, // Must not be meta-encoding
};

static const encoding_sig_t sig_META[] = {
    ENCODING_SIG(true,  0xFF, 0xFE, 0xFD, 0xFC)
};

static const encoding_t enc_META = {
    .name = "META",
    .sigs = sig_META,
    .nsigs = sizeofarray(sig_META),
};

static const encoding_t enc_BADSIGS = {
    .name = "BADSIGS",
    .sigs = NULL,
    .nsigs = 1,
};

static result_t
run_tc_api(void)
{
    result_t rc = PASS;

    printf("Registering another UTF-8 encoding\n");
    EXPECT_OOPS_BEGIN();
    {
        static encoding_link_t lnk;
        lnk.enc = &enc_fake_UTF8;
        encoding__register(&lnk);
    }
    EXPECT_OOPS_END(rc = FAIL);

    printf("Registering another encoding with UTF-8 signature\n");
    EXPECT_OOPS_BEGIN();
    {
        static encoding_link_t lnk;
        lnk.enc = &enc_UTF8_by_other_name;
        encoding__register(&lnk);
    }
    EXPECT_OOPS_END(rc = FAIL);

    printf("Registering meta encoding with signature\n");
    EXPECT_OOPS_BEGIN();
    {
        static encoding_link_t lnk;
        lnk.enc = &enc_META;
        encoding__register(&lnk);
    }
    EXPECT_OOPS_END(rc = FAIL);

    printf("Registering encoding with NULL sigs but non-zero count\n");
    EXPECT_OOPS_BEGIN();
    {
        static encoding_link_t lnk;
        lnk.enc = &enc_BADSIGS;
        encoding__register(&lnk);
    }
    EXPECT_OOPS_END(rc = FAIL);

    return rc;
}

typedef struct testcase_detect_s {
    const uint8_t *input;
    size_t inputsz;
    size_t bom;
    const char *encoding;
} testcase_detect_t;

static result_t
run_tc_detect(const void *arg)
{
    const testcase_detect_t *tc = arg;
    size_t bom;
    const char *detected;
    result_t rc = PASS;

    printf("Trying signature for %s\n",
            tc->encoding ? tc->encoding : "<unknown encoding>");
    detected = encoding_detect(tc->input, tc->inputsz, &bom);
    if (!tc->encoding && !detected) {
        printf("Unknown encoding, not detected\n");
    }
    else if (!tc->encoding) {
        printf("Unknown encoding but detected '%s'\n", detected);
        rc = FAIL;
    }
    else if (!detected) {
        printf("Encoding '%s' not detected\n", tc->encoding);
        rc = FAIL;
    }
    else if (strcmp(detected, tc->encoding)) {
        printf("Encoding '%s' detected as '%s'\n", tc->encoding, detected);
        rc = FAIL;
    }
    else if (bom != tc->bom) {
        printf("BOM length mismatch %zu != %zu\n", tc->bom, bom);
        rc = FAIL;
    }

    return rc;
}

#define TC_DETECT(e, b, ...) \
{ \
    .encoding = (e), \
    .bom = (b), \
    .input = (const uint8_t []){ __VA_ARGS__ }, \
    .inputsz = sizeof((const uint8_t []){ __VA_ARGS__ }), \
}

static const testcase_detect_t testcase_detect[] = {
    // Test cases from XML 1.1, App. E, "Autodetection of Character Encodings"
    TC_DETECT("UTF-32BE", 4, 0x00, 0x00, 0xFE, 0xFF),
    TC_DETECT("UTF-32LE", 4, 0xFF, 0xFE, 0x00, 0x00),
    TC_DETECT("UTF-32-2143", 4, 0x00, 0x00, 0xFF, 0xFE),
    TC_DETECT("UTF-32-3412", 4, 0xFE, 0xFF, 0x00, 0x00),
    TC_DETECT("UTF-16BE", 2, 0xFE, 0xFF),
    TC_DETECT("UTF-16LE", 2, 0xFF, 0xFE),
    TC_DETECT("UTF-8", 3, 0xEF, 0xBB, 0xBF),
    TC_DETECT("UTF-32BE", 0, 0x00, 0x00, 0x00, 0x3C),
    TC_DETECT("UTF-32LE", 0, 0x3C, 0x00, 0x00, 0x00),
    TC_DETECT("UTF-32-2143", 0, 0x00, 0x00, 0x3C, 0x00),
    TC_DETECT("UTF-32-3412", 0, 0x00, 0x3C, 0x00, 0x00),
    TC_DETECT("UTF-16BE", 0, 0x00, 0x3C, 0x00, 0x3F),
    TC_DETECT("UTF-16LE", 0, 0x3C, 0x00, 0x3F, 0x00),
    TC_DETECT("UTF-8", 0, 0x3C, 0x3F, 0x78, 0x6D),
    TC_DETECT("IBM500", 0, 0x4C, 0x6F, 0xA7, 0x94),

    // Invalid and corner cases
    TC_DETECT("UTF-32BE", 0, 0x00, 0x00, 0x00),
    TC_DETECT("UTF-32BE", 4, 0x00, 0x00, 0xFE),
    TC_DETECT(NULL, 0, 0x03, 0x03, 0xFF, 0x03),
};


typedef struct testcase_utf8store_s {
    uint32_t codepoint;
    const uint8_t *utf8;
    size_t len;
    bool oops;
} testcase_utf8store_t;

static result_t
run_tc_utf8store(const void *arg)
{
    const testcase_utf8store_t *tc = arg;
    uint8_t buf[UTF8_LEN_MAX];
    uint8_t *ptr = buf;
    result_t rc = PASS;
    size_t len;

    if (tc->oops) {
        printf("Codepoint U+%04X: expect OOPS on len/store\n", tc->codepoint);
        EXPECT_OOPS_BEGIN();
        (void)utf8_len(tc->codepoint);
        EXPECT_OOPS_END(rc = FAIL);
        EXPECT_OOPS_BEGIN();
        utf8_store(&ptr, tc->codepoint);
        EXPECT_OOPS_END(rc = FAIL);
    }
    else {
        printf("Codepoint U+%04X: expect %zu byte sequence\n",
                tc->codepoint, tc->len);
        OOPS_ASSERT(tc->len <= UTF8_LEN_MAX);
        if (tc->len != (len = utf8_len(tc->codepoint))) {
            printf("But got %zu bytes as length!\n", len);
            rc = FAIL;
        }
        else {
            utf8_store(&ptr, tc->codepoint);
            if (ptr != buf + len) {
                printf("But stored %zu bytes!\n", len);
                rc = FAIL;
            }
            else if (memcmp(buf, tc->utf8, len)) {
                printf("Byte sequence does not match expected\n");
                rc = FAIL;
            }
        }
    }
    
    return rc;
}

#define TC_UTF8(cp, o, ...) \
{ \
    .codepoint = (cp), \
    .utf8 = (const uint8_t []){ __VA_ARGS__ }, \
    .len = sizeof((const uint8_t []){ __VA_ARGS__ }), \
    .oops = (o), \
}

static const testcase_utf8store_t testcase_utf8store[] = {
    TC_UTF8(0x000000, false, 0x00),
    TC_UTF8(0x000001, false, 0x01),
    TC_UTF8(0x000010, false, 0x10),
    TC_UTF8(0x00007F, false, 0x7F),
    TC_UTF8(0x000080, false, 0xC2, 0x80),
    TC_UTF8(0x000081, false, 0xC2, 0x81),
    TC_UTF8(0x0000BF, false, 0xC2, 0xBF),
    TC_UTF8(0x0000C0, false, 0xC3, 0x80),
    TC_UTF8(0x000100, false, 0xC4, 0x80),
    TC_UTF8(0x000400, false, 0xD0, 0x80),
    TC_UTF8(0x0007C0, false, 0xDF, 0x80),
    TC_UTF8(0x0007FF, false, 0xDF, 0xBF),
    TC_UTF8(0x000800, false, 0xE0, 0xA0, 0x80),
    TC_UTF8(0x000801, false, 0xE0, 0xA0, 0x81),
    TC_UTF8(0x00083F, false, 0xE0, 0xA0, 0xBF),
    TC_UTF8(0x000840, false, 0xE0, 0xA1, 0x80),
    TC_UTF8(0x000FFF, false, 0xE0, 0xBF, 0xBF),
    TC_UTF8(0x001000, false, 0xE1, 0x80, 0x80),
    TC_UTF8(0x00103F, false, 0xE1, 0x80, 0xBF),
    TC_UTF8(0x001040, false, 0xE1, 0x81, 0x80),
    TC_UTF8(0x001FFF, false, 0xE1, 0xBF, 0xBF),
    TC_UTF8(0x00F000, false, 0xEF, 0x80, 0x80),
    TC_UTF8(0x00F03F, false, 0xEF, 0x80, 0xBF),
    TC_UTF8(0x00FFC0, false, 0xEF, 0xBF, 0x80),
    TC_UTF8(0x00FFFF, false, 0xEF, 0xBF, 0xBF),
    TC_UTF8(0x010000, false, 0xF0, 0x90, 0x80, 0x80),
    TC_UTF8(0x01003F, false, 0xF0, 0x90, 0x80, 0xBF),
    TC_UTF8(0x010FC0, false, 0xF0, 0x90, 0xBF, 0x80),
    TC_UTF8(0x010FFF, false, 0xF0, 0x90, 0xBF, 0xBF),
    TC_UTF8(0x03F000, false, 0xF0, 0xBF, 0x80, 0x80),
    TC_UTF8(0x03F03F, false, 0xF0, 0xBF, 0x80, 0xBF),
    TC_UTF8(0x03FFC0, false, 0xF0, 0xBF, 0xBF, 0x80),
    TC_UTF8(0x03FFFF, false, 0xF0, 0xBF, 0xBF, 0xBF),
    TC_UTF8(0x040000, false, 0xF1, 0x80, 0x80, 0x80),
    TC_UTF8(0x080000, false, 0xF2, 0x80, 0x80, 0x80),
    TC_UTF8(0x0C0000, false, 0xF3, 0x80, 0x80, 0x80),
    TC_UTF8(0x100000, false, 0xF4, 0x80, 0x80, 0x80),
    TC_UTF8(0x10FFFF, false, 0xF4, 0x8F, 0xBF, 0xBF),
    TC_UTF8(0x110000, true),
    TC_UTF8(0x7FFFFFFF, true),
    TC_UTF8(0x80000000, true),
    TC_UTF8(0xFFFFFFFF, true),
};

/// Describes a single test case for XML reader
typedef struct testcase_input_s {
    const char *encoding;
	const char *desc;
	const uint8_t *input;
    size_t inputsz;
	const size_t *breaks;
	size_t nbreaks;
	const uint32_t *output;
	const size_t noutputs;
    bool dirty;
    bool one_at_a_time; // empty input, then 1 byte
} testcase_input_t;

static result_t
run_tc_input(const void *arg)
{
    const testcase_input_t *tc = arg;
    encoding_handle_t *eh;
    size_t lastbrk, nextbrk, sz, i;
    uint32_t *out, *ptr, *end, *old;
    uint32_t tmp;
    result_t rc = PASS;
    int alternator;

    printf("Testing %s: %s\n", tc->encoding, tc->desc);

    // Allocate and initialize with FF: this would make bad UCS-4 codepoints,
    // so the encodings will not produce them. This is needed for encodings
    // that need free space to parse their input - but may not produce an
    // output to actually use it.
    out = xmalloc(tc->noutputs * sizeof(uint32_t));
    memset(out, 0xFF, tc->noutputs * sizeof(uint32_t));
    ptr = out;
    end = out + tc->noutputs;

    eh = encoding_open(tc->encoding);
    for (i = 0, lastbrk = 0; i <= tc->nbreaks; i++, lastbrk = nextbrk) {
        nextbrk = i == tc->nbreaks ? tc->inputsz : tc->breaks[i];
        printf("  Decoding block [%zu..%zu]\n", lastbrk, nextbrk - 1);
        OOPS_ASSERT(nextbrk > lastbrk && nextbrk <= tc->inputsz);
        if (tc->one_at_a_time) {
            alternator = 1;
            sz = 0;
            do {
                // Read: 0 chars, 1 char, 0 chars, 1 char...
                alternator = !alternator;
                old = ptr;
                sz += encoding_in(eh, tc->input + lastbrk + sz, tc->input + nextbrk,
                        &ptr, ptr + alternator);
                // Repeat if:
                // - there's more input
                // - we didn't try to read at this time
                // - we read something (so there may be more output)
            } while (sz != nextbrk - lastbrk || !alternator || old != ptr);
        }
        else {
            sz = encoding_in(eh, tc->input + lastbrk, tc->input + nextbrk,
                    &ptr, end);
            if (nextbrk - lastbrk != sz) {
                rc = FAIL;
                printf("  Decoding block [%zu..%zu]: consumed %zu bytes\n",
                        lastbrk, nextbrk - 1, sz);
            }
        }
    }
    if (tc->dirty && encoding_clean(eh)) {
        printf("  Expected dirty handle - got clean\n");
        rc = FAIL;
    }
    else if (!tc->dirty && !encoding_clean(eh)) {
        printf("  Expected clean handle - got dirty\n");
        rc = FAIL;
    }
    if (memcmp(out, tc->output, tc->noutputs * sizeof(uint32_t))) {
        printf("  Result does not match!\n");
        rc = FAIL;
    }

    // Attempt to read extra dword (i.e. if the encoding has unflushed output)
    // (if the test case expects a dirty handle at the end, it may legally
    // have some unflushed output, so this part is skipped for such tests;
    // if handle clean status didn't match expected - we've complained above).
    if (encoding_clean(eh)) {
        ptr = &tmp;
        sz = encoding_in(eh, tc->input + tc->inputsz, tc->input + tc->inputsz,
                &ptr, ptr + 1);
        if (ptr != &tmp) {
            printf("  Encoding had unflushed output even though the handle "
                    "is reported as clean\n");
            rc = FAIL;
        }
    }

    encoding_close(eh);
    xfree(out);
    return rc;
}

#define TC_INPUT(...) \
        .input = (const uint8_t []){ __VA_ARGS__ }, \
        .inputsz = sizeof((const uint8_t []){ __VA_ARGS__ })
#define TC_BREAKS(...) \
        .breaks = (const size_t[]){ __VA_ARGS__ }, \
        .nbreaks = sizeofarray(((const size_t[]){ __VA_ARGS__ }))
#define TC_OUTPUT(...) \
        .output = (const uint32_t[]){ __VA_ARGS__ }, \
        .noutputs = sizeofarray(((const uint32_t[]){ __VA_ARGS__ }))

static const testcase_input_t testcase_inputs_UTF8[] = {
    {
        .encoding = "UTF-8",
        .desc = "Whole string at once",
        TC_INPUT(0x01, 0x07F, 0xC2, 0x80, 0xDF, 0xBF, 0xE0, 0xA0, 0x80, 0xEF, 0xBF, 0xBF,
                0xF0, 0x90, 0x80, 0x80, 0xF4, 0x8F, 0xBF, 0xBF, 0xED, 0x9F, 0xBF,
                0xEE, 0x80, 0x80),
        TC_BREAKS(),
        TC_OUTPUT(0x0001, 0x007F, 0x0080, 0x07FF, 0x800, 0xFFFF, 0x010000, 0x10FFFF,
                0xD7FF, 0xE000),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-8",
        .desc = "Breaks in multibyte characters",
        TC_INPUT(0x01, 0x07F, 0xC2, 0x80, 0xDF, 0xBF, 0xE0, 0xA0, 0x80, 0xEF, 0xBF, 0xBF,
                0xF0, 0x90, 0x80, 0x80, 0xF4, 0x8F, 0xBF, 0xBF),
        TC_BREAKS(3, 5, 7, 8, 10, 11, 13, 14, 15, 17, 18, 19),
        TC_OUTPUT(0x0001, 0x007F, 0x0080, 0x07FF, 0x800, 0xFFFF, 0x010000, 0x10FFFF),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-8",
        .desc = "One output at a time",
        TC_INPUT(0x01, 0x07F, 0xC2, 0x80, 0xDF, 0xBF, 0xE0, 0xA0, 0x80, 0xEF, 0xBF, 0xBF,
                0xF0, 0x90, 0x80, 0x80, 0xF4, 0x8F, 0xBF, 0xBF),
        TC_BREAKS(),
        TC_OUTPUT(0x0001, 0x007F, 0x0080, 0x07FF, 0x800, 0xFFFF, 0x010000, 0x10FFFF),
        .dirty = false,
        .one_at_a_time = true,
    },
    {
        .encoding = "UTF-8",
        .desc = "Invalid starter characters",
        TC_INPUT(0x20, 0x80, 0x21, 0xBF, 0x22, 0xC0, 0x23, 0xC1, 0x24),
        TC_BREAKS(),
        TC_OUTPUT(0x0020, 0xFFFD, 0x0021, 0xFFFD, 0x0022, 0xFFFD, 0x0023, 0xFFFD, 0x0024),
        .dirty = false,
        .one_at_a_time = true,
    },
    {
        .encoding = "UTF-8",
        .desc = "Invalid trailer characters",
        TC_INPUT(0x20, 0xC2, 0x7F, 0x21, 0xC2, 0xC0, 0x23,
                0xC2, 0xC2, 0x80, 0x24, 0xDF, 0x7F, 0x25, 0xDF, 0xC0, 0x26,
                0xE0, 0x9F, 0x27, 0xE0, 0xC0, 0x28,
                0xED, 0x7F, 0x29, 0xED, 0xA0, 0x2A,
                0xEF, 0x7F, 0x2B, 0xEF, 0xC0, 0x2C,
                0xF0, 0x8F, 0x2D, 0xF0, 0xC0, 0x2E,
                0xF4, 0x7F, 0x2F, 0xF4, 0x90, 0x30,
                0xE0, 0xA0, 0x7F, 0x31, 0xE0, 0xA0, 0xC0, 0x32, // error in 2nd trailer
                0xF0, 0x90, 0x80, 0x7F, 0x33, 0xF0, 0x90, 0x80, 0xC0, 0x34, // error in 3rd trailer
                ),
        TC_BREAKS(),
        TC_OUTPUT(0x0020, 0xFFFD, 0x007F, 0x0021, 0xFFFD, 0xFFFD, 0x0023,
                0xFFFD, 0x0080, 0x0024, 0xFFFD, 0x007F, 0x0025, 0xFFFD, 0xFFFD, 0x0026,
                0xFFFD, 0xFFFD, 0x0027, 0xFFFD, 0xFFFD, 0x0028,
                0xFFFD, 0x007F, 0x0029, 0xFFFD, 0xFFFD, 0x002A,
                0xFFFD, 0x007F, 0x002B, 0xFFFD, 0xFFFD, 0x002C,
                0xFFFD, 0xFFFD, 0x002D, 0xFFFD, 0xFFFD, 0x002E,
                0xFFFD, 0x007F, 0x002F, 0xFFFD, 0xFFFD, 0x0030,
                0xFFFD, 0x007F, 0x0031, 0xFFFD, 0xFFFD, 0x0032,
                0xFFFD, 0x007F, 0x0033, 0xFFFD, 0xFFFD, 0x0034,
                ),
        .dirty = false,
        .one_at_a_time = true,
    },
    {
        .encoding = "UTF-8",
        .desc = "Unclean (1 byte of 2-byte char)",
        TC_INPUT(0xC4),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFFFFFF),
        .dirty = true,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-8",
        .desc = "Unclean (1 byte of 3-byte char)",
        TC_INPUT(0xE3),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFFFFFF),
        .dirty = true,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-8",
        .desc = "Unclean (2 bytes of 3-byte char)",
        TC_INPUT(0xE3, 0x88),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFFFFFF),
        .dirty = true,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-8",
        .desc = "Unclean (1 byte of 4-byte char)",
        TC_INPUT(0xF1),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFFFFFF),
        .dirty = true,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-8",
        .desc = "Unclean (2 bytes of 4-byte char)",
        TC_INPUT(0xF1, 0x93),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFFFFFF),
        .dirty = true,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-8",
        .desc = "Unclean (3 bytes of 4-byte char)",
        TC_INPUT(0xF1, 0x93, 0x81),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFFFFFF),
        .dirty = true,
        .one_at_a_time = false,
    },
};

static const testcase_input_t testcase_inputs_UTF16BE[] = {
    {
        .encoding = "UTF-16BE",
        .desc = "Whole string at once",
        TC_INPUT(0x00, 0x80, 0x02, 0x38, 0xD8, 0x34, 0xDD, 0x1E, 0x99, 0xA5),
        TC_BREAKS(),
        TC_OUTPUT(0x0080, 0x0238, 0x1D11E, 0x99A5),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16BE",
        .desc = "Split regular character",
        TC_INPUT(0x00, 0x80, 0x02, 0x38, 0xD8, 0x34, 0xDD, 0x1E, 0x99, 0xA5),
        TC_BREAKS(1),
        TC_OUTPUT(0x0080, 0x0238, 0x1D11E, 0x99A5),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16BE",
        .desc = "Split regular character (one output at a time)",
        TC_INPUT(0x00, 0x80, 0x02, 0x38, 0xD8, 0x34, 0xDD, 0x1E, 0x99, 0xA5),
        TC_BREAKS(1),
        TC_OUTPUT(0x0080, 0x0238, 0x1D11E, 0x99A5),
        .dirty = false,
        .one_at_a_time = true,
    },
    {
        .encoding = "UTF-16BE",
        .desc = "High surrogate separate from low surrogate",
        TC_INPUT(0x00, 0x80, 0x02, 0x38, 0xD8, 0x34, 0xDD, 0x1E, 0x99, 0xA5),
        TC_BREAKS(6),
        TC_OUTPUT(0x0080, 0x0238, 0x1D11E, 0x99A5),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16BE",
        .desc = "Split high surrogate",
        TC_INPUT(0x00, 0x80, 0x02, 0x38, 0xD8, 0x34, 0xDD, 0x1E, 0x99, 0xA5),
        TC_BREAKS(5),
        TC_OUTPUT(0x0080, 0x0238, 0x1D11E, 0x99A5),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16BE",
        .desc = "Split low surrogate",
        TC_INPUT(0x00, 0x80, 0x02, 0x38, 0xD8, 0x34, 0xDD, 0x1E, 0x99, 0xA5),
        TC_BREAKS(7),
        TC_OUTPUT(0x0080, 0x0238, 0x1D11E, 0x99A5),
        .dirty = false,
    },
    {
        .encoding = "UTF-16BE",
        .desc = "One byte at a time",
        TC_INPUT(0x00, 0x80, 0x02, 0x38, 0xD8, 0x34, 0xDD, 0x1E, 0x99, 0xA5),
        TC_BREAKS(1, 2, 3, 4, 5, 6, 7, 8, 9),
        TC_OUTPUT(0x0080, 0x0238, 0x1D11E, 0x99A5),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16BE",
        .desc = "One output at a time, one byte at a time",
        TC_INPUT(0x00, 0x80, 0x02, 0x38, 0xD8, 0x34, 0xDD, 0x1E, 0x99, 0xA5),
        TC_BREAKS(1, 2, 3, 4, 5, 6, 7, 8, 9),
        TC_OUTPUT(0x0080, 0x0238, 0x1D11E, 0x99A5),
        .dirty = false,
        .one_at_a_time = true,
    },
    {
        .encoding = "UTF-16BE",
        .desc = "Missing low surrogate",
        TC_INPUT(0xDA, 0x53, 0x02, 0x44),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFD, 0x0244),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16BE",
        .desc = "Missing low surrogate (one output character available)",
        TC_INPUT(0xDA, 0x53, 0x02, 0x44),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFD, 0x0244),
        .dirty = false,
        .one_at_a_time = true,
    },
    {
        .encoding = "UTF-16BE",
        .desc = "Missing low surrogate - next high surrogate follows",
        TC_INPUT(0xDA, 0x53, 0xD9, 0x43, 0xDE, 0xFC),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFD, 0x60EFC),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16BE",
        .desc = "Low surrogate without preceding high",
        TC_INPUT(0xDE, 0xFC, 0xE2, 0x14),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFD, 0xE214),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16BE",
        .desc = "Unclean (half of a character)",
        TC_INPUT(0xD9),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFFFFFF),
        .dirty = true,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16BE",
        .desc = "Unclean (only high surrogate)",
        TC_INPUT(0xD9, 0xB2),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFFFFFF),
        .dirty = true,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16BE",
        .desc = "Unclean (bad surrogate + pending normal character)",
        TC_INPUT(0xD9, 0xB2, 0x00, 0x31),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFD),
        .dirty = true,
        .one_at_a_time = false,
    },
};

static const testcase_input_t testcase_inputs_UTF16LE[] = {
    {
        .encoding = "UTF-16LE",
        .desc = "Whole string at once",
        TC_INPUT(0x80, 0x00, 0x38, 0x02, 0x34, 0xD8, 0x1E, 0xDD, 0xA5, 0x99),
        TC_BREAKS(),
        TC_OUTPUT(0x0080, 0x0238, 0x1D11E, 0x99A5),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16LE",
        .desc = "Split regular character",
        TC_INPUT(0x80, 0x00, 0x38, 0x02, 0x34, 0xD8, 0x1E, 0xDD, 0xA5, 0x99),
        TC_BREAKS(1),
        TC_OUTPUT(0x0080, 0x0238, 0x1D11E, 0x99A5),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16LE",
        .desc = "Split regular character (one output at a time)",
        TC_INPUT(0x80, 0x00, 0x38, 0x02, 0x34, 0xD8, 0x1E, 0xDD, 0xA5, 0x99),
        TC_BREAKS(1),
        TC_OUTPUT(0x0080, 0x0238, 0x1D11E, 0x99A5),
        .dirty = false,
        .one_at_a_time = true,
    },
    {
        .encoding = "UTF-16LE",
        .desc = "High surrogate separate from low surrogate",
        TC_INPUT(0x80, 0x00, 0x38, 0x02, 0x34, 0xD8, 0x1E, 0xDD, 0xA5, 0x99),
        TC_BREAKS(6),
        TC_OUTPUT(0x0080, 0x0238, 0x1D11E, 0x99A5),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16LE",
        .desc = "Split high surrogate",
        TC_INPUT(0x80, 0x00, 0x38, 0x02, 0x34, 0xD8, 0x1E, 0xDD, 0xA5, 0x99),
        TC_BREAKS(5),
        TC_OUTPUT(0x0080, 0x0238, 0x1D11E, 0x99A5),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16LE",
        .desc = "Split low surrogate",
        TC_INPUT(0x80, 0x00, 0x38, 0x02, 0x34, 0xD8, 0x1E, 0xDD, 0xA5, 0x99),
        TC_BREAKS(7),
        TC_OUTPUT(0x0080, 0x0238, 0x1D11E, 0x99A5),
        .dirty = false,
    },
    {
        .encoding = "UTF-16LE",
        .desc = "One byte at a time",
        TC_INPUT(0x80, 0x00, 0x38, 0x02, 0x34, 0xD8, 0x1E, 0xDD, 0xA5, 0x99),
        TC_BREAKS(1, 2, 3, 4, 5, 6, 7, 8, 9),
        TC_OUTPUT(0x0080, 0x0238, 0x1D11E, 0x99A5),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16LE",
        .desc = "One output at a time, one byte at a time",
        TC_INPUT(0x80, 0x00, 0x38, 0x02, 0x34, 0xD8, 0x1E, 0xDD, 0xA5, 0x99),
        TC_BREAKS(1, 2, 3, 4, 5, 6, 7, 8, 9),
        TC_OUTPUT(0x0080, 0x0238, 0x1D11E, 0x99A5),
        .dirty = false,
        .one_at_a_time = true,
    },
    {
        .encoding = "UTF-16LE",
        .desc = "Missing low surrogate",
        TC_INPUT(0x53, 0xDA, 0x44, 0x02),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFD, 0x0244),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16LE",
        .desc = "Missing low surrogate (one output character available)",
        TC_INPUT(0x53, 0xDA, 0x44, 0x02),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFD, 0x0244),
        .dirty = false,
        .one_at_a_time = true,
    },
    {
        .encoding = "UTF-16LE",
        .desc = "Missing low surrogate - next high surrogate follows",
        TC_INPUT(0x53, 0xDA, 0x43, 0xD9, 0xFC, 0xDE),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFD, 0x60EFC),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16LE",
        .desc = "Low surrogate without preceding high",
        TC_INPUT(0xFC, 0xDE, 0x14, 0xE2),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFD, 0xE214),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16LE",
        .desc = "Unclean (half of a character)",
        TC_INPUT(0xA2),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFFFFFF),
        .dirty = true,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16LE",
        .desc = "Unclean (only high surrogate)",
        TC_INPUT(0xB2, 0xD9),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFFFFFF),
        .dirty = true,
        .one_at_a_time = false,
    },
    {
        .encoding = "UTF-16LE",
        .desc = "Unclean (bad surrogate + pending normal character)",
        TC_INPUT(0xB2, 0xD9, 0x31, 0x00),
        TC_BREAKS(),
        TC_OUTPUT(0xFFFD),
        .dirty = true,
        .one_at_a_time = false,
    },
};

static const testcase_input_t testcase_inputs_KOI8R[] = {
    {
        .encoding = "KOI8-R",
        .desc = "Simple test",
        TC_INPUT(0x20, 0x28, 0x31, 0x41, 0x5D, 0x80, 0x92, 0xAF, 0xBF, 0x9A, 0x9D),
        TC_BREAKS(),
        TC_OUTPUT(0x0020, 0x0028, 0x0031, 0x0041, 0x005D, 0x2500, 0x2593, 0x255E,
                0x00A9, 0x00A0, 0x00B2),
        .dirty = false,
        .one_at_a_time = false,
    },
    {
        .encoding = "KOI8-R",
        .desc = "Cyrillic characters, one at a time",
        TC_INPUT(0xA3, 0xB3, 0xC0, 0xC1, 0xCF, 0xD0, 0xD6, 0xDF, 0xE0, 0xE5, 0xEE, 0xEF,
                0xF0, 0xF2, 0xF9, 0xFD, 0xFF),
        TC_BREAKS(),
        TC_OUTPUT(0x0451, 0x0401, 0x044E, 0x0430, 0x043E, 0x043F, 0x0436, 0x044A, 0x042E,
                0x0415, 0x041D, 0x041E, 0x041F, 0x0420, 0x042B, 0x0429, 0x042A),
        .dirty = false,
        .one_at_a_time = true,
    },
};

static const testset_t testsets[] = {
    TEST_SET_SIMPLE(run_tc_api, "API tests"),
    TEST_SET(run_tc_detect, "Detection of encodings", testcase_detect),
    TEST_SET(run_tc_utf8store, "UTF-8 storage primitives", testcase_utf8store),
    TEST_SET(run_tc_input, "UTF-8", testcase_inputs_UTF8),
    TEST_SET(run_tc_input, "UTF-16BE", testcase_inputs_UTF16BE),
    TEST_SET(run_tc_input, "UTF-16LE", testcase_inputs_UTF16LE),
    TEST_SET(run_tc_input, "KOI-8R", testcase_inputs_KOI8R), // Tests codepage encodings
};

static const testsuite_t testsuite = TEST_SUITE("Tests for transcoders", testsets);

/**
    Main routine for XML reader test suite.

    @param argc Number of arguments
    @param argv Arguments
    @return Exit code
*/
int
main(int argc, char *argv[])
{
    return test_run_cmdline(&testsuite, argc, argv);
}
