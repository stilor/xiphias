/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "util/strbuf.h"
#include "util/encoding.h"
#include "util/xutil.h"
#include "test/testlib.h"

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
    result_t rc = PASS;
    int alternator;

    printf("Testing %s: %s\n", tc->encoding, tc->desc);
    out = xmalloc(tc->noutputs * sizeof(uint32_t));
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
    encoding_close(eh);
    if (memcmp(out, tc->output, tc->noutputs * sizeof(uint32_t))) {
        printf("  Result does not match!\n");
        rc = FAIL;
    }

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
};

static const testset_t testsets[] = {
    TEST_SET(run_tc_input, "UTF-16BE", testcase_inputs_UTF16BE),
    TEST_SET(run_tc_input, "UTF-16LE", testcase_inputs_UTF16LE),
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
