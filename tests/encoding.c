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
    bool one_at_a_time;
} testcase_input_t;

static result_t
run_tc_input(const void *arg)
{
    const testcase_input_t *tc = arg;
    encoding_handle_t *eh;
    size_t lastbrk, nextbrk, sz, i;
    uint32_t *out, *ptr, *end;
    result_t rc = PASS;

    printf("Testing %s: %s\n", tc->encoding, tc->desc);
    out = xmalloc(tc->noutputs * sizeof(uint32_t));
    ptr = out;
    end = out + tc->noutputs;

    eh = encoding_open(tc->encoding);
    for (i = 0, lastbrk = 0; i <= tc->nbreaks; i++, lastbrk = nextbrk) {
        nextbrk = i == tc->nbreaks ? tc->inputsz : tc->breaks[i];
        OOPS_ASSERT(nextbrk > lastbrk && nextbrk <= tc->inputsz);
        sz = encoding_in(eh, tc->input + lastbrk, tc->input + nextbrk,
                &ptr, tc->one_at_a_time ? min(end, ptr + 1) : end);
        if (nextbrk - lastbrk != sz) {
            rc = FAIL;
            printf("  Decoding block [%zu..%zu]: consumed %zu bytes\n",
                    lastbrk, nextbrk - 1, sz);
        }
        else {
            printf("  Decoded block [%zu..%zu]\n", lastbrk, nextbrk - 1);
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

static const testcase_input_t testcase_inputs[] = {
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
};

static const testset_t testsets[] = {
    TEST_SET(run_tc_input, "Various API tests", testcase_inputs),
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
