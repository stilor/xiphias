/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

#include <stdio.h>
#include <string.h>

#include "util/xutil.h"
#include "unicode/unicode.h"
#include "unicode/nfc.h"
#include "test/testlib.h"

typedef struct testcase_nfc_s {
    const char *desc;
    const ucs4_t *input;
    size_t inputsz;
    const size_t *denormals;
    size_t ndenormals;
} testcase_nfc_t;

static result_t
run_tc_nfc(const void *arg)
{
    const testcase_nfc_t *tc = arg;
    const size_t *denorm, *denorm_end;
    nfc_t *nfc;
    result_t rv = PASS;
    bool d;
    size_t i;

    printf("%s\n", tc->desc);
    printf("- Input:");
    for (i = 0; i < tc->inputsz; i++) {
        printf(" U+%04x", tc->input[i]);
    }
    printf("\n");

    denorm = tc->denormals;
    denorm_end = denorm + tc->ndenormals;
    nfc = nfc_create();
    for (i = 0; i < tc->inputsz; i++) {
        d = nfc_check_nextchar(nfc, tc->input[i]);
        if (denorm < denorm_end && *denorm == i) {
            if (d) {
                printf("FAIL: Denormalized input at %zu not signaled\n", i);
                rv = FAIL;
            }
            else {
                printf("PASS: Denormalization signaled at %zu\n", i);
            }
            denorm++;
        }
        else {
            if (!d) {
                printf("FAIL: Unexpected denormalization at %zu signaled\n", i);
                rv = FAIL;
            }
        }
    }
    nfc_destroy(nfc);
    return rv;
}

#define TC_INPUT(...) \
        .input = (const ucs4_t []){ __VA_ARGS__ }, \
        .inputsz = sizeofarray(((const ucs4_t[]){ __VA_ARGS__ }))
#define TC_DENORM(...) \
        .denormals = (const size_t[]){ __VA_ARGS__ }, \
        .ndenormals = sizeofarray(((const size_t[]){ __VA_ARGS__ }))

static const testcase_nfc_t testcase_nfc[] = {
    {
        .desc = "Empty input",
        TC_INPUT(),
        TC_DENORM(),
    },
    {
        .desc = "Non-combining inputs",
        TC_INPUT(0x0041, 0x0065, 0x0032),
        TC_DENORM(),
    },
    {
        .desc = "A few combining characters",
        TC_INPUT(0x0041, 0x0300, 0x0065, 0x0301),
        TC_DENORM(1, 3),
    },
    {
        .desc = "Long sequence of denormalized combining marks",
        TC_INPUT(0x0041, 0x0300, 0x0301, 0x0302, 0x0303, 0x0304, 0x0305,
                0x0306, 0x0307, 0x0308, 0x0309, 0x030A, 0x030B, 0x030C,
                0x030D, 0x030E, 0x030F, 0x0310, 0x0311, 0x0312, 0x0313,
                0x0314, 0x0315),
        TC_DENORM(1),
    },
    {
        .desc = "Long sequence, normalized",
        // CAPITAL A WITH OGONEK, followed by a bunch of combining marks in
        // canonical order
        TC_INPUT(0x0104, 0x0327, 0x1DCE, 0x031B, 0x302A, 0x0325, 0x0326, 0x031F,
                0x059A, 0x05AD, 0x302E, 0x302F, 0x1D16D, 0x302B, 0x18A9, 0x0300,
                0x0301, 0x030A, 0x031A, 0x0358, 0x035C, 0x035D, 0x0360, 0x0345),
        TC_DENORM(),
    },
};

static const testset_t testsets[] = {
    TEST_SET(run_tc_nfc, "Sample inputs", testcase_nfc),
};

static const testsuite_t testsuite = TEST_SUITE("Tests for normalization checker", testsets);

static test_opt_t topt;

static const opt_t options[] = {
    { OPT_USAGE("Test cases for normalization checker.") },
    { OPT_TEST_LIST(topt) },
    { OPT_TEST_ARGS(topt) },
    OPT_END
};

/**
    Main routine for XML reader test suite.

    @param argc Number of arguments
    @param argv Arguments
    @return Exit code
*/
int
main(int argc, char *argv[])
{
    test_opt_prepare(&topt, &testsuite);
    opt_parse(options, argv);
    return test_opt_run(&topt);
}
