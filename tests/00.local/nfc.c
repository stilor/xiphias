/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

#include <stdio.h>
#include <string.h>

#include "util/xutil.h"
#include "unicode/unicode.h"
#include "unicode/nfc.h"
#include "test/common/testlib.h"

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
        printf(" U+%04X", tc->input[i]);
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
    {
        .desc = "Non-canonical order of marks with composed character #1",
        TC_INPUT(0x00C0, 0x0328),
        TC_DENORM(1),
    },
    {
        .desc = "Non-canonical order of marks with composed character #2",
        TC_INPUT(0x01ED, 0x031B),
        TC_DENORM(1),
    },
    {
        .desc = "Canonical order of marks with composed character #1",
        TC_INPUT(0x00CB, 0x0313),
        TC_DENORM(),
    },
    {
        .desc = "Canonical order of marks with composed character #2",
        TC_INPUT(0x00CB, 0x031A),
        TC_DENORM(),
    },
    {
        .desc = "Canonical order of marks with composed character #3",
        TC_INPUT(0x01ED, 0x0315),
        TC_DENORM(),
    },
    {
        .desc = "Composed character (3 'base' characters)",
        TC_INPUT(0x01D8, 0x0044),
        TC_DENORM(),
    },
    {
        .desc = "Partially decomposed character",
        TC_INPUT(0x00FC, 0x0301, 0x0044),
        TC_DENORM(1),
    },
    {
        .desc = "Fully decomposed character",
        TC_INPUT(0x0066, 0x0075, 0x0308, 0x0301, 0x0044),
        TC_DENORM(2),
    },
    {
        .desc = "Combining marks that do not compose with starter",
        TC_INPUT(0x007A, 0x0335, 0x0327, 0x0324),
        TC_DENORM(),
    },
    {
        .desc = "Combining marks, last one composes with starter",
        TC_INPUT(0x007A, 0x0335, 0x0327, 0x0324, 0x0301),
        TC_DENORM(4),
    },
    {
        .desc = "Non-starter decomposition",
        TC_INPUT(0x0F64, 0x0F71, 0x0F72),
        TC_DENORM(),
    },
    {
        .desc = "Non-starter decomposition (composed)",
        TC_INPUT(0x0F64, 0x0F73),
        TC_DENORM(1),
    },
    {
        .desc = "Non-starter decomposition (disjoint)",
        TC_INPUT(0x0F64, 0x0F71, 0x0F7A, 0x0F72),
        TC_DENORM(),
    },
    {
        .desc = "Two starters composing, checks resume at the next starter after",
        TC_INPUT(0x1B3A, 0x1B35, 0x0045, 0x0301),
        TC_DENORM(1, 3),
    },
    {
        .desc = "Two starters composing (composed)",
        TC_INPUT(0x1B3B),
        TC_DENORM(),
    },
    {
        .desc = "Two starters composing (disjoint)",
        TC_INPUT(0x1B3A, 0x1B44, 0x1B35),
        TC_DENORM(),
    },
    {
        .desc = "Defective sequence #1",
        TC_INPUT(0x0303, 0x01DB),
        TC_DENORM(),
    },
    {
        .desc = "Defective sequence #2",
        TC_INPUT(0x0303, 0x09BE),
        TC_DENORM(),
    },
    {
        .desc = "Defective sequence #3",
        TC_INPUT(0x0303, 0x0311, 0x0072),
        TC_DENORM(),
    },
    {
        .desc = "Defective sequence #4 (starting with disallowed combining mark)",
        TC_INPUT(0x0344, 0x00C4),
        TC_DENORM(0),
    },
    {
        .desc = "Sequence starting with NFC_QC=M character",
        TC_INPUT(0x09BE, 0x9AF, 0x09C7, 0x09BE),
        TC_DENORM(3),
    },
    {
        .desc = "Sequence begins with NFC_QC=N starter",
        TC_INPUT(0x2FA0D, 0x11B3),
        TC_DENORM(0),
    },
    {
        .desc = "Starter followed by non-combining NFC_QC=M starter",
        TC_INPUT(0x00C4, 0x11B0),
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
