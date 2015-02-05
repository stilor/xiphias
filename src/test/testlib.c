/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/**
    @file
    Test framework
*/
#include <string.h>
#include "util/xutil.h"
#include "test/testlib.h"

/// Test suite statistics
typedef struct test_stats_s {
    uint32_t passed;        ///< Tests that passed
    uint32_t failed;        ///< Tests that failed
    uint32_t unresolved;    ///< Tests that did not produce PASS/FAIL
} test_stats_t;

/**
    Type converstion for simple test case functions

    @param arg Pointer to the actual test case function
    @return Test case outcome
*/
result_t
test__exec_simple_testcase(const void *arg)
{
    const testset__simple_t *ts = arg;

    printf("%s\n", ts->desc);
    return ts->func();
}

/**
    Print usage.

    @param pgm Program name
    @param suite Test suite
    @return Nothing
*/
static void
usage(const char *pgm, const testsuite_t *suite)
{
    size_t i;

    printf("Usage: %s [SET[.CASE]] ...\n", pgm);
    printf("%s\n", suite->desc);
    printf("\n");
    printf("Valid test set/case numbers:\n");
    for (i = 0; i < suite->nsets; i++) {
        printf("  Set %4zu", i + 1);
        if (suite->sets[i].ncases > 1) {
            printf(": 1..%zu", suite->sets[i].ncases);
        }
        printf("\n");
    }
    printf("\n");
}

/**
    Run a single test case.

    @param suite Test suite
    @param si Set index
    @param ci Test case index in the set
    @param stats Test suite statistics
    @return Nothing
*/
static void
run_case(const testsuite_t *suite, size_t si, size_t ci, test_stats_t *stats)
{
    const testset_t *set = &suite->sets[si];
    const void *case_input;
    result_t rc;

    case_input = set->cases ? (const uint8_t *)set->cases + set->size * ci : NULL;
    printf("== RUNNING TESTCASE %zu.%zu\n", si + 1, ci + 1);
    rc = set->func(case_input);
    printf("== TESTCASE %zu.%zu: ", si + 1, ci + 1);
    switch (rc) {
    case PASS:
        printf("PASS\n");
        stats->passed++;
        break;
    case FAIL:
        printf("FAIL\n");
        stats->failed++;
        break;
    case UNRESOLVED:
    default:
        printf("UNRESOLVED\n");
        stats->unresolved++;
        break;
    }
}

/**
    Run all test cases in a single set.

    @param suite Test suite
    @param si Set index
    @param stats Statistics for the whole suite
    @return Nothing
*/
static void
run_set(const testsuite_t *suite, size_t si, test_stats_t *stats)
{
    const testset_t *set = &suite->sets[si];
    size_t i;

    printf("====  RUNNING TEST SET %zu\n", si + 1);
    for (i = 0; i < set->ncases; i++) {
        run_case(suite, si, i, stats);
    }
    printf("==== FINISHED TEST SET %zu\n", si + 1);
}


/**
    Parse command line and run test cases specified. Command line
    parameters are interpreted as SET[.CASE], and run all or just
    test case CASE in the set SET.

    @param suite Test suite
    @param argc Number of arguments in argv
    @param argv Arguments on the command line
    @return Exit status
*/
int
test_run_cmdline(const testsuite_t *suite, unsigned int argc, char *argv[])
{
    test_stats_t stats;
    size_t i;

    printf("====== RUNNING TESTSUITE: %s\n", suite->desc);
    stats.passed = 0;
    stats.failed = 0;
    stats.unresolved = 0;
    if (argc <= 1) {
        // No arguments: run everything
        for (i = 0; i < suite->nsets; i++) {
            run_set(suite, i, &stats);
        }
    }
    else if (argc == 2 && !strcmp(argv[1], "-h")) {
        usage(argv[0], suite);
        return 1;
    }
    else {
        // Cherry-picking test sets/cases
        for (i = 1; i < argc; i++) {
            char *eptr;
            size_t si, ci;

            si = strtoul(argv[i], &eptr, 10);
            if (eptr == argv[i] || (*eptr && *eptr != '.') || !si || si > suite->nsets) {
                usage(argv[0], suite);
                return 1;
            }
            else if (!*eptr) {
                run_set(suite, si - 1, &stats);
            }
            else {
                ci = strtoul(eptr + 1, &eptr, 10);
                if (*eptr || !ci || ci > suite->sets[si - 1].ncases) {
                    usage(argv[0], suite);
                    return 1;
                }
                run_case(suite, si - 1, ci - 1, &stats);
            }
        }
    }

    printf("\n");
    printf("SUMMARY for '%s':\n", suite->desc);
    printf("  PASSED       : %5u\n", stats.passed);
    printf("  FAILED       : %5u\n", stats.failed);
    printf("  UNRESOLVED   : %5u\n", stats.unresolved);
    printf("====== FINISHED TESTSUITE: %s\n", suite->desc);
    printf("\n");
    return (!stats.failed && !stats.unresolved) ? 0 : 1;
}

