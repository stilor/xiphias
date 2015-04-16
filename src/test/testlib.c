/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/**
    @file
    Test framework
*/
#include <string.h>
#include "util/queue.h"
#include "util/xutil.h"
#include "test/testlib.h"

/// Test failure record
typedef struct trec_s {
    STAILQ_ENTRY(trec_s) link;      ///< Linked tail-queue pointer
    size_t si;                      ///< Set index of test
    size_t ci;                      ///< Test case index
    result_t rv;                    ///< Test result
} trec_t;

/// Head of the tail queue of test failure records
typedef STAILQ_HEAD(trec_list_s, trec_s) trec_list_t;

/// Test suite statistics
typedef struct test_stats_s {
    uint32_t passed;            ///< Tests that passed
    uint32_t failed;            ///< Tests that failed
    uint32_t unresolved;        ///< Tests that did not produce PASS/FAIL
    trec_list_t testcases;      ///< List of tests
    const testsuite_t *suite;   ///< Test suite
    bool list_tests;            ///< Do not run, just list tests
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

    return ts->func();
}

/**
    Print list of available test cases.

    @param suite Test suite
    @return Nothing
*/
static void
list(const testsuite_t *suite)
{
    size_t i;

    fprintf(stderr, "Valid test set/case numbers:\n");
    for (i = 0; i < suite->nsets; i++) {
        fprintf(stderr, "  Set %4zu", i + 1);
        if (suite->sets[i].ncases > 1) {
            fprintf(stderr, ": 1..%zu", suite->sets[i].ncases);
        }
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
}

/**
    Print command line to re-run failed/unresolved tests. Frees
    the lists of failed test cases.

    @param list List of test records to process.
    @return Nothing
*/
static void
print_rerun(trec_list_t *list)
{
    trec_t *trec;

    printf("Failed test cases:\n");
    STAILQ_FOREACH(trec, list, link) {
        if (trec->rv != PASS) {
            printf(" %zu.%zu", trec->si, trec->ci);
        }
    }
    printf("\n\n");
}

/**
    Add a test case to the run list.

    @param list List of test records to process.
    @param si Set index
    @param ci Test case index
    @return Nothing
*/
static void
add_testcase(trec_list_t *list, size_t si, size_t ci)
{
    trec_t *trec;

    trec = xmalloc(sizeof(trec_t));
    trec->si = si;
    trec->ci = ci;
    trec->rv = UNRESOLVED;
    STAILQ_INSERT_TAIL(list, trec, link);
}

/**
    Run a single test case.

    @param stats Test suite statistics
    @param trec Test record
    @return Nothing
*/
static void
run_case(test_stats_t *stats, trec_t *trec)
{
    const testsuite_t *suite = stats->suite;
    const testset_t *set = &suite->sets[trec->si - 1];
    const void *case_input;

    case_input = set->cases ? (const uint8_t *)set->cases + set->size * (trec->ci - 1) : NULL;
    printf("== RUNNING TESTCASE %zu.%zu\n", trec->si, trec->ci);
    trec->rv = set->func(case_input);
    printf("== TESTCASE %zu.%zu: ", trec->si, trec->ci);
    switch (trec->rv) {
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
    printf("\n");
}

/**
    Prepare test state structure.

    @param tstat Test state
    @param suite Test suite
    @return Nothing
*/
void
test_opt_prepare(test_opt_t *tstat, const testsuite_t *suite)
{
    test_stats_t *st;

    st = xmalloc(sizeof(test_stats_t));
    st->passed = st->failed = st->unresolved = 0;
    STAILQ_INIT(&st->testcases);
    st->suite = suite;
    st->list_tests = false;
    tstat->stats = st;
}

/**
    Callback for handling --list-tests option.

    @param ps Parser state (for printing usage, if needed)
    @param pargv Pointer to argv
    @param arg Test state
    @return Nothing
*/
void
test_opt__listcb(struct opt_parse_state_s *ps, char ***pargv, void *arg)
{
    test_opt_t *to = arg;

    to->stats->list_tests = true;
}

/**
    Callback for handling positional arguments.

    @param ps Parser state (for printing usage, if needed)
    @param pargv Pointer to argv
    @param arg Test state
    @return Nothing
*/
void
test_opt__argcb(struct opt_parse_state_s *ps, char ***pargv, void *arg)
{
    test_opt_t *to = arg;
    test_stats_t *st = to->stats;
    const testsuite_t *suite = st->suite;
    const testset_t *set;
    char **argv = *pargv;
    char *eptr;
    size_t si, ci;

    while (*argv) {
        si = strtoul(*argv, &eptr, 10);
        if (eptr == *argv || (*eptr && *eptr != '.') || !si || si > suite->nsets) {
            opt_usage(ps, "Invalid test set/case specification: %s", *argv);
        }
        set = &suite->sets[si - 1];
        if (!*eptr) {
            for (ci = 1; ci <= set->ncases; ci++) {
                add_testcase(&st->testcases, si, ci);
            }
        }
        else {
            ci = strtoul(eptr + 1, &eptr, 10);
            if (*eptr || !ci || ci > set->ncases) {
                opt_usage(ps, "Invalid test set/case specification: %s", *argv);
            }
            add_testcase(&st->testcases, si, ci);
        }
        argv++;
    }
    *pargv = argv;
}

/**
    Parse command line and run test cases specified. Command line
    parameters are interpreted as SET[.CASE], and run all or just
    test case CASE in the set SET.

    @param to Test option
    @return Exit status
*/
int
test_opt_run(test_opt_t *to)
{
    test_stats_t *st = to->stats;
    const testsuite_t *suite = st->suite;
    const testset_t *set;
    const char *rundesc = "partial run";
    size_t si, ci;
    trec_t *trec;
    int rv = 0;

    if (st->list_tests) {
        list(suite);
    }
    else {
        printf("====== RUNNING TESTSUITE: %s\n", suite->desc);
        if (STAILQ_EMPTY(&st->testcases)) {
            rundesc = "full run";
            for (si = 1; si <= suite->nsets; si++) {
                set = &suite->sets[si - 1];
                for (ci = 1; ci <= set->ncases; ci++) {
                    add_testcase(&st->testcases, si, ci);
                }
            }
        }
        STAILQ_FOREACH(trec, &st->testcases, link) {
            run_case(st, trec);
        }
        printf("\n");
        printf("SUMMARY for '%s' (%s):\n", suite->desc, rundesc);
        printf("  PASSED       : %5u\n", st->passed);
        printf("  FAILED       : %5u\n", st->failed);
        printf("  UNRESOLVED   : %5u\n", st->unresolved);
        printf("====== FINISHED TESTSUITE: %s\n", suite->desc);
        printf("\n");
        if (st->failed || st->unresolved) {
            print_rerun(&st->testcases);
            rv = 1;
        }
    }

    // Destroy state object
    while ((trec = STAILQ_FIRST(&st->testcases)) != NULL) {
        STAILQ_REMOVE_HEAD(&st->testcases, link);
        xfree(trec);
    }
    xfree(st);
    to->stats = NULL;
    return rv;
}

