/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Testing framework declarations.
*/

#ifndef __test_common_testlib_h_
#define __test_common_testlib_h_

#include <stddef.h>
#include <stdbool.h>
#include "util/defs.h"
#include "util/strbuf.h"
#include "util/opt.h"
#include "unicode/unicode.h"

/// Test outcome
typedef enum result_e {
    PASS,           ///< Test passed
    FAIL,           ///< Test failed
    UNRESOLVED,     ///< Unresolved
} result_t;

/// Function to call for test
typedef result_t (*testfunc_t)(const void *arg);

/// Function to call for simple test
typedef result_t (*testfunc0_t)(void);

/// Set of tests
typedef struct testset_s {
    const char *desc;       ///< Test set description
    testfunc_t func;        ///< Function to call for this set
    const void *cases;      ///< Test cases in this set
    size_t size;            ///< Size of each test case structure
    size_t ncases;          ///< Number of test cases
} testset_t;

/// Simple test set: single function w/o arguments and a description
typedef struct testset__simple_s {
    testfunc0_t func;       ///< Simple test function
} testset__simple_t;

/// Declare simple test set with single function and no arguments
#define TEST_SET_SIMPLE(f, d) { \
    .desc = (d), \
    .func = test__exec_simple_testcase, \
    .cases = &(const testset__simple_t){ .func = (f) }, \
    .size = 0, \
    .ncases = 1, \
}

/// Declare a test set
#define TEST_SET(f, d, c) { \
    .desc = (d), \
    .func = (f), \
    .cases = (c), \
    .size = sizeof(c[0]), \
    .ncases = sizeofarray(c), \
}

/// Test suite
typedef struct testsuite_s {
    const testset_t *sets;  ///< Test sets in this testsuite
    size_t nsets;           ///< Number of test sets
    const char *desc;       ///< Description of this test suite
} testsuite_t;

/// Declare a test suite
#define TEST_SUITE(d, t) { \
    .sets = (t), \
    .nsets = sizeofarray(t), \
    .desc = (d), \
}

/// Option to test argument handler callback
typedef struct test_opt_s {
    struct test_stats_s *stats;     ///< Internal test suite test
} test_opt_t;


void test_opt_prepare(test_opt_t *tstat, const testsuite_t *suite);
int test_opt_run(test_opt_t *tstat);

/// Option for handling command line argument
#define OPT_TEST_ARGS(tstat) \
    OPT_ARGUMENT, \
    OPT_HELP("SET_OR_CASE", "Test set or test case specification"), \
    OPT_CNT_ANY, \
    OPT_TYPE(FUNC, test_opt__argcb, &tstat)

/// Option for listing tests
#define OPT_TEST_LIST(tstat) \
    OPT_KEY('l', "list-tests"), \
    OPT_HELP(NULL, "List test case number ranges"), \
    OPT_CNT_OPTIONAL, \
    OPT_TYPE(FUNC, test_opt__listcb, &tstat)

// Internal interfaces (not to be called directly)
void test_opt__argcb(struct opt_parse_state_s *, char ***pargv, void *arg);
void test_opt__listcb(struct opt_parse_state_s *, char ***pargv, void *arg);
result_t test__exec_simple_testcase(const void *arg);

/**
    Test helper function: test if two strings are either both NULL, or equal.

    @param s1 First string
    @param s2 Seconds string
    @return true if equal or both NULLs, false otherwise
*/
static inline bool
str_null_or_equal(const char *s1, const char *s2)
{
    return (!s1 && !s2) || (s1 && s2 && !strcmp(s1, s2));
}

/**
    Test helper function: test if two UTF-8 strings are either both NULL, or equal.

    @param us1 First string
    @param us2 Seconds string
    @return true if equal or both NULLs, false otherwise
*/
static inline bool
utf8_null_or_equal(const utf8_t *us1, const utf8_t *us2)
{
    return (!us1 && !us2) || (us1 && us2 && !utf8_cmp(us1, us2));
}

// Other test framework
strbuf_t *test_strbuf_subst(strbuf_t *input, utf8_t esc, size_t sz);

#endif
