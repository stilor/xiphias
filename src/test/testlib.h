/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Testing framework declarations.
*/

#ifndef __test_testlib_h_
#define __test_testlib_h_

#include <stddef.h>
#include <stdbool.h>
#include "util/defs.h"
#include "util/strbuf.h"
#include "util/unicode.h"

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

int test_run_cmdline(const testsuite_t *suite, unsigned int argc, char *argv[]);

// Internal interfaces (not to be called directly)
result_t test__exec_simple_testcase(const void *arg);

// Other test framework
strbuf_t *test_strbuf_subst(strbuf_t *input, utf8_t esc, size_t sz);

#endif
