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

/// Test outcome
typedef enum result_e {
    PASS,           ///< Test passed
    FAIL,           ///< Test failed
    UNRESOLVED,     ///< Unresolved
} result_t;

/// Function to call for test
typedef result_t (*testfunc_t)(const void *arg);

/// Set of tests
typedef struct testset_s {
    testfunc_t func;        ///< Function to call for this set
    const void *cases;      ///< Test cases in this set
    size_t size;            ///< Size of each test case structure
    size_t ncases;          ///< Number of test cases
} testset_t;

/// Declare simple test set with single function and no arguments
#define TEST_SET_SIMPLE(f) { \
    .func = test__exec_simple_testcase, \
    .cases = (f), \
    .size = 0, \
    .ncases = 1, \
}

/// Test suite
typedef struct testsuite_s {
    const testset_t *sets;  ///< Test sets in this testsuite
    size_t nsets;           ///< Number of test sets
    const char *desc;       ///< Description of this test suite
} testsuite_t;

#define TEST_SUITE(d, t) { \
    .sets = (t), \
    .nsets = sizeofarray(t), \
    .desc = (d), \
}

int test_run_cmdline(const testsuite_t *suite, unsigned int argc, char *argv[]);

// Internal interfaces (not to be called directly)
result_t test__exec_simple_testcase(const void *arg);

#endif
