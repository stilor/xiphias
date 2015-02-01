/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

#include "util/strstore.h"
#include "test/testlib.h"

static result_t
strstore_create_destroy(void)
{
    strstore_t *store;

    store = strstore_create(16);
    strstore_destroy(store);
    return PASS;
}

static const testset_t tests[] = {
    TEST_SET_SIMPLE(strstore_create_destroy, "Create and destroy empty storage"),
};

static const testsuite_t testsuite = TEST_SUITE("Tests for refcounted string storage", tests);

int
main(int argc, char *argv[])
{
    return test_run_cmdline(&testsuite, argc, argv);
}
