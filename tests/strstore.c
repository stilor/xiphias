/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

#include "util/strstore.h"
#include "test/testlib.h"

static result_t
create_destroy(void)
{
    strstore_t *store;

    store = strstore_create(4);
    strstore_destroy(store);
    return PASS;
}

static result_t
pointer_cmp(void)
{
    const char *p1, *p2;
    strstore_t *store;

    store = strstore_create(4);
    p1 = strstore_ndup(store, "ABCDEFGHI", 6);
    if (p1 != strstore_ndup(store, "ABCDEF", 6)) {
        return FAIL;
    }
    p2 = strstore_ndup(store, "ABCDEFGHI", 9);
    if (p1 != strstore_ndup(store, "ABCDEFG", 6)) {
        return FAIL;
    }
    if (p2 != strstore_ndup(store, "ABCDEFGHIJ", 9)) {
        return FAIL;
    }
    strstore_destroy(store);
    return PASS;
}

static result_t
refcount_delete(void)
{
    strstore_t *store;

    store = strstore_create(1);
    strstore_ndup(store, "ABCDEF", 6);
    strstore_ndup(store, "GHI", 3);
    strstore_ndup(store, "ABCDEF", 6);
    strstore_ndup(store, "ABCDEF", 6);
    strstore_ndup(store, "JKLM", 4);
    strstore_ndup(store, "NOPQRST", 7);
    strstore_ndup(store, "GHI", 3);
    strstore_ndup(store, "NOPQRST", 7);
    strstore_free(store, "JKLM");
    strstore_free(store, "GHI");
    strstore_free(store, "GHI");
    strstore_free(store, "NOPQRST");
    strstore_free(store, "ABCDEF");
    strstore_free(store, "ABCDEF");
    strstore_free(store, "NOPQRST");
    strstore_free(store, "ABCDEF");
    strstore_destroy(store);
    return PASS; // No assertions? good.
}

static const testset_t tests[] = {
    TEST_SET_SIMPLE(create_destroy, "Create and destroy empty storage"),
    TEST_SET_SIMPLE(pointer_cmp, "Verifying pointer comparison"),
    TEST_SET_SIMPLE(refcount_delete, "Refcount verification"),
};

static const testsuite_t testsuite = TEST_SUITE("Tests for refcounted string storage", tests);

int
main(int argc, char *argv[])
{
    return test_run_cmdline(&testsuite, argc, argv);
}
