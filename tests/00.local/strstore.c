/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

#include "util/strstore.h"
#include "test/common/testlib.h"

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
    const utf8_t *p1, *p2;
    strstore_t *store;

    store = strstore_create(4);
    p1 = strstore_ndup(store, U("ABCDEFGHI"), 6);
    if (p1 != strstore_ndup(store, U("ABCDEF"), 6)) {
        return FAIL;
    }
    p2 = strstore_ndup(store, U("ABCDEFGHI"), 9);
    if (p1 != strstore_ndup(store, U("ABCDEFG"), 6)) {
        return FAIL;
    }
    if (p2 != strstore_ndup(store, U("ABCDEFGHIJ"), 9)) {
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
    strstore_ndup(store, U("ABCDEF"), 6);
    strstore_ndup(store, U("GHI"), 3);
    strstore_ndup(store, U("ABCDEF"), 6);
    strstore_ndup(store, U("ABCDEF"), 6);
    strstore_ndup(store, U("JKLM"), 4);
    strstore_ndup(store, U("NOPQRST"), 7);
    strstore_ndup(store, U("GHI"), 3);
    strstore_ndup(store, U("NOPQRST"), 7);
    strstore_free(store, U("JKLM"));
    strstore_free(store, U("GHI"));
    strstore_free(store, U("GHI"));
    strstore_free(store, U("NOPQRST"));
    strstore_free(store, U("ABCDEF"));
    strstore_free(store, U("ABCDEF"));
    strstore_free(store, U("NOPQRST"));
    strstore_free(store, U("ABCDEF"));
    strstore_destroy(store);
    return PASS; // No assertions? good.
}

static const testset_t tests[] = {
    TEST_SET_SIMPLE(create_destroy, "Create and destroy empty storage"),
    TEST_SET_SIMPLE(pointer_cmp, "Verifying pointer comparison"),
    TEST_SET_SIMPLE(refcount_delete, "Refcount verification"),
};

static const testsuite_t testsuite = TEST_SUITE("Tests for refcounted string storage", tests);

static test_opt_t topt;

static const opt_t options[] = {
    { OPT_USAGE("Test cases for encodings.") },
    { OPT_TEST_LIST(topt) },
    { OPT_TEST_ARGS(topt) },
    OPT_END
};

int
main(int argc, char *argv[])
{
    test_opt_prepare(&topt, &testsuite);
    opt_parse(options, argv);
    return test_opt_run(&topt);
}
