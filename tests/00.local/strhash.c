/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */
#include <string.h>
#include <stdbool.h>
#include "util/strhash.h"
#include "test/testlib.h"

typedef uint32_t obj_t;

static obj_t objects[16];
static obj_t *expected_ptr[16];
static obj_t expected_val[16];

static void
test_cb(void *payload)
{
    obj_t *o = payload;

    *o = 1;
}

static bool
check_expected(strhash_t *hash, const char *msg)
{
    utf8_t buf[10];
    obj_t *o;
    size_t i;

    for (i = 0; i < sizeofarray(objects); i++) {
        snprintf((char *)buf, sizeof(buf), "obj%zu", i);
        o = strhash_get(hash, buf);
        if (o != expected_ptr[i]) {
            printf("[%s] Expect handle %p for '%s', got %p\n", msg, expected_ptr[i], buf, o);
            return false;
        }
        if (objects[i] != expected_val[i]) {
            printf("[%s] Expected value %u in object %zu, got %u\n", msg, expected_val[i], i, objects[i]);
            return false;
        }
    }
    printf("[%s] values/pointers match expected\n", msg);
    return true;
}

static result_t
test_hash(void)
{
    strhash_t *hash;
    utf8_t buf[10];
    size_t i;

    hash = strhash_create(3, test_cb);
    for (i = 0; i < sizeofarray(objects); i++) {
        snprintf((char *)buf, sizeof(buf), "obj%zu", i);
        strhash_set(hash, buf, &objects[i]);
        expected_ptr[i] = &objects[i];
    }
    if (!check_expected(hash, "init")) {
        return FAIL;
    }

    memset(objects, 0, sizeof(objects));
    strhash_set(hash, U"obj4", &objects[7]);
    expected_ptr[4] = &objects[7];
    expected_val[4] = 1;
    if (!check_expected(hash, "4 <- 7")) {
        return FAIL;
    }

    strhash_set(hash, U"obj9", NULL);
    expected_ptr[9] = NULL;
    expected_val[9] = 1;
    if (!check_expected(hash, "9 <- NULL")) {
        return FAIL;
    }

    strhash_destroy(hash);
    return PASS;
}

static const testset_t tests[] = {
    TEST_SET_SIMPLE(test_hash, "Basic test for string hash"),
};

static const testsuite_t testsuite = TEST_SUITE("Tests for string-keyed hash", tests);

int
main(int argc, char *argv[])
{
    return test_run_cmdline(&testsuite, argc, argv);
}
