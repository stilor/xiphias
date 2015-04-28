/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <sys/wait.h>

#include "util/xutil.h"
#include "util/opt.h"
#include "test/common/testlib.h"

#define EX_PASS   11
#define EX_FAIL   14

typedef struct test_var_s {
    bool v_bool;
    unsigned int v_cnt;
    const char *v_string;
    const char *v_func[2];
    const char *v_arg;
} test_var_t;

static test_var_t test_vars = {
    .v_bool = false,
    .v_string = NULL,
};

typedef struct testcase_opt_s {
    const char *desc;
    const char **args;
    const opt_t *opts;
    const test_var_t expected_vars;
    bool expect_usage;
} testcase_opt_t;

static result_t
run_tc_opt(const void *arg)
{
    const testcase_opt_t *tc = arg;
    char **args;
    result_t rv = PASS;
    size_t len;
    pid_t pid;
    int st;

    printf("%s\n", tc->desc);
    pid = fork();
    if (pid == -1) {
        perror("fork");
        rv = FAIL;
    }
    else if (pid) {
        // Parent
        (void)wait(&st);
        if (!WIFEXITED(st)) {
            rv = UNRESOLVED;
        }
        else switch (WEXITSTATUS(st)) {
        case EX_PASS: rv = tc->expect_usage ? FAIL : PASS; break;
        case EX_FAIL: rv = FAIL; break;
        case EX_USAGE: rv = tc->expect_usage ? PASS : FAIL; break;
        default: rv = UNRESOLVED; break;
        }
    }
    else {
        // Child
        st = EX_PASS;
        if (!freopen("/dev/null", "w", stderr)) {
            fprintf(stderr, "Cannot redirect standard error\n");
            exit(EX_FAIL);
        }
        for (len = 0; tc->args[len]; len++) {
            // Calculate length
        }
        args = xmalloc((len + 2) * sizeof(char *));
        args[0] = (char[]){"/usr/bin/sample-progname"};
        memcpy(&args[1], tc->args, (len + 1) * sizeof(char *));
        opt_parse(tc->opts, args);
        if (tc->expected_vars.v_bool != test_vars.v_bool
                || tc->expected_vars.v_cnt != test_vars.v_cnt
                || !str_null_or_equal(tc->expected_vars.v_string, test_vars.v_string)
                || !str_null_or_equal(tc->expected_vars.v_func[0], test_vars.v_func[0])
                || !str_null_or_equal(tc->expected_vars.v_func[1], test_vars.v_func[1])
                || !str_null_or_equal(tc->expected_vars.v_arg, test_vars.v_arg)) {
            st = EX_FAIL;
        }
        xfree(args);
        exit(st);
    }
    return rv;
}

static void
func_usage(struct opt_parse_state_s *st, char ***pargv, void *arg)
{
        opt_usage(st, "%s", __func__);
}

static void
func_1_arg(struct opt_parse_state_s *st, char ***pargv, void *arg)
{
    char **argv = *pargv;

    if (*argv == NULL) {
        opt_usage(st, "%s: requires 1 argument", __func__);
    }
    test_vars.v_func[0] = *argv;
    *pargv = argv + 1;
}

static void
func_2_arg(struct opt_parse_state_s *st, char ***pargv, void *arg)
{
    char **argv = *pargv;

    if (argv[0] == NULL || argv[1] == NULL) {
        opt_usage(st, "%s: requires 2 arguments", __func__);
    }
    test_vars.v_func[0] = argv[0];
    test_vars.v_func[1] = argv[1];
    *pargv = argv + 2;
}

static const opt_t test_option_types[] = {
    {
        OPT_USAGE("Test option parser"),
    },
    {
        OPT_KEY('b', "boolean"),
        OPT_HELP(NULL, "Set boolean option"),
        OPT_CNT_OPTIONAL,
        OPT_TYPE(BOOL, &test_vars.v_bool),
    },
    {
        OPT_KEY('c', "counter"),
        OPT_HELP(NULL, "Increment counter option"),
        OPT_CNT_ANY,
        OPT_TYPE(COUNTER, &test_vars.v_cnt),
    },
    {
        OPT_KEY('s', "string"),
        OPT_HELP("STRING", "Set string option"),
        OPT_CNT_OPTIONAL,
        OPT_TYPE(STRING, &test_vars.v_string),
    },
    {
        OPT_KEY('f', "function"),
        OPT_HELP("FUNC-ARG", "Set function-parsed option"),
        OPT_CNT_OPTIONAL,
        OPT_TYPE(FUNC, func_1_arg, NULL),
    },
    {
        OPT_KEY('\0', "function2"),
        OPT_HELP("ARG1 ARG2", "Set two function-parsed options"),
        OPT_CNT_OPTIONAL,
        OPT_TYPE(FUNC, func_2_arg, NULL),
    },
    {
        OPT_KEY('\0', "function-usage"),
        OPT_HELP(NULL, "Function calls usage"),
        OPT_CNT_OPTIONAL,
        OPT_TYPE(FUNC, func_usage, NULL),
    },
    {
        OPT_KEY('\0', "very-long-option-which-is-never-going-to-be-called"),
        OPT_HELP(NULL, "Unused option"),
        OPT_CNT_OPTIONAL,
        OPT_TYPE(FUNC, func_usage, NULL),
    },
    OPT_END
};

static const testcase_opt_t testcase_opt_types[] = {
    {
        .desc = "No options, variables retain their values",
        .args = (const char *[]){ NULL },
        .opts = test_option_types,
        .expected_vars = {
            .v_bool = false,
            .v_cnt = 0,
            .v_string = NULL,
            .v_func = { NULL, NULL },
            .v_arg = NULL,
        },
        .expect_usage = false,
    },
    {
        .desc = "Set all options, short names",
        .args = (const char *[]){ "-b", "-s", "SAMPLE", "-f", "FUNC", "-c", NULL },
        .opts = test_option_types,
        .expected_vars = {
            .v_bool = true,
            .v_cnt = 1,
            .v_string = "SAMPLE",
            .v_func = { "FUNC", NULL },
            .v_arg = NULL,
        },
        .expect_usage = false,
    },
    {
        .desc = "Set all options, short names, contracted",
        .args = (const char *[]){ "-fFUNC", "-cccc", "-bsSAMPLE", NULL },
        .opts = test_option_types,
        .expected_vars = {
            .v_bool = true,
            .v_cnt = 4,
            .v_string = "SAMPLE",
            .v_func = { "FUNC", NULL },
            .v_arg = NULL,
        },
        .expect_usage = false,
    },
    {
        .desc = "Set all options, long names",
        .args = (const char *[]){ "--counter", "--counter", "--string", "SAMPLE",
            "--boolean", "--function", "FUNC", NULL },
        .opts = test_option_types,
        .expected_vars = {
            .v_bool = true,
            .v_cnt = 2,
            .v_string = "SAMPLE",
            .v_func = { "FUNC", NULL },
            .v_arg = NULL,
        },
        .expect_usage = false,
    },
};

static const testcase_opt_t testcase_opt_usage[] = {
    {
        .desc = "Usage by request (short option)",
        .args = (const char *[]){ "-?", NULL },
        .opts = test_option_types,
        .expect_usage = true,
    },
    {
        .desc = "Usage by request (long option)",
        .args = (const char *[]){ "--help", NULL },
        .opts = test_option_types,
        .expect_usage = true,
    },
    {
        .desc = "Unknown short option",
        .args = (const char *[]){ "-@", NULL },
        .opts = test_option_types,
        .expect_usage = true,
    },
    {
        .desc = "Unknown long option",
        .args = (const char *[]){ "--@@@@", NULL },
        .opts = test_option_types,
        .expect_usage = true,
    },
    {
        .desc = "Missing string option argument",
        .args = (const char *[]){ "--string", NULL },
        .opts = test_option_types,
        .expect_usage = true,
    },
    {
        .desc = "Call from function option",
        .args = (const char *[]){ "--function-usage", NULL },
        .opts = test_option_types,
        .expect_usage = true,
    },
    {
        .desc = "Extra arguments",
        .args = (const char *[]){ "extra", "arguments", NULL },
        .opts = test_option_types,
        .expect_usage = true,
    },
};

static const opt_t test_option_minmax[] = {
    {
        OPT_KEY('\0', "cnt"),
        OPT_HELP(NULL, "Counter"),
        OPT_CNT(2, 4),
        OPT_TYPE(COUNTER, &test_vars.v_cnt),
    },
    OPT_END
};

static const testcase_opt_t testcase_opt_minmax[] = {
    {
        .desc = "Not enough options",
        .args = (const char *[]){ "--cnt", NULL },
        .opts = test_option_minmax,
        .expect_usage = true,
    },
    {
        .desc = "Minimum # of options",
        .args = (const char *[]){ "--cnt", "--cnt", NULL },
        .opts = test_option_minmax,
        .expected_vars = {
            .v_bool = false,
            .v_cnt = 2,
            .v_string = NULL,
            .v_func = { NULL, NULL },
            .v_arg = NULL,
        },
        .expect_usage = false,
    },
    {
        .desc = "Maximum # of options",
        .args = (const char *[]){ "--cnt", "--cnt", "--cnt", "--cnt", NULL },
        .opts = test_option_minmax,
        .expected_vars = {
            .v_bool = false,
            .v_cnt = 4,
            .v_string = NULL,
            .v_func = { NULL, NULL },
            .v_arg = NULL,
        },
        .expect_usage = false,
    },
    {
        .desc = "Too many options",
        .args = (const char *[]){ "--cnt", "--cnt", "--cnt", "--cnt", "--cnt", NULL },
        .opts = test_option_minmax,
        .expect_usage = true,
    },
};

static const opt_t test_option_args[] = {
    {
        OPT_KEY('s', "string"),
        OPT_HELP("STR", "String"),
        OPT_CNT_OPTIONAL,
        OPT_TYPE(STRING, &test_vars.v_string),
    },
    {
        OPT_ARGUMENT,
        OPT_HELP("ARG", "Argument"),
        OPT_CNT_SINGLE,
        OPT_TYPE(STRING, &test_vars.v_arg),
    },
    {
        OPT_ARGUMENT,
        OPT_HELP("VERY-LONG-ARGUMENT-NAME-WONT-FIT-ON-A-LINE", "Unused option"),
        OPT_CNT_OPTIONAL,
        OPT_TYPE(FUNC, func_usage, NULL),
    },
    OPT_END
};

static const testcase_opt_t testcase_opt_args[] = {
    {
        .desc = "Arguments without delimiter",
        .args = (const char *[]){ "-sSTRING", "ARG", NULL },
        .opts = test_option_args,
        .expected_vars = {
            .v_bool = false,
            .v_cnt = 0,
            .v_string = "STRING",
            .v_func = { NULL, NULL },
            .v_arg = "ARG",
        },
        .expect_usage = false,
    },
    {
        .desc = "Arguments with delimiter",
        .args = (const char *[]){ "--", "-sSTRING", NULL },
        .opts = test_option_args,
        .expected_vars = {
            .v_bool = false,
            .v_cnt = 0,
            .v_string = NULL,
            .v_func = { NULL, NULL },
            .v_arg = "-sSTRING",
        },
        .expect_usage = false,
    },
    {
        .desc = "Usage (unknown short option) with arguments",
        .args = (const char *[]){ "-x", "--", "-sSTRING", NULL },
        .opts = test_option_args,
        .expect_usage = true,
    },
    {
        .desc = "Usage (unknown long option) with arguments",
        .args = (const char *[]){ "--xxx", "--", "-sSTRING", NULL },
        .opts = test_option_args,
        .expect_usage = true,
    },
};

static const testset_t testsets[] = {
    TEST_SET(run_tc_opt, "Option types", testcase_opt_types),
    TEST_SET(run_tc_opt, "Usage", testcase_opt_usage),
    TEST_SET(run_tc_opt, "Option min/max", testcase_opt_minmax),
    TEST_SET(run_tc_opt, "Arguments", testcase_opt_args),
};

static const testsuite_t testsuite = TEST_SUITE("Tests for option parser", testsets);

static test_opt_t topt;

static const opt_t options[] = {
    { OPT_USAGE("Test cases for option parser.") },
    { OPT_TEST_LIST(topt) },
    { OPT_TEST_ARGS(topt) },
    OPT_END
};

/**
    Main routine for option parser test.

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
