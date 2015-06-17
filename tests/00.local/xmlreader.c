/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "util/strbuf.h"
#include "util/xutil.h"
#include "unicode/encoding.h"
#include "xml/reader.h"
#include "test/common/testlib.h"
#include "test/xml/reader-event.h"

/// Location of the input files.
static const char *xml_input_dir = ".";

/// Re-running the same test cases with multiple variants
typedef struct testcase_opts_s {
    const char *desc;                   ///< Description of test case variant

    ///< Function to create the options for constructor
    const xml_reader_options_t *(*opts_create)(xml_reader_options_t *opts);

    ///< Function to compare events
    bool (*evt_compare)(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2);
} testcase_opts_t;

/// Describes a single test case for XML reader
typedef struct testcase_s {
    const char *at_file;                    ///< Test case defined in this file
    uint32_t at_line;                       ///< Test case defined on this line
    const char *desc;                       ///< Description of a test case
    const char *input;                      ///< Input file name
    bool use_bom;                           ///< Prepend byte order mark to this file?
    const char *encoding;                   ///< Transcode the file to this encoding
    const char *transport_encoding;         ///< Encoding from transport layer

    /// Test set up
    void (*setup)(xml_reader_t *);

    /// Test tear down
    void (*teardown)(xml_reader_t *);

    /// Extra checks in the test event callback
    result_t (*checkevt)(xml_reader_t *h, xml_reader_cbparam_t *e, const void *arg);

    // Events must be last: they're present in all tests, or warning will result
    // from using default initializations
    const xml_reader_cbparam_t *events;     ///< Events expected while parsing this input
} testcase_t;

/// Callback status
typedef struct test_cb_s {
    xml_reader_t *h;                    ///< Reader handle
    const testcase_t *tc;               ///< Testcase description
    const testcase_opts_t *tcopt;       ///< Testcase options
    const xml_reader_options_t *handle_opts; ///< Handle creation options
    const xml_reader_cbparam_t *expect; ///< Currently expected events
    bool failed;                        ///< Whether any of the expected events compared unequal
    uint32_t evtcnt;                    ///< Total counter of events
} test_cb_t;

/// How many unexpected events per test case at most
#define MAX_NONE_EVENTS              10

/**
    Test callback. Checks if received event matches the next expected event.

    @param arg Pointer to the next expected event pointer
    @param cbparam Current event
    @return Nothing
*/
static void
test_cb(void *arg, xml_reader_cbparam_t *cbparam)
{
    test_cb_t *cbarg = arg;
    result_t rc;

    if (cbarg->expect->cbtype == XML_READER_CB_NONE
            && cbarg->evtcnt++ >= MAX_NONE_EVENTS) {
        xml_reader_stop(cbarg->h);
        printf("             FAIL: Exceeded number of unexpected events (%u)\n",
                MAX_NONE_EVENTS);
        return;
    }
    if (cbarg->tcopt->evt_compare(cbarg->expect, cbparam)) {
        printf("             PASS: ");
        xmlreader_event_print(cbparam);
    }
    else {
        printf("  (received) FAIL: ");
        xmlreader_event_print(cbparam);
        printf("  (expected)     : ");
        if (cbarg->expect->cbtype != XML_READER_CB_NONE) {
            xmlreader_event_print(cbarg->expect);
        }
        else {
            printf("NO EVENT\n");
        }
        cbarg->failed = true;
    }
    if (cbarg->expect->cbtype != XML_READER_CB_NONE) {
        cbarg->expect += 1;
    }
    if (cbarg->tc->checkevt) {
        rc = cbarg->tc->checkevt(cbarg->h, cbparam, cbarg->handle_opts);
        if (rc != PASS) {
            printf("             FAIL: in test-specific callback\n");
            cbarg->failed = true;
        }
    }
}

/**
    Substitute string buffer from loader with some postprocessing.

    @param arg Test case description
    @param sbuf String buffer from loader
    @return String buffer for testing
*/
static strbuf_t *
sbuf_subst(void *arg, strbuf_t *sbuf)
{
    const testcase_t *tc = arg;
    void *start, *end;

    sbuf = test_strbuf_subst(sbuf, '\\', 4096);
    if (tc->use_bom) {
        if (strbuf_wptr(sbuf, &start, &end) < 3) {
            OOPS; // There shouldn't be anything in the buffer yet
        }
        memcpy(start, "\xEF\xBB\xBF", 3); // BOM in UTF-8
        strbuf_wadvance(sbuf, 3);
    }
    if (tc->encoding) {
        sbuf = strbuf_iconv_read(sbuf, "UTF-8", tc->encoding, 4096);
    }
    return sbuf;
}

/**
    Run a single test case and compare produced events with expected events.

    @param arg Testcase description
    @return PASS/FAIL
*/
static result_t
run_testcase(const void *arg, const testcase_opts_t *o)
{
    xml_reader_options_t opts;
    const char *search_paths[2] = { xml_input_dir, NULL };
    xml_loader_opts_file_t file_loader_opts;
    const testcase_t *tc = arg;
    xml_reader_t *reader;
    result_t rc;
    test_cb_t cbarg;

    // Brief summary of the test
    printf("%s\n", tc->desc);
    printf("- Variant: %s\n", o->desc);
    printf("- Defined at %s:%u\n", tc->at_file, tc->at_line);
    printf("- Input: %s/%s\n", xml_input_dir, tc->input);
    printf("- Encoded into '%s', %s Byte-order mark\n",
            tc->encoding ? tc->encoding : "UTF-8",
            tc->use_bom ? "with" : "without");

    file_loader_opts.searchpaths = search_paths;
    file_loader_opts.subst_func = sbuf_subst;
    file_loader_opts.subst_arg = DECONST(tc); // sbuf_subst will cast it back to const
    file_loader_opts.transport_encoding = tc->transport_encoding;

    // Run the test
    printf("XML reader events:\n");

    cbarg.handle_opts = o->opts_create(&opts);
    reader = xml_reader_new(cbarg.handle_opts);
    cbarg.expect = tc->events;
    cbarg.failed = false;
    cbarg.h = reader;
    cbarg.tc = tc;
    cbarg.tcopt = o;
    cbarg.evtcnt = 0;

    xml_reader_set_callback(reader, test_cb, &cbarg);
    xml_reader_set_loader(reader, xml_loader_file, &file_loader_opts);

    if (tc->setup) {
        tc->setup(reader);
    }

    xml_reader_load_document_entity(reader, NULL, tc->input);
    xml_reader_run(reader); // Emits the events

    if (tc->teardown) {
        tc->teardown(reader);
    }

    while (cbarg.expect->cbtype != XML_READER_CB_NONE) {
        printf("  (not seen) FAIL: ");
        xmlreader_event_print(cbarg.expect);
        cbarg.expect += 1;
        cbarg.failed = true;
    }
    rc = cbarg.failed ? FAIL : PASS;

    xml_reader_delete(reader);
    return rc;
}

static const xml_reader_options_t *
opts_fn_none(xml_reader_options_t *opts)
{
    return NULL;
}

static const testcase_opts_t opts_dflt = {
    .desc = "default (NULL options)",
    .opts_create = opts_fn_none,
    .evt_compare = xmlreader_event_equal,
};

static const xml_reader_options_t *
opts_fn_init(xml_reader_options_t *opts)
{
    xml_reader_opts_default(opts);
    return opts;
}

static const testcase_opts_t opts_init = {
    .desc = "initialized with default",
    .opts_create = opts_fn_init,
    .evt_compare = xmlreader_event_equal,
};

static const xml_reader_options_t *
opts_fn_noloc(xml_reader_options_t *opts)
{
    xml_reader_opts_default(opts);
    opts->loctrack = false;
    return opts;
}

static bool
evtcmp_fn_noloc(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    xml_reader_cbparam_t x1 = *e1;
    xml_reader_cbparam_t x2 = *e2;

    memset(&x1.loc, 0, sizeof(x1.loc));
    memset(&x2.loc, 0, sizeof(x2.loc));
    return xmlreader_event_equal(&x1, &x2);
}

static const testcase_opts_t opts_noloc = {
    .desc = "no location tracking",
    .opts_create = opts_fn_noloc,
    .evt_compare = evtcmp_fn_noloc,
};

/// Define a test case runner with a given option
#define TC_RUNNER(x) \
        static result_t \
        run_testcase_##x(const void *arg) \
        { \
            return run_testcase(arg, &opts_##x); \
        } \
        struct __dummy

TC_RUNNER(dflt);
TC_RUNNER(init);
TC_RUNNER(noloc);

/// Initializer for basic test info
#define TC(d) \
        .at_file = __FILE__, \
        .at_line = __LINE__, \
        .desc = d

#include "xmlreader-tests.c"

static test_opt_t topt;

static const opt_t options[] = {
    { OPT_USAGE("Test cases for encodings.") },
    {
        OPT_KEY('d', "search-dir"),
        OPT_HELP("DIR", "Directory where test XML inputs are located"),
        OPT_CNT_OPTIONAL,
        OPT_TYPE(STRING, &xml_input_dir)
    },
    { OPT_TEST_LIST(topt) },
    { OPT_TEST_ARGS(topt) },
    OPT_END
};

/**
    Main routine for XML reader test suite.

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
