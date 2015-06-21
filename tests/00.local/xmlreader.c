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

    /// Function to create the options for constructor
    const xml_reader_options_t *(*opts_create)(xml_reader_options_t *opts);

    /// Function to compare events
    bool (*evt_compare)(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2);

    /// Check non-received events
    bool (*check_remaining)(const xml_reader_cbparam_t *e);

    /// Skip installing test callback 
    bool nocallback;

    /// Number of events before taking some action; 0 - on every event
    uint32_t action_nevt;

    /// Argument to pass to action function
    void *action_arg;

    /// Action to take on event #X
    void (*action_evt)(void *arg, xml_reader_t *h);

    /// Action to take on exiting from xml_reader_run; return true if the run loop is to restart
    bool (*action_endrun)(void *arg, xml_reader_t *h);
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

    /// Options setup: takes precedence over the one testcase_opts_t
    const xml_reader_options_t *(*opts_create)(xml_reader_options_t *opts);

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
    uint32_t noevtcnt;                  ///< Total counter of NONE events
    uint32_t totalevtcnt;               ///< Total counter of all events
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
    bool (*evt_compare)(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2);
    result_t rc;

    evt_compare = cbarg->tcopt->evt_compare ? cbarg->tcopt->evt_compare :
            xmlreader_event_equal;

    if (cbarg->expect->cbtype == XML_READER_CB_NONE
            && cbarg->noevtcnt++ >= MAX_NONE_EVENTS) {
        xml_reader_stop(cbarg->h);
        printf("             FAIL: Exceeded number of unexpected events (%u)\n",
                MAX_NONE_EVENTS);
        return;
    }
    if (evt_compare(cbarg->expect, cbparam)) {
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
    cbarg->totalevtcnt++;
    if (cbarg->tcopt->action_evt) {
        if (!cbarg->tcopt->action_nevt || cbarg->tcopt->action_nevt == cbarg->totalevtcnt) {
            cbarg->tcopt->action_evt(cbarg->tcopt->action_arg, cbarg->h);
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

    xml_reader_opts_default(&opts);
    cbarg.handle_opts = tc->opts_create ? tc->opts_create(&opts) :
            o->opts_create ? o->opts_create(&opts) : NULL;
    reader = xml_reader_new(cbarg.handle_opts);
    cbarg.expect = tc->events;
    cbarg.failed = false;
    cbarg.h = reader;
    cbarg.tc = tc;
    cbarg.tcopt = o;
    cbarg.noevtcnt = 0;
    cbarg.totalevtcnt = 0;

    if (!o->nocallback) {
        xml_reader_set_callback(reader, test_cb, &cbarg);
    }

    xml_reader_set_loader(reader, xml_loader_file, &file_loader_opts);

    if (tc->setup) {
        tc->setup(reader);
    }

    xml_reader_load_document_entity(reader, NULL, tc->input);
    do {
        xml_reader_run(reader); // Emits the events
    } while (o->action_endrun && o->action_endrun(o->action_arg, reader));

    if (tc->teardown) {
        tc->teardown(reader);
    }

    if (o->check_remaining) {
        cbarg.failed = o->check_remaining(cbarg.expect);
    }
    else {
        while (cbarg.expect->cbtype != XML_READER_CB_NONE) {
            printf("  (not seen) FAIL: ");
            xmlreader_event_print(cbarg.expect);
            cbarg.expect += 1;
            cbarg.failed = true;
        }
    }
    rc = cbarg.failed ? FAIL : PASS;

    xml_reader_delete(reader);
    return rc;
}

static const testcase_opts_t opts_dflt = {
    .desc = "default (NULL options)",
};

static const xml_reader_options_t *
opts_fn_init(xml_reader_options_t *opts)
{
    return opts;
}

static const testcase_opts_t opts_init = {
    .desc = "initialized with default",
    .opts_create = opts_fn_init,
};

static const xml_reader_options_t *
opts_fn_noloc(xml_reader_options_t *opts)
{
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

static bool
chkrem_ignore_unseen(const xml_reader_cbparam_t *e1)
{
    return false;
}

static const testcase_opts_t opts_nocb = {
    .desc = "no callback",
    .nocallback = true,
    .check_remaining = chkrem_ignore_unseen,
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
TC_RUNNER(nocb);

/// State structure for stop/restart test modes
typedef struct {
    bool stopped;           ///< Stop has been issued
    bool on_every_event;    ///< Stop on every event
    size_t stop_on;         ///< Stop on the specified event
    size_t events_rcvd;     ///< Total number of events received
} stop_restart_state_t;

static void
stop_restart_state_init(stop_restart_state_t *st)
{
    st->stopped = false;
    st->on_every_event = false;
    st->stop_on = 0;
    st->events_rcvd = 0;
}

static void
evt_reader_stop(void *arg, xml_reader_t *h)
{
    stop_restart_state_t *st = arg;

    st->events_rcvd++;
    if ((st->on_every_event || st->events_rcvd == st->stop_on) && !st->stopped) {
        xml_reader_stop(h);
        st->stopped = true;
        printf("  -- stop --\n");
    }
}

static bool
evt_reader_restart(void *arg, xml_reader_t *h)
{
    stop_restart_state_t *st = arg;

    if (st->stopped) {
        printf("  --- go ---\n");
        st->stopped = false;
        return true;
    }
    return false;
}

// Runner that stops the test after each received message and restarts it
static result_t
run_testcase_stopngo(const void *arg)
{
    stop_restart_state_t st;
    testcase_opts_t opts;

    stop_restart_state_init(&st);
    st.on_every_event = true;

    memset(&opts, 0, sizeof(opts));
    opts.desc = "stop-and-go";
    opts.action_arg = &st;
    opts.action_evt = evt_reader_stop;
    opts.action_endrun = evt_reader_restart;
    return run_testcase(arg, &opts);
}

// Runner that stops the test after each received message and deletes the handle
static result_t
run_testcase_stopndrop(const void *arg)
{
    const testcase_t *tc = arg;
    const xml_reader_cbparam_t *cbp = tc->events;
    stop_restart_state_t st;
    testcase_opts_t opts;
    size_t max_evt, last_events_rcvd;
    result_t rc;

    // count total expected events
    for (max_evt = 0; cbp->cbtype != XML_READER_CB_NONE; max_evt++, cbp++) {
    }

    last_events_rcvd = max_evt;
    while (--max_evt) {
        printf("\n[[ run until event %zu ]]\n", max_evt);
        stop_restart_state_init(&st);
        st.stop_on = max_evt;

        memset(&opts, 0, sizeof(opts));
        opts.desc = "stop-and-drop";
        opts.action_arg = &st;
        opts.action_evt = evt_reader_stop;
        opts.check_remaining = chkrem_ignore_unseen;
        if ((rc = run_testcase(arg, &opts)) != PASS) {
            return rc;
        }
        if (st.events_rcvd > last_events_rcvd) {
            printf("  FAIL: stopping at evt %zu produced more events (%zu) than stopping "
                    "at event %zu (%zu)\n", st.stop_on, st.events_rcvd, st.stop_on + 1,
                    last_events_rcvd);
            return FAIL;
        }
    }
    return PASS;
}

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
