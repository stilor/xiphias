/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "util/strbuf.h"
#include "util/encoding.h"
#include "util/xutil.h"
#include "xml/reader.h"
#include "xmltest/xmlreader-event.h"
#include "test/testlib.h"

/**
    Location of the input files.
    @todo get from prog's path? On the command line?
*/
#define XML_INPUT_DIR "tests/00.local/xmlreader-input"

/// Describes a single test case for XML reader
typedef struct testcase_s {
    const char *at_file;                    ///< Test case defined in this file
    uint32_t at_line;                       ///< Test case defined on this line
    const char *desc;                       ///< Description of a test case
    const char *input;                      ///< Input file name
    bool use_bom;                           ///< Prepend byte order mark to this file?
    const char *encoding;                   ///< Transcode the file to this encoding

    /// Allow to take some extra setup steps
    result_t (*pretest)(xml_reader_t *h, const void *arg);
    const void *pretest_arg;                ///< Argument to pretest function

    /// Extra checks in the test event callback
    result_t (*checkevt)(xml_reader_t *h, xml_reader_cbparam_t *e, const void *arg);
    const void *checkevt_arg;               ///< Argument to checkevt function

    // Events must be last: they're present in all tests, or warning will result
    // from using default initializations
    const xml_reader_cbparam_t *events;     ///< Events expected while parsing this input
} testcase_t;

typedef struct test_cb_s {
    xml_reader_t *h;
    const testcase_t *tc;
    const xml_reader_cbparam_t *expect;
    bool failed;
} test_cb_t;

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

    if (xmlreader_event_equal(cbarg->expect, cbparam)) {
        printf("             PASS: ");
        xmlreader_event_print(cbparam);
    }
    else {
        printf("  (received) FAIL: ");
        xmlreader_event_print(cbparam);
        printf("  (expected)     : ");
        xmlreader_event_print(cbarg->expect);
        cbarg->failed = true;
    }
    if (cbarg->expect->cbtype != XML_READER_CB_NONE) {
        cbarg->expect += 1;
    }
    if (cbarg->tc->checkevt) {
        rc = cbarg->tc->checkevt(cbarg->h, cbparam, cbarg->tc->checkevt_arg);
        if (rc != PASS) {
            printf("             FAIL: in test-specific callback\n");
            cbarg->failed = true;
        }
    }
}

/**
    Run a single test case and compare produced events with expected events.

    @param arg Testcase description
    @return PASS/FAIL
*/
static result_t
run_testcase(const void *arg)
{
    const testcase_t *tc = arg;
    xml_reader_t *reader;
    strbuf_t *sbuf;
    char *path = NULL;
    result_t rc;
    test_cb_t cbarg;

    // Brief summary of the test
    printf("%s\n", tc->desc);
    printf("- Defined at %s:%u\n", tc->at_file, tc->at_line);
    printf("- Input: %s/%s\n", XML_INPUT_DIR, tc->input);
    printf("- Encoded into '%s', %s Byte-order mark\n",
            tc->encoding ? tc->encoding : "UTF-8",
            tc->use_bom ? "with" : "without");

    // Set up input stream chain
    path = xasprintf("%s/%s", XML_INPUT_DIR, tc->input);
    sbuf = strbuf_file_read(path, 4096);
    sbuf = test_strbuf_subst(sbuf, '\\', 4096);
    if (tc->use_bom) {
        void *start, *end;

        if (strbuf_wptr(sbuf, &start, &end) < 3) {
            OOPS; // There shouldn't be anything in the buffer yet
        }
        memcpy(start, "\xEF\xBB\xBF", 3); // BOM in UTF-8
        strbuf_wadvance(sbuf, 3);
    }
    if (tc->encoding) {
        sbuf = strbuf_iconv_read(sbuf, "UTF-8", tc->encoding, 4096);
    }

    // Run the test
    printf("XML reader events:\n");
    reader = xml_reader_new(sbuf, tc->input);

    cbarg.expect = tc->events;
    cbarg.failed = false;
    cbarg.h = reader;
    cbarg.tc = tc;
    xml_reader_set_callback(reader, test_cb, &cbarg);

    rc = tc->pretest ? tc->pretest(reader, tc->pretest_arg) : PASS;

    if (rc == PASS) {
        xml_reader_process_document_entity(reader);
        while (cbarg.expect->cbtype != XML_READER_CB_NONE) {
            printf("  (not seen) FAIL: ");
            xmlreader_event_print(cbarg.expect);
            cbarg.expect += 1;
            cbarg.failed = true;
        }
        rc = cbarg.failed ? FAIL : PASS;
    }

    xml_reader_delete(reader);
    xfree(path);
    return rc;
}

// Some macro magic for declaring event (which is a disciminated union)
#define FL_MESSAGE          message
#define FL_XMLDECL          xmldecl
#define FL_COMMENT          comment
#define FL_PI_TARGET        pi_target
#define FL_PI_CONTENT       pi_content
#define FL_APPEND           append
#define FL_CDSECT           append
#define FL_STAG             stag
#define FL_STAG_END         stag_end
#define FL_ETAG             etag
#define FL_ATTR             attr
#define FL_ENTITY_UNKNOWN   entity
#define FL_ENTITY_START     entity
#define FL_ENTITY_END       entity
#define FL(t)           FL_##t

#define E(t, l, ...)    { .cbtype = XML_READER_CB_##t, .loc = l, .FL(t) = { __VA_ARGS__ }, }
#define END             { .cbtype = XML_READER_CB_NONE, }

// Initializer for location info
#define LOC(s,l,p)      { .src = (s), .line = (l), .pos = (p), }

// Initializer for basic test info
#define TC(d) \
        .at_file = __FILE__, \
        .at_line = __LINE__, \
        .desc = d

#include "xmlreader-tests.c"

/**
    Main routine for XML reader test suite.

    @param argc Number of arguments
    @param argv Arguments
    @return Exit code
*/
int
main(int argc, char *argv[])
{
    return test_run_cmdline(&testsuite, argc, argv);
}
