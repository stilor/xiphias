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
#include "test/testlib.h"

// TBD get from prog's path? On the command line?
#define XML_INPUT_DIR "tests/input"

/// Describes a single test case for XML reader
typedef struct testcase_s {
    const char *desc;                       ///< Description of a test case
    const char *input;                      ///< Input file name
    bool use_bom;                           ///< Prepend byte order mark to this file?
    const char *encoding;                   ///< Transcode the file to this encoding
    const char *transport_encoding;         ///< If not NULL, configure XML reader with it
    const xml_reader_cbparam_t *events;     ///< Events expected while parsing this input
} testcase_t;

/// Per-event methods
typedef struct event_s {
    const char *desc;                               ///< Description of an event
    void (*print)(const xml_reader_cbparam_t *e);   ///< Print a text description of an event
    bool (*equal)(const xml_reader_cbparam_t *e1,
            const xml_reader_cbparam_t *e2);        ///< Check events for equality
} event_t;

static bool
str_null_or_equal(const char *s1, const char *s2)
{
    return (!s1 && !s2) || (s1 && s2 && !strcmp(s1, s2));
}

// Supporting functions: print event data
static void
evprint_none(const xml_reader_cbparam_t *cbparam)
{
}

static bool
evequal_none(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    return false;
}

static void
evprint_message(const xml_reader_cbparam_t *cbparam)
{
    static const char * const severity[] = {
        [XMLERR_NOTE]  = "NOTE",
        [XMLERR_WARN]  = "WARN",
        [XMLERR_ERROR] = "ERR",
    };
    const xml_reader_cbparam_message_t *x = &cbparam->message;
    uint32_t s = XMLERR_SEVERITY(x->info);

    printf("%s [%s %03u:%04u]",
            x->msg ? x->msg : "<no message>",
            s < sizeofarray(severity) ? severity[s] : "???",
            XMLERR_SPEC(x->info),
            XMLERR_CODE(x->info));
}

static bool
evequal_message(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_message_t *x1 = &e1->message;
    const xml_reader_cbparam_message_t *x2 = &e2->message;

    return str_null_or_equal(x1->msg, x2->msg)
            && x1->info == x2->info;
}

static void
evprint_xmldecl(const xml_reader_cbparam_t *cbparam)
{
    static const char * const stdalone[] = {
        [XML_INFO_STANDALONE_NO_VALUE] = "n/a",
        [XML_INFO_STANDALONE_YES] = "yes",
        [XML_INFO_STANDALONE_NO] = "no",
    };
    static const char * const xmlversion[] = {
        [XML_INFO_VERSION_NO_VALUE] = "n/a",
        [XML_INFO_VERSION_1_0] = "1.0",
        [XML_INFO_VERSION_1_1] = "1.1",
    };
    const xml_reader_cbparam_xmldecl_t *x = &cbparam->xmldecl;

    printf("encoding '%s', standalone '%s', version '%s'",
            x->encoding ? x->encoding : "<unknown>",
            x->standalone < sizeofarray(stdalone) ? stdalone[x->standalone] : "???",
            x->version < sizeofarray(xmlversion) ? xmlversion[x->version] : "???");
}

static bool
evequal_xmldecl(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_xmldecl_t *x1 = &e1->xmldecl;
    const xml_reader_cbparam_xmldecl_t *x2 = &e2->xmldecl;

    return str_null_or_equal(x1->encoding, x2->encoding)
            && x1->standalone == x2->standalone
            && x1->version == x2->version;
}

static void
evprint_dtd_begin(const xml_reader_cbparam_t *cbparam)
{
    // TBD
}

static bool
evequal_dtd_begin(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    return false; // TBD
}

static void
evprint_dtd_end(const xml_reader_cbparam_t *cbparam)
{
    // TBD
}

static bool
evequal_dtd_end(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    return false; // TBD
}

static void
evprint_stag(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_stag_t *x = &cbparam->stag;

    printf("Element '%.*s' [%zu], parent %p, baton %p",
            (int)x->typelen, x->type, x->typelen,
            x->parent, x->baton);
}

static bool
evequal_stag(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_stag_t *x1 = &e1->stag;
    const xml_reader_cbparam_stag_t *x2 = &e2->stag;

    return x1->typelen == x2->typelen
            && !memcmp(x1->type, x2->type, x1->typelen)
            && x1->parent == x2->parent
            && x1->baton == x2->baton;
}

static void
evprint_etag(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_etag_t *x = &cbparam->etag;

    printf("Element '%.*s' [%zu], baton %p, used %s",
            (int)x->typelen, x->type, x->typelen,
            x->baton, x->is_empty ? "EmptyElemTag" : "STag");
}

static bool
evequal_etag(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_etag_t *x1 = &e1->etag;
    const xml_reader_cbparam_etag_t *x2 = &e2->etag;

    return x1->typelen == x2->typelen
            && !memcmp(x1->type, x2->type, x1->typelen)
            && x1->baton == x2->baton
            && x1->is_empty == x2->is_empty;
}

static const event_t events[] = {
    [XML_READER_CB_NONE] = {
        .desc = "NO EVENT",
        .print = evprint_none,
        .equal = evequal_none,
    },
    [XML_READER_CB_MESSAGE] = {
        .desc = "Message",
        .print = evprint_message,
        .equal = evequal_message,
    },
    [XML_READER_CB_XMLDECL] = {
        .desc = "XML declaration",
        .print = evprint_xmldecl,
        .equal = evequal_xmldecl,
    },
    [XML_READER_CB_DTD_BEGIN] = {
        .desc = "DTD begin",
        .print = evprint_dtd_begin,
        .equal = evequal_dtd_begin,
    },
    [XML_READER_CB_DTD_END] = {
        .desc = "DTD end",
        .print = evprint_dtd_end,
        .equal = evequal_dtd_end,
    },
    [XML_READER_CB_STAG] = {
        .desc = "Start tag",
        .print = evprint_stag,
        .equal = evequal_stag,
    },
    [XML_READER_CB_ETAG] = {
        .desc = "End tag",
        .print = evprint_etag,
        .equal = evequal_etag,
    },
};

static void
print_event(const xml_reader_cbparam_t *cbparam)
{
    if (cbparam->cbtype < sizeofarray(events) && events[cbparam->cbtype].desc) {
        printf("  [%s:%u:%u] %s: ",
                cbparam->loc.src ? cbparam->loc.src : "<undef>",
                cbparam->loc.line,
                cbparam->loc.pos,
                events[cbparam->cbtype].desc);
        events[cbparam->cbtype].print(cbparam);
        printf("\n");
    }
    else {
        printf("  UNKNOWN EVENT TYPE %u\n", cbparam->cbtype);
    }
}

static bool
equal_events(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    if (e1->cbtype != e2->cbtype
            || e1->cbtype >= sizeofarray(events)
            || !str_null_or_equal(e1->loc.src, e2->loc.src)
            || e1->loc.line != e2->loc.line
            || e1->loc.pos != e2->loc.pos
            || !events[e1->cbtype].equal) {
        return false;
    }
    return events[e1->cbtype].equal(e1, e2);
}

typedef struct test_cb_s {
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
test_cb(void *arg, const xml_reader_cbparam_t *cbparam)
{
    test_cb_t *cbarg = arg;

    if (equal_events(cbarg->expect, cbparam)) {
        printf("             PASS: ");
        print_event(cbparam);
    }
    else {
        printf("  (received) FAIL: ");
        print_event(cbparam);
        printf("  (expected)     : ");
        print_event(cbarg->expect);
        cbarg->failed = true;
    }
    if (cbarg->expect->cbtype != XML_READER_CB_NONE) {
        cbarg->expect += 1;
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
    result_t rc = FAIL;
    test_cb_t cbarg;

    // Brief summary of the test
    printf("%s\n", tc->desc);
    printf("- Input: %s/%s\n", XML_INPUT_DIR, tc->input);
    printf("- Encoded into '%s', %s Byte-order mark\n",
            tc->encoding ? tc->encoding : "UTF-8",
            tc->use_bom ? "with" : "without");
    if (tc->transport_encoding) {
        printf("- Reporting transport encoding '%s'\n",
                tc->transport_encoding);
    }

    // Set up input stream
    path = xasprintf("%s/%s", XML_INPUT_DIR, tc->input);
    sbuf = strbuf_file_read(path, 4096);
    if (tc->use_bom) {
        void *start, *end;

        if (strbuf_wptr(sbuf, &start, &end) < 3) {
            OOPS_ASSERT(0); // There shouldn't be anything in the buffer yet
        }
        memcpy(start, "\xEF\xBB\xBF", 3);
        strbuf_wadvance(sbuf, 3);
    }
    sbuf = test_strbuf_subst(sbuf, '\\', 4096);
    if (tc->encoding) {
        sbuf = strbuf_iconv_read(sbuf, "UTF-8", tc->encoding, 4096);
    }

    // Run the test
    printf("XML reader events:\n");
    reader = xml_reader_new(sbuf, tc->input);

    cbarg.expect = tc->events;
    cbarg.failed = false;
    xml_reader_set_callback(reader, test_cb, &cbarg);

    if (tc->transport_encoding) {
        xml_reader_set_transport_encoding(reader, tc->transport_encoding);
    }

    xml_reader_process_document_entity(reader);
    xml_reader_delete(reader);

    while (cbarg.expect->cbtype != XML_READER_CB_NONE) {
        printf("  (not seen) FAIL: ");
        print_event(cbarg.expect);
        cbarg.expect += 1;
        cbarg.failed = true;
    }

    if (!cbarg.failed) {
        rc = PASS;
    }

    xfree(path);
    return rc;
}

// Some macro magic for declaring event (which is a disciminated union)
#define FL_MESSAGE      message
#define FL_XMLDECL      xmldecl
#define FL_STAG         stag
#define FL_ETAG         etag
#define FL(t)           FL_##t

#define E(t, l, ...)    { .cbtype = XML_READER_CB_##t, .loc = l, .FL(t) = { __VA_ARGS__ }, }
#define END             { .cbtype = XML_READER_CB_NONE, }

// Initializer for location info
#define LOC(s,l,p)      { .src = (s), .line = (l), .pos = (p), }

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
