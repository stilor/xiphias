/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <iconv.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "util/strbuf.h"
#include "util/encoding.h"
#include "util/xutil.h"
#include "xml/reader.h"

// TBD get from prog's path? On the command line?
#define XML_INPUT_DIR "tests/input"

/// Describes a single test case for XML reader
typedef struct testcase_s {
    const char *desc;                       ///< Description of a test case
    const char *input;                      ///< Input file name
    bool use_bom;                           ///< Prepend byte order mark to this file?
    const char *encoding;                   ///< Transcode the file to this encoding
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
    const xml_reader_cbparam_message_t *x = &cbparam->message;

    printf("%s:%u:%u: %s [S%u C%u:%u]",
            x->loc.src ? x->loc.src : "<undef>",
            x->loc.line,
            x->loc.pos,
            x->msg ? x->msg : "<no message>",
            x->info.severity,
            x->info.spec,
            x->info.code);
}

static bool
evequal_message(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_message_t *x1 = &e1->message;
    const xml_reader_cbparam_message_t *x2 = &e2->message;

    return str_null_or_equal(x1->loc.src, x2->loc.src)
            && x1->loc.line == x2->loc.line
            && x1->loc.pos == x2->loc.pos
            && str_null_or_equal(x1->msg, x2->msg)
            && x1->info.severity == x2->info.severity
            && x1->info.spec == x2->info.spec
            && x1->info.code == x2->info.code;
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

    printf("%s, encoding '%s', standalone '%s', version '%s'",
            x->has_decl ? "has declaration" : "implied declaration",
            x->encoding ? x->encoding : "<unknown>",
            x->standalone < sizeofarray(stdalone) ? stdalone[x->standalone] : "???",
            x->version < sizeofarray(xmlversion) ? xmlversion[x->version] : "???");
}

static bool
evequal_xmldecl(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_xmldecl_t *x1 = &e1->xmldecl;
    const xml_reader_cbparam_xmldecl_t *x2 = &e2->xmldecl;

    return x1->has_decl == x2->has_decl
            && str_null_or_equal(x1->encoding, x2->encoding)
            && x1->standalone == x2->standalone
            && x1->version == x2->version;
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
};

static void
print_event(const xml_reader_cbparam_t *cbparam)
{
    if (cbparam->cbtype < sizeofarray(events) && events[cbparam->cbtype].desc) {
        printf("  %s: ", events[cbparam->cbtype].desc);
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
            || !events[e1->cbtype].equal) {
        return false;
    }
    return events[e1->cbtype].equal(e1, e2);
}

// Some macro magic for declaring event (which is a disciminated union)
#define FL_MESSAGE      message
#define FL_XMLDECL      xmldecl
#define FL(t)           FL_##t

#define E(t, ...)       { .cbtype = XML_READER_CB_##t, .FL(t) = { __VA_ARGS__ }, }
#define END             { .cbtype = XML_READER_CB_NONE, }

#include "xmlreader-tests.c"

typedef enum result_e {
    PASS,
    FAIL,
} result_t;

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
        printf("  PASS: ");
        print_event(cbparam);
        cbarg->expect += 1;
    }
    else {
        printf("  FAIL: (received) ");
        print_event(cbparam);
        printf("      : (expected) ");
        print_event(cbarg->expect);
        cbarg->failed = true;
    }
}

/**
    Run a single test case and compare produced events with expected events.

    @param tc Testcase description
    @return PASS/FAIL
*/
static result_t
run_testcase(const testcase_t *tc)
{
    xml_reader_t *reader;
    strbuf_t *sbuf;
    struct stat sb;
    char *path = NULL;
    size_t len, len2, orig_len, conv_len;
    char *buf, *buf2, *orig_buf = NULL, *conv_buf = NULL;
    int fd = -1;
    int rv;
    iconv_t cd = (iconv_t)-1;
    result_t rc = FAIL;
    test_cb_t cbarg;

    // Read the input
    len = strlen(XML_INPUT_DIR) + 1 + strlen(tc->input) + 1;
    path = xmalloc(len);
    snprintf(path, len, "%s/%s", XML_INPUT_DIR, tc->input);
    if (stat(path, &sb) < 0) {
        printf("Input not found: %s (%s)\n", path, strerror(errno));
        goto out;
    }
    orig_len = len = sb.st_size;
    if (tc->use_bom) {
        orig_len += 3;   // BOM is 3 bytes in UTF-8
    }
    buf = orig_buf = xmalloc(len);
    if (tc->use_bom) {
        buf[0] = 0xEF;
        buf[1] = 0xBB;
        buf[2] = 0xBF;
        buf += 3;
    }
    if ((fd = open(path, O_RDONLY)) < 0) {
        printf("Failed to open: %s (%s)\n", path, strerror(errno));
        goto out;
    }
    errno = 0;
    rv = read(fd, buf, len);
    if (rv < 0 || (size_t)rv != len) {
        printf("Read failed: %s (%s) %d != %zu\n", path, strerror(errno), rv, len);
        goto out;
    }
    close(fd);
    fd = -1;

    // Convert to requested encoding
    conv_len = orig_len;
    do {
        conv_buf = xmalloc(conv_len);
        buf = orig_buf;
        len = orig_len;
        buf2 = conv_buf;
        len2 = conv_len;
        if ((cd = iconv_open(tc->encoding, "UTF-8")) == (iconv_t)-1) {
            printf("Encoding '%s' not supported: %s\n", tc->encoding, strerror(errno));
            goto out;
        }
        if (iconv(cd, &buf, &len, &buf2, &len2) == (size_t)-1) {
            if (errno != E2BIG) {
                printf("Conversion error for '%s': %s\n", path, strerror(errno));
                goto out;
            }
            // insufficient output buffer
            xfree(conv_buf);
            conv_buf = NULL;
            conv_len *= 2;
        }
        iconv_close(cd);
        cd = (iconv_t)-1;
    } while (conv_buf == NULL);

    // Run the test
    sbuf = strbuf_new_from_memory(conv_buf, conv_len - len2, false);
    reader = xml_reader_new(sbuf);

    cbarg.expect = tc->events;
    cbarg.failed = false;
    xml_reader_set_callback(reader, test_cb, &cbarg);
    xml_reader_process_xml(reader, true);
    xml_reader_delete(reader);
    // Check that there were no mismatches and all events were seen
    if (!cbarg.failed && cbarg.expect->cbtype == XML_READER_CB_NONE) {
        rc = PASS;
    }

out:
    if (cd != (iconv_t)-1) {
        iconv_close(cd);
    }
    if (fd >= 0) {
        close(fd);
    }
    xfree(path);
    xfree(orig_buf);
    xfree(conv_buf);
    return rc;
}

/**
    Run all the testcases in a suite.

    @param tcs Testcases
    @param num Number of testcases
    @return Nothing
*/
static void
run(const testcase_t *tcs, size_t num)
{
    size_t i;
    result_t rc;

    for (i = 0; i < num; i++) {
        printf("Running test: %s\n", tcs[i].desc);
        rc = run_testcase(&tcs[i]);
        switch (rc) {
        case PASS:
            printf("PASS: %s\n", tcs[i].desc);
            break;
        case FAIL:
            printf("FAIL: %s\n", tcs[i].desc);
            break;
        default:
            printf("UNRESOLVED: %s\n", tcs[i].desc);
            break;
        }
        printf("\n");
    }
}

/**
    Main routine for XML reader test suite.

    @param argc Number of arguments
    @param argv Arguments
    @return Exit code
*/
int
main(int argc, char *argv[])
{
    // TBD function to run all the test cases
    run(testcases, sizeofarray(testcases));

    return 0;
}
