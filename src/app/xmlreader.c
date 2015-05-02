/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */
#include <errno.h>
#include <stdio.h>

#include "util/strbuf.h"
#include "util/opt.h"
#include "xml/reader.h"
#include "test/common/testlib.h"
#include "test/xml/reader-event.h"

/// Whether C code generation is requested
static bool gencode;

/// Whether escape sentences are substituted
static bool subst;

/// Generate verbose "stacktraces" for each event
static bool stacktrace;

/// Transport encoding
static const char *transport_encoding;

/// Location used for the document entity
/// @todo Figure out linker flags so that binaries are runnable from any directory
static const char *location;

/// Input file name
static const char *inputfile;

static const opt_t options[] = {
    {
        OPT_USAGE("Display events from reading an XML file."),
    },
    {
        OPT_KEY('c', "code"),
        OPT_HELP(NULL, "Generate C code rather than text description"),
        OPT_CNT_OPTIONAL,
        OPT_TYPE(BOOL, &gencode),
    },
    {
        OPT_KEY('s', "substitute-escapes"),
        OPT_HELP(NULL, "Substitute escape sequences \\Uxxxx\\, \\Bxx\\, etc."),
        OPT_CNT_OPTIONAL,
        OPT_TYPE(BOOL, &subst),
    },
    {
        OPT_KEY('\0', "stacktrace"),
        OPT_HELP(NULL, "Generate verbose stacktrace for each event"),
        OPT_CNT_OPTIONAL,
        OPT_TYPE(BOOL, &stacktrace),
    },
    {
        OPT_KEY('t', "transport-encoding"),
        OPT_HELP( "ENCODING", "Specify encoding reported from transport layer"),
        OPT_CNT_OPTIONAL,
        OPT_TYPE(STRING, &transport_encoding),
    },
    {
        // TBD remove
        OPT_KEY('l', "location"),
        OPT_HELP( "LOC", "Specify location for the document entity"),
        OPT_CNT_OPTIONAL,
        OPT_TYPE(STRING, &location),
    },
    {
        OPT_ARGUMENT,
        OPT_HELP("XMLFILE", "Input file"),
        OPT_CNT_SINGLE,
        OPT_TYPE(STRING, &inputfile),
    },
    OPT_END
};

struct cb_arg_s {
    int exitstatus;
    xml_reader_t *h;
};

static void
stacktrace_human(void *arg, const xmlerr_loc_t *loc)
{
    printf("\t... %s:%u:%u\n", loc->src, loc->line, loc->pos);
}

static void
stacktrace_code(void *arg, const xmlerr_loc_t *loc)
{
    printf("    // From %s:%u:%u\n", loc->src, loc->line, loc->pos);
}

static void
cb(void *arg, xml_reader_cbparam_t *cbparam)
{
    struct cb_arg_s *cba = arg;

    if (gencode) {
        if (stacktrace) {
            xml_reader_stack(cba->h, stacktrace_code, NULL);
        }
        xmlreader_event_gencode(cbparam);
    }
    else {
        xmlreader_event_print(cbparam);
        if (stacktrace) {
            xml_reader_stack(cba->h, stacktrace_human, NULL);
        }
        if (cbparam->cbtype == XML_READER_CB_MESSAGE
                && XMLERR_SEVERITY(cbparam->message.info) == XMLERR_ERROR) {
            cba->exitstatus = 1;
        }
    }
}

int
main(int argc, char *argv[])
{
    xml_reader_options_t opts;
    xml_reader_t *reader;
    strbuf_t *sbuf;
    struct cb_arg_s cb_arg;

    opt_parse(options, argv);
    if ((sbuf = strbuf_file_read(inputfile, 4096)) == NULL) {
        /// @todo Pool with 'last error' queue? Also for memory, file descs...
        fprintf(stderr, "Failed to open `%s': %s\n", inputfile, strerror(errno));
        return 2;
    }

    if (subst) {
        sbuf = test_strbuf_subst(sbuf, '\\', 4096);
    }

    if (gencode) {
        printf("(const xml_reader_cbparam_t[]){\n");
    }

    xml_reader_opts_default(&opts);
    opts.func = cb;
    opts.arg = &cb_arg;

    reader = xml_reader_new(&opts);
    cb_arg.exitstatus = 0;
    cb_arg.h = reader;

    xml_reader_add_parsed_entity(reader, sbuf,
            location ? location : inputfile, transport_encoding);
    xml_reader_process(reader);
    xml_reader_delete(reader);
    if (gencode) {
        printf("    END,\n");
        printf("},\n");
    }
    return cb_arg.exitstatus;
}
