/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */
#include <errno.h>
#include <stdio.h>

#include "util/strbuf.h"
#include "util/opt.h"
#include "xml/loader.h"
#include "xml/reader.h"
#include "test/common/testlib.h"
#include "test/xml/reader-event.h"

/// Whether C code generation is requested
static bool gencode;

/// Whether escape sentences are substituted
static bool subst;

/// Whether external entities are loaded
static bool load_ent;

/// Generate verbose "stacktraces" for each event
static bool stacktrace;

/**
    Interject a escape-substitution string buffer if one was requested.

    @param arg Ignored
    @param sbuf String buffer from loader
    @return If substitution is performed, chained string buffer. Otherwise,
        @a sbuf.
*/
static strbuf_t *
sbuf_subst(void *arg, strbuf_t *sbuf)
{
    return subst ? test_strbuf_subst(sbuf, '\\', 4096) : sbuf;
}

/// Search paths
static const char *search_paths[2] = { NULL, NULL }; // First one to be overwritten

/// Loader options for external entities (including the document entity)
/// @todo Allow options to be specified multiple times (variable array,
/// perhaps) to have multiple search paths
static xml_loader_opts_file_t file_loader_opts = {
    .searchpaths = search_paths,
    .transport_encoding = NULL,
    .subst_func = sbuf_subst,
    .subst_arg = NULL,
};

/// Input file name
static const char *inputfile;

/// Application options
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
        OPT_TYPE(STRING, &file_loader_opts.transport_encoding),
    },
    {
        OPT_KEY('e', "load-external-entities"),
        OPT_HELP(NULL, "Load external entities"),
        OPT_CNT_OPTIONAL,
        OPT_TYPE(BOOL, &load_ent),
    },
    {
        OPT_KEY('\0', "search"),
        OPT_HELP("DIR", "search for external entities in directory DIR"),
        OPT_CNT_OPTIONAL,
        OPT_TYPE(STRING, &search_paths[0]),
    },
    {
        OPT_ARGUMENT,
        OPT_HELP("XMLFILE", "Input file"),
        OPT_CNT_SINGLE,
        OPT_TYPE(STRING, &inputfile),
    },
    OPT_END
};

/// Argument to callback
struct cb_arg_s {
    int exitstatus;
    xml_reader_t *h;
};

/**
    Provide a "stacktrace" of the current reader position in human-readable format.

    @param arg Arbitrary argument (ignored)
    @param loc Location information
    @return Nothing
*/
static void
stacktrace_human(void *arg, const xmlerr_loc_t *loc)
{
    printf("\t... %s:%u:%u\n", loc->src, loc->line, loc->pos);
}

/**
    Provide a "stacktrace" of the current reader position in format suitable
    for code generation.

    @param arg Arbitrary argument (ignored)
    @param loc Location information
    @return Nothing
*/
static void
stacktrace_code(void *arg, const xmlerr_loc_t *loc)
{
    printf("    // From %s:%u:%u\n", loc->src, loc->line, loc->pos);
}

/**
    Event callback. Prints the events in either human-readable format,
    or as a C code with event structures.

    @param arg Callback argument
    @param cbparam Event description
    @return Nothing
*/
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

/**
    Main program for the xmlreader application.

    @param argc Number of arguments in @a argv
    @param argv Arguments to the application
    @return 0 on success, 1 on seeing error events in human readable mode,
        EX_USAGE on error in option parsing.
*/
int
main(int argc, char *argv[])
{
    xml_reader_t *reader;
    struct cb_arg_s cb_arg;

    // TBD add coverage testing for the applications
    opt_parse(options, argv);

    if (gencode) {
        printf("(const xml_reader_cbparam_t[]){\n");
    }

    reader = xml_reader_new(NULL);
    cb_arg.exitstatus = 0;
    cb_arg.h = reader;

    xml_reader_set_callback(reader, cb, &cb_arg);
    xml_reader_set_loader(reader, xml_loader_file, &file_loader_opts);
    xml_reader_set_document_entity(reader, NULL, inputfile);

    // TBD this currently disables loading the main document, too. It should
    // instead disable the loading of the entities referenced from the main
    // document.
    if (!load_ent) {
        xml_reader_set_loader(reader, xml_loader_noload, NULL);
    }

    xml_reader_run(reader);
    xml_reader_delete(reader);
    if (gencode) {
        printf("    END,\n");
        printf("},\n");
    }
    return cb_arg.exitstatus;
}
