/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */
#include <stdio.h>

#include "util/strbuf.h"
#include "util/opt.h"
#include "xml/reader.h"
#include "xmltest/xmlreader-event.h"

/// Whether C code generation is requested
static bool gencode;

/// Transport encoding
static const char *transport_encoding;

/// Input file name
static const char *inputfile;

static const opt_t options[] = {
    OPT_USAGE("Display events from reading an XML file."),
    OPT('c', "code", BOOL, NULL,
            "Generate C code rather than text description", &gencode),
    OPT('t', "transport-encoding", STRING, "ENCODING",
            "Specify encoding reported from transport layer", &transport_encoding),
    OPT_ARGUMENT(STRING, "XMLFILE",
            "Input file", &inputfile),
    OPT_END
};

static void
cb(void *arg, xml_reader_cbparam_t *cbparam)
{
    if (gencode) {
        xmlreader_event_gencode(cbparam);
    }
    else {
        xmlreader_event_print(cbparam);
        if (cbparam->cbtype == XML_READER_CB_MESSAGE
                && XMLERR_SEVERITY(cbparam->message.info) == XMLERR_ERROR) {
            *(int *)arg = 1;
        }
    }
}

int
main(int argc, char *argv[])
{
    xml_reader_options_t opts;
    xml_reader_t *reader;
    strbuf_t *sbuf;
    int exitstatus = 0;

    /// @todo Allow to specify transport encoding
    opt_parse(options, argv);
    sbuf = strbuf_file_read(inputfile, 4096);

    if (gencode) {
        printf("(const xml_reader_cbparam_t[]){\n");
    }

    xml_reader_opts_default(&opts);
    opts.func = cb;
    opts.arg = &exitstatus;

    reader = xml_reader_new(&opts);
    xml_reader_add_parsed_entity(reader, sbuf, inputfile, transport_encoding);
    xml_reader_process(reader);
    xml_reader_delete(reader);
    if (gencode) {
        printf("    END,\n");
        printf("},\n");
    }
    return exitstatus;
}
