/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */
#include <stdio.h>

#include "util/strbuf.h"
#include "xml/reader.h"
#include "xmltest/xmlreader-event.h"

static void
cb(void *arg, xml_reader_cbparam_t *cbparam)
{
	xmlreader_event_print(cbparam);
	if (cbparam->cbtype == XML_READER_CB_MESSAGE
			&& XMLERR_SEVERITY(cbparam->message.info) == XMLERR_ERROR) {
        *(int *)arg = 1;
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
    if (argc != 2) {
	    printf("Usage: %s <XML file>\n", argv[0]);
	    return 2;
    }
    sbuf = strbuf_file_read(argv[1], 4096);

    xml_reader_opts_default(&opts);
    opts.func = cb;
    opts.arg = &exitstatus;

    reader = xml_reader_new(&opts);
    xml_reader_add_parsed_entity(reader, sbuf, argv[1], NULL);
    xml_reader_process(reader);
    xml_reader_delete(reader);
    return exitstatus;
}
