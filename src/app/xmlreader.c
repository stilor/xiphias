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
    xml_reader_t *reader;
    strbuf_t *sbuf;
    int exitstatus = 0;

    if (argc != 2) {
	    printf("Usage: %s <XML file>\n", argv[0]);
	    return 2;
    }
    sbuf = strbuf_file_read(argv[1], 4096);
    reader = xml_reader_new(sbuf, argv[1]);
    xml_reader_set_callback(reader, cb, &exitstatus);
    xml_reader_process_document_entity(reader);
    xml_reader_delete(reader);
    return exitstatus;
}
