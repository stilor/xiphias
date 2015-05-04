/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Loaders for entities.
*/
#include "util/defs.h"

#include "xml/reader.h"
#include "xml/loader.h"

/// Default size for buffer's internal storage
#define DEFAULT_BUFFER_SIZE 4096

/**
    Dummy loader: always reports a failure to load.

    @param h Reader handle
    @param arg Ignored
    @param pubid Ignored
    @param sysid Ignored
    @return Nothing
*/
void
xml_loader_noload(xml_reader_t *h, void *arg, const char *pubid, const char *sysid)
{
    // No-op
}

/**
    Loader interpreting system ID as a file path.

    @param h Reader handle
    @param arg Ignored
    @param pubid Ignored
    @param sysid File path to open (cannot be URL)
    @return String buffer for the file, or NULL if file cannot be opened
*/
void
xml_loader_file(xml_reader_t *h, void *arg, const char *pubid, const char *sysid)
{
    strbuf_t *buf;

    if ((buf = strbuf_file_read(sysid, DEFAULT_BUFFER_SIZE)) != NULL) {
        xml_reader_add_parsed_entity(h, buf, sysid, NULL);
    }
    // TBD signal a 'failed to load' error if opening a file failed
}
