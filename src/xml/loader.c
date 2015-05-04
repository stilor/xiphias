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

// Default search option for file loader
static const xml_loader_opts_file_t default_file_opts = {
    .searchpaths = (const char *[]){ NULL },
    .transport_encoding = NULL,
    .subst_func = NULL,
    .subst_arg = NULL,
};

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
    const xml_loader_opts_file_t *opts = arg ? arg : &default_file_opts;
    strbuf_t *buf;
    const char **srch;
    bool is_absolute;
    const char *tmppath;

    if (!strncmp(sysid, "file://", 7)) {
        // URL must be absolute
        sysid += 7;
        is_absolute = true;
    }
    else if (sysid[0] == '/') {
        // Absolute path
        is_absolute = true;
    }
    else {
        // Prepare the search paths
        is_absolute = false;
    }

    // First, try the path as is. If we're successful, we're done
    if ((buf = strbuf_file_read(sysid, DEFAULT_BUFFER_SIZE)) != NULL) {
        goto success;
    }

    // For relative paths, try to prepend search paths
    if (!is_absolute) {
        for (srch = opts->searchpaths; *srch; srch++) {
            tmppath = xasprintf("%s/%s", *srch, sysid);
            buf = strbuf_file_read(tmppath, DEFAULT_BUFFER_SIZE);
            xfree(tmppath);
            if (buf) {
                goto success;
            }
        }
    }

    // None of the search paths worked
    xml_reader_message(h, NULL, XMLERR(ERROR, XML, ENTITY_LOAD_FAILURE),
            "Entity failed to load: %s", sysid);
    return;

success:
    if (opts->subst_func) {
        buf = opts->subst_func(opts->subst_arg, buf);
    }
    xml_reader_add_parsed_entity(h, buf, sysid, opts->transport_encoding);
}
