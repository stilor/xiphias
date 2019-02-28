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
    Initialize loader information structure.

    @param loader_info Loader information structure
    @param public_id Initial value of public ID
    @param system_id Initial value of system ID
    @return Nothing
*/
void
xml_loader_info_init(xml_loader_info_t *loader_info,
        const utf8_t *public_id, const utf8_t *system_id)
{
    loader_info->public_id = utf8_dup(public_id);
    loader_info->system_id = utf8_dup(system_id);
}

/**
    Set public ID of the entity for the loader.

    @param loader_info Loader information structure
    @param id Public ID string
    @param len Length of the public ID string
    @return Nothing
*/
void
xml_loader_info_set_public_id(xml_loader_info_t *loader_info,
        const utf8_t *id, size_t len)
{
    xfree(loader_info->public_id);
    loader_info->public_id = utf8_ndup(id, len);
}

/**
    Set system ID of the entity for the loader.

    @param loader_info Loader information structure
    @param id System ID string
    @param len Length of the system ID string
    @return Nothing
*/
void
xml_loader_info_set_system_id(xml_loader_info_t *loader_info,
        const utf8_t *id, size_t len)
{
    xfree(loader_info->system_id);
    loader_info->system_id = utf8_ndup(id, len);
}

/**
    Check if the loader info has been set (public/system ID or both).

    @param loader_info Loader information structure
    @return true if there is a loadable entity
*/
bool
xml_loader_info_isset(const xml_loader_info_t *loader_info)
{
    return loader_info->public_id || loader_info->system_id;
}

/**
    Destroy loader information structure.

    @param loader_info Loader information structure
    @return Nothing
*/
void xml_loader_info_destroy(xml_loader_info_t *loader_info)
{
    xfree(loader_info->public_id);
    xfree(loader_info->system_id);
}

/**
    Dummy loader: always reports a failure to load.

    @param h Reader handle
    @param arg Ignored
    @param loader_info Loader information (ignored)
    @return Nothing
*/
void
xml_loader_noload(xml_reader_t *h, void *arg, const xml_loader_info_t *loader_info)
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
    @param loader_info Loader information
    @return String buffer for the file, or NULL if file cannot be opened
*/
void
xml_loader_file(xml_reader_t *h, void *arg, const xml_loader_info_t *loader_info)
{
    const xml_loader_opts_file_t *opts = arg ? arg : &default_file_opts;
    const char *sysid = S(loader_info->system_id);
    strbuf_t *buf;
    const char **srch;
    bool is_absolute;
    const char *tmppath;

    if (!sysid) {
        xml_reader_message(h, NULL, XMLERR(ERROR, XML, ENTITY_LOAD_FAILURE),
                "%s() can only load entities with system ID", __func__);
        return;
    }

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
    xml_reader_add_parsed_entity(h, buf, loader_info->system_id,
            opts->transport_encoding);
}
