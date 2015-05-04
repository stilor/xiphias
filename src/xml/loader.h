/* vi: set ts=5 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Interface for entity loaders.
*/

#ifndef __xml_loader_h_
#define __xml_loader_h_

// Forward declarations
struct xml_reader_s;

/**
    Callback for loading external entities

    @param h Reader handle
    @param arg Arbitrary argument to the loader (e.g. options)
    @param pubid Public ID of the entity
    @param sysid System ID of the entity
    @return Nothing
*/
typedef void (*xml_loader_t)(struct xml_reader_s *h, void *arg,
        const char *pubid, const char *sysid);

/**
    Callback for loader options that allows to chain other string buffers
    to the one about to be added as an entity's input.

    @param arg Arbitrary argument
    @param sbuf Input string buffer opened by the loader
    @return Possibly new string buffer
*/
typedef strbuf_t *(*xml_loader_subst_t)(void *arg, strbuf_t *sbuf);

void xml_loader_noload(struct xml_reader_s *h, void *arg,
        const char *pubid, const char *sysid);

/// Loader options for file loader
typedef struct {
    const char **searchpaths;      ///< Possible prefixes to relative paths, NULL-terminated
    const char *transport_encoding;///< Report this as a transport encoding
    xml_loader_subst_t subst_func; ///< Substitution function
    void *subst_arg;               ///< Argument to substitution function
} xml_loader_opts_file_t;

void xml_loader_file(struct xml_reader_s *h, void *arg,
        const char *pubid, const char *sysid);

// TBD: URL loader, catalog-based resolver

#endif
