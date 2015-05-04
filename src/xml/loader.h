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

// TBD use loader to add first (document) entity in xmlreader app & test
// TBD add 'search path list' as an option to xml_loader_file and use it instead of -d in test
// (and add to app)
void xml_loader_noload(struct xml_reader_s *h, void *arg,
        const char *pubid, const char *sysid);
void xml_loader_file(struct xml_reader_s *h, void *arg,
        const char *pubid, const char *sysid);

// TBD: URL loader, catalog-based resolver

#endif
