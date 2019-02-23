/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Information items manipulation routines.
*/
#include <string.h>

#include "util/defs.h"
#include "util/xutil.h"

#include "unicode/unicode.h"

#include "xml/xmlerr.h"
#include "xml/infoset.h"

/// Information context
struct xml_infoset_ctx_s {
    /// Per-type bins of free items and accounting for active items
    struct {
        xml_ii_list_t free;     ///< Free items available for reuse
        uint32_t alloccnt;      ///< Number of allocated items
    } bin[XML_II_TYPE_MAX];
};

/// Value for the references defined as "unknown"
xml_ii_t xml_ii_unknown = {
    .type = XML_II_TYPE_NONE,
    .loc = { NULL, 0, 0 },
};

/// Value for the references defined as "no value"
xml_ii_t xml_ii_no_value = {
    .type = XML_II_TYPE_NONE,
    .loc = { NULL, 0, 0 },
};

/**
    Allocate a new infoset context. Infoset context may be shared between multiple
    documents (e.g. processing similar documents with the same attributes/elements,
    or applying stylesheet to a document).

    @returns Pointer to the information context.
*/
xml_infoset_ctx_t *
xml_infoset_ctx_new(void)
{
    xml_infoset_ctx_t *ic;
    unsigned int i;

    ic = xmalloc(sizeof(*ic));
    for (i = 0; i < XML_II_TYPE_MAX; i++) {
        STAILQ_INIT(&ic->bin[i].free);
        ic->bin[i].alloccnt = 0;
    }
    return ic;
}

/**
    Destroy an infoset context.

    @pre Any documents using this information context must free all their
    content first.

    @param ic Information context pointer
    @return Nothing
*/
void
xml_infoset_ctx_delete(xml_infoset_ctx_t *ic)
{
    unsigned int i;
    xml_ii_t *ii;

    // Verify there are no outstanding elements and purge the free bins.
    for (i = 0; i < XML_II_TYPE_MAX; i++) {
        OOPS_ASSERT(ic->bin[i].alloccnt == 0);
        while ((ii = STAILQ_FIRST(&ic->bin[i].free)) != NULL) {
            STAILQ_REMOVE_HEAD(&ic->bin[i].free, link);
            xfree(ii); // free items have no references/strings
        }
    }
    xfree(ic);
}

/**
    Initializer for Document information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_init_document(xml_ii_document_t *doc)
{
}

/**
    Deinitializer for Document information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_destroy_document(xml_ii_document_t *doc)
{
}

/**
    Initializer for Element information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_init_element(xml_ii_element_t *e)
{
}

/**
    Deinitializer for Element information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_destroy_element(xml_ii_element_t *e)
{
}

/**
    Initializer for Attribute information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_init_attribute(xml_ii_attribute_t *a)
{
}

/**
    Deinitializer for Attribute information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_destroy_attribute(xml_ii_attribute_t *a)
{
}

/**
    Initializer for Processing Instruction information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_init_pi(xml_ii_pi_t *pi)
{
}

/**
    Deinitializer for Processing Instruction information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_destroy_pi(xml_ii_pi_t *pi)
{
}

/**
    Initializer for Unexpanded Entity information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_init_unexpanded_entity(xml_ii_unexpanded_entity_t *unx)
{
}

/**
    Deinitializer for Unexpanded Entity information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_destroy_unexpanded_entity(xml_ii_unexpanded_entity_t *unx)
{
}

/**
    Initializer for Character information item (group).

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_init_text(xml_ii_text_t *t)
{
}

/**
    Deinitializer for Character information item (group).

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_destroy_text(xml_ii_text_t *t)
{
}

/**
    Initializer for Comment information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_init_comment(xml_ii_comment_t *c)
{
}

/**
    Deinitializer for Comment information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_destroy_comment(xml_ii_comment_t *c)
{
}

/**
    Initializer for Document Type Declaration (DTD) information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_init_dtd(xml_ii_dtd_t *dtd)
{
}

/**
    Deinitializer for Document Type Declaration (DTD) information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_destroy_dtd(xml_ii_dtd_t *dtd)
{
}

/**
    Initializer for Unparsed Entity information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_init_unparsed_entity(xml_ii_unparsed_entity_t *unp)
{
}

/**
    Deinitializer for Unparsed Entity information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_destroy_unparsed_entity(xml_ii_unparsed_entity_t *unp)
{
}

/**
    Initializer for Notation information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_init_notation(xml_ii_notation_t *n)
{
}

/**
    Deinitializer for Notation information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_destroy_notation(xml_ii_notation_t *n)
{
}

/**
    Initializer for Namespace information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_init_namespace(xml_ii_namespace_t *ns)
{
}

/**
    Deinitializer for Namespace information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_destroy_namespace(xml_ii_namespace_t *ns)
{
}

/**
    Allocate a new II from the infoset context.

    @param ic Infoset context
    @param type Type of the II
    @return Pointer to the II
*/
xml_ii_t *
xml_ii_new(xml_infoset_ctx_t *ic, enum xml_ii_type_e type)
{
    static const size_t ii_size[] = {
#define SIZE_II_TYPE(t,s) \
        [XML_II_TYPE_##t] = sizeof(xml_ii_##s##_t),
    XML_II__FOREACH_TYPE(SIZE_II_TYPE)
#undef SIZE_II_TYPE
    };
    xml_ii_t *ii;

    OOPS_ASSERT(type < XML_II_TYPE_MAX);

    // If there is a free item in a bin, use it. Otherwise, allocate.
    if ((ii = STAILQ_FIRST(&ic->bin[type].free)) != NULL) {
        STAILQ_REMOVE_HEAD(&ic->bin[type].free, link);
        OOPS_ASSERT(ii->type == type);
    }
    else {
        ii = xmalloc(ii_size[type]);
    }

    memset(ii, 0, ii_size[type]);
    ii->type = type;

    // Type-specific initialization
    switch (type) {
#define INITIALIZE_II_TYPE(t, s) \
    case XML_II_TYPE_##t: xml_ii_init_##s((xml_ii_##s##_t *)ii); break;

    XML_II__FOREACH_TYPE(INITIALIZE_II_TYPE)
#undef INITIALIZE_II_TYPE

    default:
        OOPS;
    }

    // There is now one more live pointer of this type
    ic->bin[type].alloccnt++;
    return ii;
}

/**
    Free a previously allocated II.

    @param ic Infoset context
    @param ii Information item
    @return Nothing
*/
void
xml_ii_delete(xml_infoset_ctx_t *ic, xml_ii_t *ii)
{
    // Type-specific de-initialization
    switch (ii->type) {

#define DESTROY_II_TYPE(t, s) \
    case XML_II_TYPE_##t: xml_ii_destroy_##s((xml_ii_##s##_t *)ii); break;

    XML_II__FOREACH_TYPE(DESTROY_II_TYPE)
#undef DESTROY_II_TYPE

    default:
        OOPS;
    }

    // One item goes from live to free list
    ic->bin[ii->type].alloccnt--;
    STAILQ_INSERT_HEAD(&ic->bin[ii->type].free, ii, link);
}

