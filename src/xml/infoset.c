/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Information items manipulation routines.
*/
#include <string.h>

#include "util/defs.h"
#include "util/strstore.h"
#include "util/xutil.h"

#include "unicode/unicode.h"

#include "xml/xmlerr.h"
#include "xml/infoset.h"

/// Information context
struct xml_infoset_ctx_s {
    /// Attributes configured for this context
    xml_infoset_ctx_attr_t attr;

    /// Per-type bins of free items and accounting for active items
    struct {
        xml_ii_list_t free;     ///< Free items available for reuse
        uint32_t alloccnt;      ///< Number of allocated items
    } bin[XML_II_TYPE_MAX];

    /// String storage
    strstore_t *strings;
};

/// Value for the references defined as "unknown"
xml_ii_t xml_ii_unknown = {
    .type = XML_II_TYPE_NONE,
    .refcnt = 1, // Referenced by the library so that it is never freed
    .loc = { NULL, 0, 0 },
};

/// Value for the references defined as "no value"
xml_ii_t xml_ii_no_value = {
    .type = XML_II_TYPE_NONE,
    .refcnt = 1, // Referenced by the library so that it is never freed
    .loc = { NULL, 0, 0 },
};

/// Default options for infoset context creation
static const xml_infoset_ctx_attr_t ic_ctx_attr_default = {
    .strstore_order = 10,
};

/**
    Destroy an array of references to IIs.

    @param arr Array
    @return Nothing
*/
static void
ii_array_destroy(xml_ii_array_t *arr)
{
    size_t i;

    if (arr->num == 1) {
        xml_ii_unref(&arr->refs.single);
    }
    else if (arr->num > 1) {
        for (i = 0; i < arr->num; i++) {
            xml_ii_unref(&arr->refs.array[i]);
        }
        xfree(arr->refs.array);
    }
    arr->num = 0;
}

/**
    Allocate a new infoset context. Infoset context may be shared between multiple
    documents (e.g. processing similar documents with the same attributes/elements,
    or applying stylesheet to a document).

    @param attr Attributes for the context being created
    @returns Pointer to the information context.
*/
xml_infoset_ctx_t *
xml_infoset_ctx_new(const xml_infoset_ctx_attr_t *attr)
{
    xml_infoset_ctx_t *ic;
    unsigned int i;

    if (!attr) {
        attr = &ic_ctx_attr_default;
    }

    ic = xmalloc(sizeof(*ic));
    memcpy(&ic->attr, attr, sizeof(*attr));

    for (i = 0; i < XML_II_TYPE_MAX; i++) {
        STAILQ_INIT(&ic->bin[i].free);
        ic->bin[i].alloccnt = 0;
    }
    ic->strings = strstore_create(attr->strstore_order);
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
    OOPS_ASSERT(strstore_isempty(ic->strings));
    strstore_destroy(ic->strings);
    xfree(ic);
}

/*
    Initializers and de-initializers for specific types of information items.

    Note about de-initializers: these are not recursively going through the
    corresponding hierarchical links (such as element's attributes list or
    DTD's list of PIs). It is expected that the element is removed from such
    lists prior to being "unreferenced" (i.e. deleted); the reason for this
    is to avoid deeply recursive element deletion. This approach, on the other
    hand, may result in references (such as those in a IDREFS-typed attribute)
    pointing to elements that are no longer in a tree ("orphaned"). This is
    better than having such references as dangling pointers - to some memory
    that is no longer used for an information item of that type, or to a
    reused II - that would make any code following such references go completely
    haywire.

    For the purposes of these de-initializers, "hierarchical pointers" are
    (a) lists linked via the 'link' pointer in the II; and (b) mandatory
    upstream/downstream pointers ('document_element' in xml_ii_document_t;
    'parent' in many other II types).
*/

/**
    Initializer for Document information item.

    @param doc Document II
    @return Nothing
*/
static void
xml_ii_init_document(xml_ii_document_t *doc)
{
    STAILQ_INIT(&doc->children);
    STAILQ_INIT(&doc->notations);
    STAILQ_INIT(&doc->unparsed_entities);
}

/**
    Deinitializer for Document information item.

    @param doc Document II
    @param ic Owner infoset context
    @return Nothing
*/
static void
xml_ii_destroy_document(xml_ii_document_t *doc, xml_infoset_ctx_t *ic)
{
    OOPS_ASSERT(STAILQ_EMPTY(&doc->children));
    OOPS_ASSERT(STAILQ_EMPTY(&doc->notations));
    OOPS_ASSERT(STAILQ_EMPTY(&doc->unparsed_entities));
    OOPS_ASSERT(!doc->document_element);
    strstore_free(ic->strings, doc->base_uri);
    strstore_free(ic->strings, doc->encoding);
}

/**
    Initializer for Element information item.

    @param e Element II
    @return Nothing
*/
static void
xml_ii_init_element(xml_ii_element_t *e)
{
    STAILQ_INIT(&e->children);
    STAILQ_INIT(&e->attributes);
    STAILQ_INIT(&e->ns_attributes);
}

/**
    Deinitializer for Element information item.

    @param e Element II
    @param ic Owner infoset context
    @return Nothing
*/
static void
xml_ii_destroy_element(xml_ii_element_t *e, xml_infoset_ctx_t *ic)
{
    OOPS_ASSERT(STAILQ_EMPTY(&e->children));
    OOPS_ASSERT(STAILQ_EMPTY(&e->attributes));
    OOPS_ASSERT(STAILQ_EMPTY(&e->ns_attributes));
    OOPS_ASSERT(!e->parent);
    strstore_free(ic->strings, e->ns_name);
    strstore_free(ic->strings, e->local_name);
    strstore_free(ic->strings, e->prefix);
    strstore_free(ic->strings, e->base_uri);
    ii_array_destroy(&a->namespaces);
}

/**
    Initializer for Attribute information item.

    @param a Attribute II
    @return Nothing
*/
static void
xml_ii_init_attribute(xml_ii_attribute_t *a)
{
    // No-op
}

/**
    Deinitializer for Attribute information item.

    @param a Attribute II
    @param ic Owner infoset context
    @return Nothing
*/
static void
xml_ii_destroy_attribute(xml_ii_attribute_t *a, xml_infoset_ctx_t *ic)
{
    OOPS_ASSERT(!a->owner);
    strstore_free(ic->strings, a->ns_name);
    strstore_free(ic->strings, a->local_name);
    strstore_free(ic->strings, a->prefix);
    if (ic->attr.flags & XML_INFOSET_CTX_F_NO_STORE_ATTR_VALUE) {
        xfree(a->value);
    }
    else {
        strstore_free(ic->strings, a->value);
    }
    ii_array_destroy(&a->references);
}

/**
    Initializer for Processing Instruction information item.

    @param pi Processing Instruction II
    @return Nothing
*/
static void
xml_ii_init_pi(xml_ii_pi_t *pi)
{
    // No-op
}

/**
    Deinitializer for Processing Instruction information item.

    @param pi Processing Instruction II
    @param ic Owner infoset context
    @return Nothing
*/
static void
xml_ii_destroy_pi(xml_ii_pi_t *pi, xml_infoset_ctx_t *ic)
{
    OOPS_ASSERT(!pi->parent);
    strstore_free(ic->strings, pi->target);
    if (ic->attr.flags & XML_INFOSET_CTX_F_NO_STORE_PI_CONTENT) {
        free(pi->content);
    }
    else {
        strstore_free(ic->strings, pi->content);
    }
    strstore_free(ic->strings, pi->base_uri);
    xml_ii_unref(&pi->notation); // not a mandatory hierarchical reference
}

/**
    Initializer for Unexpanded Entity information item.

    @param unx Unexpanded Entity II
    @return Nothing
*/
static void
xml_ii_init_unexpanded_entity(xml_ii_unexpanded_entity_t *unx)
{
    // No-op
}

/**
    Deinitializer for Unexpanded Entity information item.

    @param unx Unexpanded Entity II
    @param ic Owner infoset context
    @return Nothing
*/
static void
xml_ii_destroy_unexpanded_entity(xml_ii_unexpanded_entity_t *unx, xml_infoset_ctx_t *ic)
{
    OOPS_ASSERT(!unx->parent);
    strstore_free(ic->strings, unx->name);
    strstore_free(ic->strings, unx->sysid);
    strstore_free(ic->strings, unx->pubid);
    strstore_free(ic->strings, unx->decl_base_uri);
}

/**
    Initializer for Character information item (group).

    @param t Text (group of Characters) II
    @return Nothing
*/
static void
xml_ii_init_text(xml_ii_text_t *t)
{
    // No-op
}

/**
    Deinitializer for Character information item (group).

    @param t Text (group of Characters) II
    @param ic Owner infoset context
    @return Nothing
*/
static void
xml_ii_destroy_text(xml_ii_text_t *t, xml_infoset_ctx_t *ic)
{
    OOPS_ASSERT(!t->parent);
    xfree(t->content);
}

/**
    Initializer for Comment information item.

    @param c Comment II
    @return Nothing
*/
static void
xml_ii_init_comment(xml_ii_comment_t *c)
{
    // No-op
}

/**
    Deinitializer for Comment information item.

    @param c Comment II
    @param ic Owner infoset context
    @return Nothing
*/
static void
xml_ii_destroy_comment(xml_ii_comment_t *c, xml_infoset_ctx_t *ic)
{
    OOPS_ASSERT(!c->parent);
    xfree(c->content);
}

/**
    Initializer for Document Type Declaration (DTD) information item.

    @param dtd Document Type Declaration II
    @return Nothing
*/
static void
xml_ii_init_dtd(xml_ii_dtd_t *dtd)
{
    STAILQ_INIT(&dtd->children);
}

/**
    Deinitializer for Document Type Declaration (DTD) information item.

    @param dtd Document Type Declaration II
    @param ic Owner infoset context
    @return Nothing
*/
static void
xml_ii_destroy_dtd(xml_ii_dtd_t *dtd, xml_infoset_ctx_t *ic)
{
    OOPS_ASSERT(STAILQ_EMPTY(&dtd->children));
    OOPS_ASSERT(!dtd->parent);
    strstore_free(ic->strings, dtd->sysid);
    strstore_free(ic->strings, dtd->pubid);
}

/**
    Initializer for Unparsed Entity information item.

    @param unp Unparsed Entity II
    @return Nothing
*/
static void
xml_ii_init_unparsed_entity(xml_ii_unparsed_entity_t *unp)
{
    // No-op
}

/**
    Deinitializer for Unparsed Entity information item.

    @param unp Unparsed Entity II
    @param ic Owner infoset context
    @return Nothing
*/
static void
xml_ii_destroy_unparsed_entity(xml_ii_unparsed_entity_t *unp, xml_infoset_ctx_t *ic)
{
    strstore_free(ic->strings, unp->name);
    strstore_free(ic->strings, unp->sysid);
    strstore_free(ic->strings, unp->pubid);
    strstore_free(ic->strings, unp->decl_base_uri);
    strstore_free(ic->strings, unp->notation_name);
    xml_ii_unref(&unp->notation); // not a mandatory hierarchical reference
}

/**
    Initializer for Notation information item.

    @param n Notation II
    @return Nothing
*/
static void
xml_ii_init_notation(xml_ii_notation_t *n)
{
    // No-op
}

/**
    Deinitializer for Notation information item.

    @param n Notation II
    @param ic Owner infoset context
    @return Nothing
*/
static void
xml_ii_destroy_notation(xml_ii_notation_t *n, xml_infoset_ctx_t *ic)
{
    strstore_free(ic->strings, n->name);
    strstore_free(ic->strings, n->sysid);
    strstore_free(ic->strings, n->pubid);
    strstore_free(ic->strings, n->decl_base_uri);
}

/**
    Initializer for Namespace information item.

    @param ns Namespace II
    @return Nothing
*/
static void
xml_ii_init_namespace(xml_ii_namespace_t *ns)
{
    // No-op
}

/**
    Deinitializer for Namespace information item.

    @param ns Namespace II
    @param ic Owner infoset context
    @return Nothing
*/
static void
xml_ii_destroy_namespace(xml_ii_namespace_t *ns, xml_infoset_ctx_t *ic)
{
    strstore_free(ic->strings, ns->prefix);
    strstore_free(ic->strings, ns->ns_name);
}

/**
    Allocate a new II from the infoset context. The caller has a reference to the new object.

    @param ic Infoset context
    @param type Type of the II
    @param loc Location of the II's definition; may be NULL (no location information)
    @return Pointer to the II
*/
xml_ii_t *
xml_ii__new(xml_infoset_ctx_t *ic, enum xml_ii_type_e type, const xmlerr_loc_t *loc)
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
    ii->ctx = ic;
    ii->type = type;
    if (loc) {
        ii->loc.src = strstore_dup(ic->strings, loc->src);
        ii->loc.line = loc->line;
        ii->loc.pos = loc->pos;
    }

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
    ii->refcnt = 1;
    return ii;
}

/**
    Free a previously allocated II.

    @param ii Information item
    @return Nothing
*/
void
xml_ii__delete(xml_ii_t *ii)
{
    xml_infoset_ctx_t *ic = ii->ctx;

    // Free the string in XML location - the only common allocated resource
    strstore_free(ic->strings, ii->loc.src);
    ii->loc.src = NULL;

    // Type-specific de-initialization
    switch (ii->type) {

#define DESTROY_II_TYPE(t, s) \
    case XML_II_TYPE_##t: xml_ii_destroy_##s((xml_ii_##s##_t *)ii, ic); break;

    XML_II__FOREACH_TYPE(DESTROY_II_TYPE)
#undef DESTROY_II_TYPE

    default:
        OOPS;
    }

    // One item goes from live to free list
    ic->bin[ii->type].alloccnt--;
    STAILQ_INSERT_HEAD(&ic->bin[ii->type].free, ii, link);
}

/// Define member-setting functions
#define DEFINE_II_SETTER(s, m, c) \
        void \
        xml_ii_##s##_set_##m(xml_ii_##s##_t *ii, const utf8_t *new_value) \
        { \
            if (c) { /* individual strings stored */ \
                xfree(ii->m); \
                ii->m = utf8_dup(new_value); \
            } \
            else { /* using deduplicating storage */ \
                strstore_free(ii->ctx->strings, ii->m); \
                ii->m = strstore_dup(ii->ctx->strings, new_value); \
            } \
        }

XML_II__FOREACH_STRSTORE_MEMBER(DEFINE_II_SETTER, ii->ctx->attr.flags)
#undef DEFINE_II_SETTER
