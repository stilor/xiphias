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
    ii_array_destroy(&e->namespaces);
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
        xfree(pi->content);
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
#define SIZE_II_TYPE(t, s, a) \
        [XML_II_TYPE_##t] = sizeof(xml_ii_##s##_t),
    XML_II__FOREACH_TYPE(SIZE_II_TYPE, dummy)
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
#define INITIALIZE_II_TYPE(t, s, a) \
    case XML_II_TYPE_##t: xml_ii_init_##s((xml_ii_##s##_t *)ii); break;

    XML_II__FOREACH_TYPE(INITIALIZE_II_TYPE, dummy)
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

    // Common fields
    OOPS_ASSERT(!ii->doc); // Must be removed from the 'children' list prior to this call
    strstore_free(ic->strings, ii->loc.src);
    ii->loc.src = NULL;

    // Type-specific de-initialization
    switch (ii->type) {

#define DESTROY_II_TYPE(t, s, a) \
    case XML_II_TYPE_##t: xml_ii_destroy_##s((xml_ii_##s##_t *)ii, ic); break;

    XML_II__FOREACH_TYPE(DESTROY_II_TYPE, dummy)
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

/**
    Add a child node to a document. Only DTD, PI, Comment and Element nodes may be
    added; only a single instance of DTD and Element each are permitted. Consumes
    the caller's reference to the child node.

    @param doc Document node
    @param child New node being added
    @param after Insert new node after this one; if NULL, insert at the head of the list
    @return Nothing
*/
void
xml_ii_document_insert_child_after(xml_ii_document_t *doc, xml_ii_t *child, xml_ii_t *after)
{
    switch (child->type) {
    case XML_II_TYPE_ELEMENT:
        // This checks for document_element being unset first
        xml_ii_ref_element(&doc->document_element, XML_II_ELEMENT(child));
        xml_ii_ref(&XML_II_ELEMENT(child)->parent, XML_II(doc));
        break;
    case XML_II_TYPE_PI:
        xml_ii_ref(&XML_II_PI(child)->parent, XML_II(doc));
        break;
    case XML_II_TYPE_COMMENT:
        xml_ii_ref(&XML_II_COMMENT(child)->parent, XML_II(doc));
        break;
    case XML_II_TYPE_DTD:
        xml_ii_ref_dtd(&doc->dtd, XML_II_DTD(child));
        xml_ii_ref(&XML_II_DTD(child)->parent, XML_II(doc));
        break;
    default:
        OOPS;
    }
    if (after) {
        STAILQ_INSERT_AFTER(&doc->children, after, child, link);
    }
    else {
        STAILQ_INSERT_HEAD(&doc->children, child, link);
    }
    xml_ii_ref_document(&child->doc, doc);
}

/**
    Add a child node to an element node. Only other elements, comments, PI and text nodes
    are allowed. Consumes the caller's reference to the child node.

    @param e Existing element node
    @param child New node being added
    @param after Insert new node after this one; if NULL, insert at the head of the list
    @return Nothing
*/
void
xml_ii_element_insert_child_after(xml_ii_element_t *e, xml_ii_t *child, xml_ii_t *after)
{
    switch (child->type) {
    case XML_II_TYPE_ELEMENT:
        xml_ii_ref(&XML_II_ELEMENT(child)->parent, XML_II(e));
        break;
    case XML_II_TYPE_PI:
        xml_ii_ref(&XML_II_PI(child)->parent, XML_II(e));
        break;
    case XML_II_TYPE_COMMENT:
        xml_ii_ref(&XML_II_COMMENT(child)->parent, XML_II(e));
        break;
    case XML_II_TYPE_TEXT:
        xml_ii_ref(&XML_II_TEXT(child)->parent, XML_II(e));
        break;
    case XML_II_TYPE_UNEXPANDED_ENTITY:
        xml_ii_ref(&XML_II_UNEXPANDED_ENTITY(child)->parent, XML_II(e));
        break;
    default:
        OOPS;
    }
    /**
        @todo For now, allow inserting only to elements that are already a part of the document.
        It may be needed later to support constructing tree fragments outside of a document
        and then reconnecting them to a document later. This would need a recursive update of
        the ->doc pointer in all descendant nodes (elements, attributes, ...). Also, it is not
        clear how to resolve document-wide references in such case (e.g. when an attribute of
        type IDREF or NOTATION refers to an element or notation outside of that tree fragment).
        Alternatively, require creation of temporary document and provide interfaces for
        "grafting" a tree from one document to another.
    */
    xml_ii_ref_document(&child->doc, e->doc);
    if (after) {
        STAILQ_INSERT_AFTER(&e->children, after, child, link);
    }
    else {
        STAILQ_INSERT_HEAD(&e->children, child, link);
    }
}

/**
    Add a child node to a DTD node. Only PIs are allowed. Consumes the caller's reference to
    the child node.

    @param dtd Existing DTD node
    @param child New node being added
    @param after Insert new node after this one; if NULL, insert at the head of the list
    @return Nothing
*/
void
xml_ii_dtd_insert_child_after(xml_ii_dtd_t *dtd, xml_ii_t *child, xml_ii_t *after)
{
    switch (child->type) {
    case XML_II_TYPE_PI:
        xml_ii_ref(&XML_II_PI(child)->parent, XML_II(dtd));
        break;
    default:
        OOPS;
    }
    /**
        @todo For now, allow inserting only to DTDs that are already a part of the document.
        See xml_ii_element_insert_child_after for rationale.
    */
    xml_ii_ref_document(&child->doc, dtd->doc);
    if (after) {
        STAILQ_INSERT_AFTER(&dtd->children, after, child, link);
    }
    else {
        STAILQ_INSERT_HEAD(&dtd->children, child, link);
    }
}

/**
    Insert an attribute into an element's list. Only insert at the tail (attribute list is
    an unordered set). Does not check for uniqueness of attribute's name. Consumes caller's
    reference on the attribute.

    @param e Existing element node
    @param attr Attribute being inserted
    @return Nothing
*/
void
xml_ii_element_insert_attribute(xml_ii_element_t *e, xml_ii_attribute_t *a)
{
    STAILQ_INSERT_TAIL(a->is_ns_attribute ?  &e->ns_attributes : &e->attributes, XML_II(a), link);
    /** @todo Only allow insertion to elements that a part of a document for now . */
    xml_ii_ref_document(&a->doc, e->doc);
    xml_ii_ref_element(&a->owner, e);
}

/**
    Remove an attribute from the element.

    @param a Attribute to be removed.
    @return Nothing
*/
void
xml_ii_attribute_delete(xml_ii_attribute_t *a)
{
    xml_ii_element_t *e = a->owner;

    OOPS_ASSERT(a->doc);
    OOPS_ASSERT(e);
    STAILQ_REMOVE(a->is_ns_attribute ?  &e->ns_attributes : &e->attributes, XML_II(a), xml_ii_s, link);
    xml_ii_unref(&a->owner);
    xml_ii_unref(&a->doc);

    // Note that this may not free the object yet if it is referenced from somewhere else
    xml_ii_unref(&a);
}

/**
    Add a notation to a document. Insert at the tail (notations are an unordered set). Does not
    check for uniqueness. Consumes caller's reference on the notation.

    @param doc Document node
    @param n Notation to insert
    @return Nothing
*/
void
xml_ii_document_insert_notation(xml_ii_document_t *doc, xml_ii_notation_t *n)
{
    xml_ii_ref_document(&n->doc, doc);
    STAILQ_INSERT_TAIL(&doc->notations, XML_II(n), link);
}

/**
    Delete a notation.

    @param n Notation to be deleted
    @return Nothing
*/
void
xml_ii_notation_delete(xml_ii_notation_t *n)
{
    xml_ii_document_t *doc = n->doc;

    OOPS_ASSERT(doc);
    STAILQ_REMOVE(&doc->notations, XML_II(n), xml_ii_s, link);
    xml_ii_unref(&n->doc);

    // Note that this may not free the object yet if it is referenced from somewhere else
    xml_ii_unref(&n);
}

/**
    Add an unparsed entity to the document. Insert at the tail (unparsed entities are an unordered set).
    Does not check for uniqueness. Consumes caller's reference on the entity.

    @param doc Document node
    @param unp Unparsed entity to be added
    @return Nothing
*/
void
xml_ii_document_insert_unparsed_entity(xml_ii_document_t *doc, xml_ii_unparsed_entity_t *unp)
{
    xml_ii_ref_document(&unp->doc, doc);
    STAILQ_INSERT_TAIL(&doc->unparsed_entities, XML_II(unp), link);
}

/**
    Remove an unparsed entity.

    @param ii Node being removed.
    @return Nothing.
*/
void
xml_ii_remove_unparsed_entity(xml_ii_unparsed_entity_t *unp)
{
    xml_ii_document_t *doc = unp->doc;

    OOPS_ASSERT(doc);
    STAILQ_REMOVE(&doc->unparsed_entities, XML_II(unp), xml_ii_s, link);
    xml_ii_unref(&unp->doc);

    // Note that this may not free the object yet if it is referenced from somewhere else
    xml_ii_unref(&unp);
}

/// @todo Make these child/sibling/parent functions externally visible?

/**
    Helper function: get the first child node.

    @param cur Current II
    @return A pointer to the next child II, or NULL if this II has no children.
*/
static xml_ii_t *
ii_child(xml_ii_t *cur)
{
    switch (cur->type) {
#define DESCEND(t, s) \
    case XML_II_TYPE_##t: \
        return STAILQ_FIRST(&XML_II_##t(cur)->children);

XML_II__FOREACH_PARENT_TYPE(DESCEND)
#undef DESCEND

    default:
        return NULL;
    }
}

/**
    Helper function: get the next sibling node.

    @param cur Current II
    @return Sibling node or NULL if @a cur is the last in the list of children
*/
static xml_ii_t *
ii_sibling(xml_ii_t *cur)
{
    return STAILQ_NEXT(cur, link);
}

/**
    Helper function: get the parent II.

    @param cur Current II
    @return Parent node or NULL if this element does not has a parent. Note
        that attributes have "owner", not "parent".
*/
static xml_ii_t *
ii_parent(xml_ii_t *cur)
{
    switch (cur->type) {
#define ASCEND(t, s) \
    case XML_II_TYPE_##t: \
        return XML_II_##t(cur)->parent;

XML_II__FOREACH_CHILD_TYPE(ASCEND)
#undef ASCEND

    default:
        return NULL;
    }
}

/**
    User-visible API for tree traversal: invoke function(s) for each node in the tree.
    Nodes are visited depth first, pre-order. On element nodes, attribute nodes are
    visited first (of which, NS attributes are followed by non-NS attributes),
    followed by child nodes (child elements, text, PIs, comments) in the document
    order.

    @todo Add a bitfield of types of interest, and only traverse single-type lists
    (->notations, ->attributes) if the corresponding type is requested?

    @param top Topmost II for the traversal. Must be one of the types that can have
        child nodes, i.e. Document/Element/DTD.
    @param pre_func Function to invoke for each node, pre-order; return 'true' to
        continue traversal or 'false' to abort. The function shall not modify
        the tree unless it aborts the traversal immediately after the modification.
        Null if no pre-order operations are requested.
    @param post_func Function to invoke for each node, post-order; return 'true' to
        continue traversal or 'false' to abort. The function shall not modify
        the tree unless it aborts the traversal immediately after the modification,
        or unless the only modification is the removal of the element it is invoked
        upon.
    @param arg An opaque argument to @a pre_func and @a post_func.
    @return Nothing
*/
void
xml_ii_traverse(xml_ii_t *top, bool (*pre_func)(void *, xml_ii_t *),
        bool (*post_func)(void *, xml_ii_t *), void *arg)
{
    unsigned int idx;
    xml_ii_t *ii, *ii2, *next;

#define INVOKE(what, on) \
    do { \
        if (what##_func && !what##_func((on), (arg))) { \
            return; \
        } \
    } while (0)

    ii = top;
    do {
        // Process the II itself
        INVOKE(pre, ii);

        // For certain types, invoke on non-child nodes (attributes, ...)
        switch (ii->type) {
        case XML_II_TYPE_DOCUMENT:
            STAILQ_FOREACH(ii2, &XML_II_DOCUMENT(ii)->notations, link) {
                INVOKE(pre, ii2);
                INVOKE(post, ii2);
            }
            STAILQ_FOREACH(ii2, &XML_II_DOCUMENT(ii)->unparsed_entities, link) {
                INVOKE(pre, ii2);
                INVOKE(post, ii2);
            }
            break;
        case XML_II_TYPE_ELEMENT:
            STAILQ_FOREACH(ii2, &XML_II_ELEMENT(ii)->ns_attributes, link) {
                INVOKE(pre, ii2);
                INVOKE(post, ii2);
            }
            STAILQ_FOREACH(ii2, &XML_II_ELEMENT(ii)->attributes, link) {
                INVOKE(pre, ii2);
                INVOKE(post, ii2);
            }
            XML_II_ARRAY_FOREACH(idx, ii2, &XML_II_ELEMENT(ii)->namespaces) {
                INVOKE(pre, ii2);
                INVOKE(post, ii2);
            }
            break;
        default:
            break; // Other types have no non-children lists
        }

        // Now determine where we go next. If going down, do not call post_func yet
        if ((next = ii_child(ii)) != NULL) {
            ii = next;
        }
        else {
            // Do not traverse siblings of the original top element
            while (ii != top && (next = ii_sibling(ii)) == NULL) {
                next = ii_parent(ii);
                INVOKE(post, ii);
                ii = next;
            }
            INVOKE(post, ii);
            ii = next;
        }
    } while (ii != top);

#undef INVOKE
}

/**
    Callback for a tree removal: remove a given II.

    @param arg Unused argument
    @param ii II to be deleted
    @return Always true (continue traversal)
*/
static bool
ii_remove(void *arg, xml_ii_t *ii)
{
    OOPS; //TBD
    return true;
}

/**
    Remove a tree recursively.

    @param top XML information item
    @return Nothing
*/
void
xml_ii_remove_tree(xml_ii_t *top)
{
    xml_ii_traverse(top, NULL, ii_remove, NULL);
}
