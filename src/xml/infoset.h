/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Definitions related to XML Infoset specification (REC-xml-infoset-20040204).
*/

#ifndef __xml_infoset_h_
#define __xml_infoset_h_

#include <stddef.h>

#include "util/queue.h"
#include "xml/xmlerr.h"

/// XML version values
enum xml_info_version_e {
    XML_INFO_VERSION_NO_VALUE,      ///< Version not specified
    XML_INFO_VERSION_1_0,           ///< XML 1.0
    XML_INFO_VERSION_1_1            ///< XML 1.1
};

/// XML standalone status
enum xml_info_standalone_e {
    XML_INFO_STANDALONE_NO_VALUE,   ///< Standalone status not specified
    XML_INFO_STANDALONE_YES,        ///< Document is standalone
    XML_INFO_STANDALONE_NO,         ///< Document is not standalone
};

/// Types of XML information items (IIs)
enum xml_ii_type_e {
    XML_II_TYPE_DOCUMENT,           ///< Document information item
    XML_II_TYPE_ELEMENT,            ///< Element information item
    XML_II_TYPE_ATTRIBUTE,          ///< Attribute information item
    XML_II_TYPE_PI,                 ///< Processing Instruction information item
    XML_II_TYPE_UNEXPANDED_ENTITY,  ///< Unexpanded Entity information item
    XML_II_TYPE_TEXT,               ///< (A group of) character information items
    XML_II_TYPE_COMMENT,            ///< Comment information item
    XML_II_TYPE_DTD,                ///< Document Type Declaration information item
    XML_II_TYPE_UNPARSED_ENTITY,    ///< Unparsed Entity information item
    XML_II_TYPE_NOTATION,           ///< Notation information item
    XML_II_TYPE_NAMESPACE,          ///< Namespace information item

    XML_II_TYPE_MAX,                ///< Number of valid declared types
    XML_II_TYPE_NONE,               ///< Special information item; cannot be allocated or freed
};

/// Attribute type
enum xml_ii_attr_type_e {
    XML_II_ATTR_NO_VALUE,           ///< No declaration for this attribute
    XML_II_ATTR_UNKNOWN,            ///< No declaration, but not all declaration have been read
    XML_II_ATTR_ID,                 ///< Attribute is an ID
    XML_II_ATTR_IDREF,              ///< Attribute is a reference to an element
    XML_II_ATTR_IDREFS,             ///< Attribute is a list of references to elements
    XML_II_ATTR_ENTITY,             ///< Attribute is a reference to an entity
    XML_II_ATTR_ENTITIES,           ///< Attribute is a list of references to entities
    XML_II_ATTR_NMTOKEN,            ///< Attribute is a name token
    XML_II_ATTR_NMTOKENS,           ///< Attribute is a list of name tokens
    XML_II_ATTR_NOTATION,           ///< Attribute is a reference to a notation
    XML_II_ATTR_CDATA,              ///< Attribute contains character data (text)
    XML_II_ATTR_ENUMERATION,        ///< Attribute contains one of the enumerated values

    XML_II_ATTR_MAX,                ///< Number of declared attribute types
};

// Forward declaration
typedef struct xml_ii_s xml_ii_t;

// Opaque type for infoset manipulation
typedef struct xml_infoset_ctx_s xml_infoset_ctx_t;

/// Head of the information items list: single-linked, with tail pointer
typedef STAILQ_HEAD(xml_ii_list_s, xml_ii_s) xml_ii_list_t;

/**
    Array of references; used for many-to-one relations like "IDREF attributes to a single ID"
    or "list of in-scope namespaces to namespace II" (since namespaces are inherited from parent
    element to its children, we don't want to create a copy of all namespace IIs to create a list
    in each child).
*/
typedef struct xml_ii_array_s {
    size_t num;                     ///< Number of references in the array
    union {
        xml_ii_t **array;           ///< References to the information items
        xml_ii_t *single;           ///< Single reference to the information item
    } refs;
} xml_ii_array_t;

/// An iterator over an array of IIs
#define XML_II_ARRAY_FOREACH(idx, var, parray) \
        for (idx = 0, var = (parray)->num <= 1 ? (parray)->refs.single : (parray)->refs.array[0]; \
                idx < (parray)->num; \
                idx++, /* only relevant for >1 */ var = (parray)->refs.array[idx])

/**
    Common members of all information items. Not all IIs can be referenced or linked in some II's
    list of children, but the code that will iterate over such lists/references needs to be agnostic
    of the II type. The link pointer is also used internally to store free structures.
*/
#define XML_II__COMMON_MEMBERS \
    enum xml_ii_type_e type;        /**< Type of the II */ \
    uint32_t refcnt;                /**< References from other IIs */ \
    STAILQ_ENTRY(xml_ii_s) link;    /**< Link for 'children' list */ \
    xmlerr_loc_t loc;               /**< Location of the definition */ \
    xml_infoset_ctx_t *ctx;         /**< Context from which this item was allocated */ \
    struct xml_ii_document_s *doc   /**< Document to which this item belongs */


/// Document information item (section 2.1)
typedef struct xml_ii_document_s {
    XML_II__COMMON_MEMBERS;

    /// An ordered list of child IIs, in document order
    xml_ii_list_t children;

    /// The element II corresponding to the document element
    struct xml_ii_element_s *document_element;

    /// An unordered set of notation IIs
    xml_ii_list_t notations;

    /// An unordered set of unparsed entity IIs
    xml_ii_list_t unparsed_entities;

    /// The base URI of the document entity
    const utf8_t *base_uri;

    /// The name of the character encoding scheme in which the document entity is expressed.
    const utf8_t *encoding;

    /// An indication of the standalone status of the document
    enum xml_info_standalone_e standalone;

    /// A string representing the XML version of the document. Use an enumerated value instead.
    enum xml_info_version_e version;

    /// ... indication of whether the processor has read the complete DTD
    bool all_declarations_processed;

    /// Document type declaration, if present
    struct xml_ii_dtd_s *dtd;
} xml_ii_document_t;

/// Element information item (section 2.2)
typedef struct xml_ii_element_s {
    XML_II__COMMON_MEMBERS;

    /// The namespace name, if any, of the element type
    const utf8_t *ns_name;

    /// The local part of the element-type name
    const utf8_t *local_name;

    /// The namespace prefix part of the element-type name
    const utf8_t *prefix;

    /// An ordered list of child IIs, in document order
    xml_ii_list_t children;

    /// An unordered set of attribute IIs
    xml_ii_list_t attributes;

    /// An unordered set of attribute IIs, one for each of the namespace declarations
    xml_ii_list_t ns_attributes;

    /// An unordered set of namespace information items
    xml_ii_array_t namespaces;

    /// The base URI of the element
    const utf8_t *base_uri;

    /// The document or element II which contains this information item in its [children] property
    xml_ii_t *parent;
} xml_ii_element_t;

/// Attribute information item (section 2.3)
typedef struct xml_ii_attribute_s {
    XML_II__COMMON_MEMBERS;

    /// The namespace name, if any, of the element type
    const utf8_t *ns_name;

    /// The local part of the element-type name
    const utf8_t *local_name;

    /// The namespace prefix part of the element-type name
    const utf8_t *prefix;

    /// Normalized attribute value
    const utf8_t *value;

    /// A flag indicating whether this attribute was actually specified in the start-tag of its element
    bool specified;

    /// A flag indicating whether this attribute is a namespace attribute
    bool is_ns_attribute;

    /// An indication of the type declared for this attribute in the DTD
    enum xml_ii_attr_type_e attrtype;

    /// Ordered list of the element, unparsed entity, or notation IIs referred to in the attribute value
    // TBD similarly to single-item references, "array_no_value" and "array_unknown"?
    xml_ii_array_t references;

    /// Owner element
    struct xml_ii_element_s *owner;
} xml_ii_attribute_t;

/// Processing Instruction information item (section 2.4)
typedef struct xml_ii_pi_s {
    XML_II__COMMON_MEMBERS;

    /// Target part of the processing instruction
    const utf8_t *target;

    /// Content of the processing instruction
    const utf8_t *content;

    /// The base URI of the element
    const utf8_t *base_uri;

    /// The notation information item named by the target
    xml_ii_t *notation;

    /// The document or element II which contains this information item in its [children] property
    xml_ii_t *parent;
} xml_ii_pi_t;

/// Unexpanded Entity information item (section 2.5)
typedef struct xml_ii_unexpanded_entity_s {
    XML_II__COMMON_MEMBERS;

    /// Name of the entity references
    const utf8_t *name;

    /// The system identifier of the entity
    const utf8_t *sysid;

    /// The public identifier of the entity
    const utf8_t *pubid;

    /// The base URI relative to which the system identifier should be resolved
    const utf8_t *decl_base_uri;

    /// The element II which contains this information item in its [children] property
    xml_ii_t *parent;
} xml_ii_unexpanded_entity_t;

/// Character information item(s) (section 2.6, XML applications are free to chunk characters into larger groups as necessary or desirable)
typedef struct xml_ii_text_s {
    XML_II__COMMON_MEMBERS;

    /// Content of the processing instruction
    const utf8_t *content;

    /// Flag: contains only whitespace
    bool whitespace;

    /// The document or element II which contains this information item in its [children] property
    xml_ii_t *parent;
} xml_ii_text_t;

/// Comment information item (section 2.7)
typedef struct xml_ii_comment_s {
    XML_II__COMMON_MEMBERS;

    /// Content of the processing instruction
    const utf8_t *content;

    /// The document or element II which contains this information item in its [children] property
    xml_ii_t *parent;
} xml_ii_comment_t;

/// Document Type Declaration information item (section 2.8)
typedef struct xml_ii_dtd_s {
    XML_II__COMMON_MEMBERS;

    /// The system identifier of the external subset
    const utf8_t *sysid;

    /// The public identifier of the external subset
    const utf8_t *pubid;

    /// An ordered list of child PI IIs, in document order
    xml_ii_list_t children;

    /// The document II which contains this information item in its [children] property
    xml_ii_t *parent;
} xml_ii_dtd_t;

/// Unparsed Entity information item (section 2.9)
typedef struct xml_ii_unparsed_entity_s {
    XML_II__COMMON_MEMBERS;

    /// The name of the entity
    const utf8_t *name;

    /// The system identifier of the entity
    const utf8_t *sysid;

    /// The public identifier of the entity
    const utf8_t *pubid;

    /// The base URI relative to which the system identifier should be resolved
    const utf8_t *decl_base_uri;

    /// The notation name associated with the entity
    const utf8_t *notation_name;

    /// The notation II named by the notation name
    xml_ii_t *notation;
} xml_ii_unparsed_entity_t;

/// Notation information item (section 2.10)
typedef struct xml_ii_notation_s {
    XML_II__COMMON_MEMBERS;

    /// The name of the notation
    const utf8_t *name;

    /// The system identifier of the notation
    const utf8_t *sysid;

    /// The public identifier of the notation
    const utf8_t *pubid;

    /// The base URI relative to which the system identifier should be resolved
    const utf8_t *decl_base_uri;
} xml_ii_notation_t;

/// Namespace information item (section 2.10)
typedef struct xml_ii_namespace_s {
    XML_II__COMMON_MEMBERS;

    /// The prefix whose binding this item describes
    const utf8_t *prefix;

    /// The namespace name to which the prefix is bound
    const utf8_t *ns_name;
} xml_ii_namespace_t;

/// Generic information item, can be typecast to a specific type at runtime
typedef struct xml_ii_s {
    XML_II__COMMON_MEMBERS;
} xml_ii_t;

// Special "poisoned" IIs for references
extern xml_ii_t xml_ii_unknown;
extern xml_ii_t xml_ii_no_value;

/// Binary flags for infoset context
enum {
    /**
        Do not use deduplicating storage for attribute values. Attributes usually have
        a limited set of used values, so de-duplicating them would result in memory
        use savings. However, if the document has unusually unique attribute values,
        using strings directly may offer a performance benefit.
    */
    XML_INFOSET_CTX_F_NO_STORE_ATTR_VALUE  = 1 << 0,

    /** Do not use deduplicating storage for PI content. */
    XML_INFOSET_CTX_F_NO_STORE_PI_CONTENT  = 1 << 1,
};

/// Options for creating an infoset context
typedef struct xml_infoset_ctx_attr_s {
    unsigned int strstore_order;    ///< Log2 of number of buckets in string storage
    uint32_t flags;                 ///< Binary flags
} xml_infoset_ctx_attr_t;

xml_infoset_ctx_t *xml_infoset_ctx_new(const xml_infoset_ctx_attr_t *attr);
void xml_infoset_ctx_delete(xml_infoset_ctx_t *ic);
 
xml_ii_t *xml_ii__new(xml_infoset_ctx_t *ic, enum xml_ii_type_e type, const xmlerr_loc_t *loc);
void xml_ii__delete(xml_ii_t *ii);

/// Mapping between the types and the structures; applies 'something' to every pair
#define XML_II__FOREACH_TYPE(something, arg) \
        something(DOCUMENT, document, arg) \
        something(ELEMENT, element, arg) \
        something(ATTRIBUTE, attribute, arg) \
        something(PI, pi, arg) \
        something(UNEXPANDED_ENTITY, unexpanded_entity, arg) \
        something(TEXT, text, arg) \
        something(COMMENT, comment, arg) \
        something(DTD, dtd, arg) \
        something(UNPARSED_ENTITY, unparsed_entity, arg) \
        something(NOTATION, notation, arg) \
        something(NAMESPACE, namespace, arg)

/// Helper for XML_II__CHKTYPE: construct a type name
#define XML_II__PTR_TYPECHECK_HELPER(t, s, a) \
        || __types_compat(a, struct xml_ii_##s##_s *)

// Check if a pointer is type-compatible with xml_ii_t
#define XML_II__PTR_TYPECHECK(ii) \
        (__types_compat(__typeof__(ii), struct xml_ii_s *) \
         XML_II__FOREACH_TYPE(XML_II__PTR_TYPECHECK_HELPER, __typeof__(ii)))

/// Create a reference to the information item.
#define xml_ii__define_ref(func, strct, extracheck) \
        static inline void \
        func(strct **ptr, strct *ii) \
        { \
            OOPS_ASSERT(*ptr == NULL); /* any previous refs must've been cleared */ \
            OOPS_ASSERT(ii != NULL); \
            extracheck \
            ii->refcnt++; \
            *ptr = ii; \
        }

xml_ii__define_ref(xml_ii_ref, xml_ii_t,)

#define XML_II__DEFINE_TYPED_REF(t, s, a) \
            xml_ii__define_ref(xml_ii_ref_##s, xml_ii_##s##_t, \
                    OOPS_ASSERT(ii->type == XML_II_TYPE_##t);)
XML_II__FOREACH_TYPE(XML_II__DEFINE_TYPED_REF, dummy)

/// Drop a reference to the information item. Reference can be NULL, in which case this has no effect.
#define xml_ii_unref(ptr) \
        do { \
            OOPS_ASSERT(XML_II__PTR_TYPECHECK(*(ptr))); \
            if (*(ptr) != NULL) {\
                if (--((*(ptr))->refcnt) == 0) { \
                    xml_ii__delete((xml_ii_t *)(*(ptr))); \
                } \
                (*ptr) = NULL; \
            } \
        } while (0)

/// Define an accessor function that verifies the type and returns a typecasted pointer
#define XML_II__DEFINE_TYPECAST(t, s, a) \
        static inline xml_ii_##s##_t * \
        XML_II_##t(xml_ii_t *item) \
        { \
            OOPS_ASSERT(item->type == XML_II_TYPE_##t); \
            return (xml_ii_##s##_t *)item; \
        }

XML_II__FOREACH_TYPE(XML_II__DEFINE_TYPECAST, dummy)
#undef XML_II__DEFINE_TYPECAST

/// Typecast into a generic type
#define XML_II(ptr) \
        (OOPS_ASSERT(XML_II__PTR_TYPECHECK(ptr)),(xml_ii_t *)(ptr))

/// Allocate a new item of the specified type
#define XML_II__DEFINE_ALLOC(t, s, a) \
        static inline xml_ii_##s##_t * \
        xml_ii_new_##s(xml_infoset_ctx_t *ic, const xmlerr_loc_t *loc) \
        { \
            return (xml_ii_##s##_t *)xml_ii__new(ic, XML_II_TYPE_##t, loc); \
        }

XML_II__FOREACH_TYPE(XML_II__DEFINE_ALLOC, dummy)
#undef XML_II__DEFINE_ALLOC

/**
    List of members with UTF-8 strings. Flag is the infoset context's flag member,
    if condition evaluates to true - do not use deduplicating string storage.
*/
#define XML_II__FOREACH_STRSTORE_MEMBER(something, flag) \
        something(document, base_uri, false) \
        something(document, encoding, false) \
        something(element, ns_name, false) \
        something(element, local_name, false) \
        something(element, prefix, false) \
        something(element, base_uri, false) \
        something(attribute, ns_name, false) \
        something(attribute, local_name, false) \
        something(attribute, prefix, false) \
        something(attribute, value, ((flag) & XML_INFOSET_CTX_F_NO_STORE_ATTR_VALUE)) \
        something(pi, target, false) \
        something(pi, content, ((flag) & XML_INFOSET_CTX_F_NO_STORE_PI_CONTENT)) \
        something(pi, base_uri, false) \
        something(unexpanded_entity, name, false) \
        something(unexpanded_entity, sysid, false) \
        something(unexpanded_entity, pubid, false) \
        something(unexpanded_entity, decl_base_uri, false) \
        something(text, content, true) \
        something(comment, content, true) \
        something(dtd, sysid, false) \
        something(dtd, pubid, false) \
        something(unparsed_entity, sysid, false) \
        something(unparsed_entity, pubid, false) \
        something(unparsed_entity, decl_base_uri, false) \
        something(notation, name, false) \
        something(notation, sysid, false) \
        something(notation, pubid, false) \
        something(notation, decl_base_uri, false) \
        something(namespace, prefix, false) \
        something(namespace, ns_name, false)

/// Declare prototypes for the member-setting functions
#define XML_II__DECLARE_SETTER(s, m, c) \
        void xml_ii_##s##_set_##m(xml_ii_##s##_t *ii, const utf8_t *new_value);

XML_II__FOREACH_STRSTORE_MEMBER(XML_II__DECLARE_SETTER, dummy)
#undef XML_II__DECLARE_SETTER


/// List of IIs with an ordered list of 'children'.
#define XML_II__FOREACH_PARENT_TYPE(something) \
        something(DOCUMENT, document) \
        something(ELEMENT, element) \
        something(DTD, dtd)

/// List of IIs that can be a child of another II (via the `parent` link)
#define XML_II__FOREACH_CHILD_TYPE(something) \
        something(ELEMENT, element) \
        something(PI, pi) \
        something(UNEXPANDED_ENTITY, unexpanded_entoty) \
        something(TEXT, text) \
        something(COMMENT, comment) \
        something(DTD, dtd)

/// Declare prototypes for manipulators of the 'children' list
#define XML__II_DECLARE_CHILDREN_FUNCTIONS(t, s) \
        void xml_ii_##s##_insert_child_after(xml_ii_##s##_t *parent, xml_ii_t *child, xml_ii_t *after); \
        static inline void \
        xml_ii_##s##_insert_child_first(xml_ii_##s##_t *parent, xml_ii_t *child) \
        { \
            xml_ii_##s##_insert_child_after(parent, child, NULL); \
        } \
        static inline void \
        xml_ii_##s##_insert_child_last(xml_ii_##s##_t *parent, xml_ii_t *child) \
        { \
            xml_ii_##s##_insert_child_after(parent, child, STAILQ_LAST(&parent->children, xml_ii_s, link)); \
        }

XML_II__FOREACH_PARENT_TYPE(XML__II_DECLARE_CHILDREN_FUNCTIONS)
#undef XML__II_DECLARE_CHILDREN_FUNCTIONS

void xml_ii_element_insert_attribute(xml_ii_element_t *e, xml_ii_attribute_t *a);
void xml_ii_attribute_delete(xml_ii_attribute_t *a);
void xml_ii_document_insert_notation(xml_ii_document_t *doc, xml_ii_notation_t *n);
void xml_ii_notation_delete(xml_ii_notation_t *n);
void xml_ii_document_insert_unparsed_entity(xml_ii_document_t *doc, xml_ii_unparsed_entity_t *unp);
void xml_ii_remove_unparsed_entity(xml_ii_unparsed_entity_t *unp);

void xml_ii_traverse(xml_ii_t *top, bool (*pre_func)(void *, xml_ii_t *),
        bool (*post_func)(void *, xml_ii_t *), void *arg);
void xml_ii_remove_tree(xml_ii_t *top);

#endif
