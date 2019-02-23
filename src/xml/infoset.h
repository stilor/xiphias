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

/// Head of the information items list: single-linked, with tail pointer
typedef STAILQ_HEAD(xml_ii_list_s, xml_ii_s) xml_ii_list_t;

/**
    Array of references; used for many-to-one relations like "IDREF attributes to a single ID"
    or "list of in-scope namespaces to namespace II" (since namespaces are inherited from parent
    element to its children, we don't want to create a copy of all namespace IIs to create a list
    in each child).
*/
typedef struct xml_ii_array_s {
    size_t num;         ///< Number of references in the array
    xml_ii_t **refs;    ///< References to the information items
} xml_ii_array_t;

/**
    Common members of all information items. Not all IIs can be referenced or linked in some II's
    list of children, but the code that will iterate over such lists/references needs to be agnostic
    of the II type. The link pointer is also used internally to store free structures.
*/
#define XML_II__COMMON_MEMBERS \
    enum xml_ii_type_e type;        /**< Type of the II */ \
    uint32_t refcnt;                /**< References from other IIs */ \
    STAILQ_ENTRY(xml_ii_s) link;    /**< Link for 'children' list */ \
    xmlerr_loc_t loc                /**< Location of the definition */ 



/// Document information item (section 2.1)
typedef struct xml_ii_document_s {
    XML_II__COMMON_MEMBERS;

    /// An ordered list of child IIs, in document order
    xml_ii_list_t children;

    /// The element II corresponding to the document element
    xml_ii_t *document_element;

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
    const char *value;

    /// A flag indicating whether this attribute was actually specified in the start-tag of its element
    bool specified;

    /// An indication of the type declared for this attribute in the DTD
    enum xml_ii_attr_type_e attrtype;

    /// Number of references in the array
    uint32_t num_references;

    /// Array of references
    xml_ii_t **references;

    /// Owner element
    xml_ii_t *owner;
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

/// Mapping between the types and the structures; applies 'something' to every pair
#define XML_II__FOREACH_TYPE(something) \
        something(DOCUMENT, document) \
        something(ELEMENT, element) \
        something(ATTRIBUTE, attribute) \
        something(PI, pi) \
        something(UNEXPANDED_ENTITY, unexpanded_entity) \
        something(TEXT, text) \
        something(COMMENT, comment) \
        something(DTD, dtd) \
        something(UNPARSED_ENTITY, unparsed_entity) \
        something(NOTATION, notation) \
        something(NAMESPACE, namespace)

/// Define an accessor function that verifies the type and returns a typecasted pointer
#define XML_II__DEFINE_TYPECAST(t, s) \
        static inline xml_ii_##s##_t * \
        XML_II_##t(xml_ii_t *item) \
        { \
            OOPS_ASSERT(item->type == XML_II_TYPE_##t); \
            return (xml_ii_##s##_t *)item; \
        }

XML_II__FOREACH_TYPE(XML_II__DEFINE_TYPECAST)
#undef XML_II__DEFINE_TYPECAST

// Special "poisoned" IIs for references
extern xml_ii_t xml_ii_unknown;
extern xml_ii_t xml_ii_no_value;

// Opaque type for infoset manipulation
typedef struct xml_infoset_ctx_s xml_infoset_ctx_t;

xml_infoset_ctx_t *xml_infoset_ctx_new(void);
void xml_infoset_ctx_delete(xml_infoset_ctx_t *ic);
 
// TBD make xml_ii_new internal interface; expose xml_ii_new_{document,element,...} with appropriate extra args
xml_ii_t *xml_ii_new(xml_infoset_ctx_t *ic, enum xml_ii_type_e type);
void xml_ii_delete(xml_infoset_ctx_t *ic, xml_ii_t *ii);

#endif
