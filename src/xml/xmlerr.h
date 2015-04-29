/* vi: set ts=5 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Handle for reading an XML entity.
*/

#ifndef __xml_xmlerr_h_
#define __xml_xmlerr_h_

#include <stdint.h>

/// Description of the error location
typedef struct {
    const char *src;     ///< Input source (URL/file/whatever)
    uint32_t line;       ///< Line to which the message pertains
    uint32_t pos;        ///< Position in the line to which the message pertains
} xmlerr_loc_t;

/// XML error severity
enum xmlerr_severity_e {
    XMLERR__NONE,        ///< Internally used value: no error
    XMLERR_INFO,         ///< Informational (e.g. additional information for another message)
    XMLERR_WARN,         ///< Warning (can successfully recover)
    XMLERR_ERROR,        ///< Error (may continue processing but fail at the end)
};

/// Specifications that define error conditions
enum xmlerr_spec_e {
    XMLERR_SPEC_NONE,    ///< No specification (e.g. internal error)
    XMLERR_SPEC_XML,     ///< W3C: XML 1.x
    XMLERR_SPEC_XMLNS,   ///< W3C: Namespaces in XML 1.x
};

#define XMLERR_DEF(a, b) XMLERR_##a##_##b,

#define XMLERR_XML \
          /* Production mismatches */ \
          XMLERR_DEF(XML, P_Char) \
          XMLERR_DEF(XML, P_XMLDecl) /* or TextDecl */ \
          XMLERR_DEF(XML, P_document) \
          XMLERR_DEF(XML, P_content) \
          XMLERR_DEF(XML, P_element) \
          XMLERR_DEF(XML, P_STag) /* or EmptyElemTag */ \
          XMLERR_DEF(XML, P_ETag) \
          XMLERR_DEF(XML, P_Attribute) \
          XMLERR_DEF(XML, P_AttValue) \
          XMLERR_DEF(XML, P_Reference) \
          XMLERR_DEF(XML, P_CharRef) \
          XMLERR_DEF(XML, P_EntityRef) \
          XMLERR_DEF(XML, P_PEReference) \
          XMLERR_DEF(XML, P_Comment) \
          XMLERR_DEF(XML, P_PI) \
          XMLERR_DEF(XML, P_CharData) \
          XMLERR_DEF(XML, P_CDSect) \
          XMLERR_DEF(XML, P_doctypedecl) \
          XMLERR_DEF(XML, P_SystemLiteral) \
          XMLERR_DEF(XML, P_PubidLiteral) \
          XMLERR_DEF(XML, P_ExternalID) \
          XMLERR_DEF(XML, P_EntityDecl) \
          XMLERR_DEF(XML, P_EntityValue) \
          XMLERR_DEF(XML, P_NotationDecl) \
          XMLERR_DEF(XML, P_extSubset) \
          /* Other errors and recommendations (spelled in text of the spec) */ \
          XMLERR_DEF(XML, ENCODING_ERROR) \
          XMLERR_DEF(XML, PREDEFINED_ENTITY) \
          XMLERR_DEF(XML, ENTITY_REDECLARED) \
          XMLERR_DEF(XML, FUTURE_VERSION) \
          XMLERR_DEF(XML, NORMALIZATION) \
          /* Well-formedness constraints (spelled in production comments) */ \
          XMLERR_DEF(XML, WFC_PES_IN_INTERNAL_SUBSET) \
          XMLERR_DEF(XML, WFC_EXTERNAL_SUBSET) \
          XMLERR_DEF(XML, WFC_PE_BETWEEN_DECLARATIONS) \
          XMLERR_DEF(XML, WFC_ELEMENT_TYPE_MATCH) \
          XMLERR_DEF(XML, WFC_UNIQUE_ATT_SPEC) \
          XMLERR_DEF(XML, WFC_NO_EXTERNAL_ENTITY_REFERENCES) \
          XMLERR_DEF(XML, WFC_NO_LT_IN_ATTRIBUTE_VALUES) \
          XMLERR_DEF(XML, WFC_LEGAL_CHARACTER) \
          XMLERR_DEF(XML, WFC_ENTITY_DECLARED) \
          XMLERR_DEF(XML, WFC_PARSED_ENTITY) \
          XMLERR_DEF(XML, WFC_NO_RECURSION) \
          XMLERR_DEF(XML, WFC_IN_DTD) \
          /* Validity constraints */ \
          XMLERR_DEF(XML, VC_PROPER_DECL_PE_NESTING) \
          XMLERR_DEF(XML, VC_NOTATION_DECLARED) \
          XMLERR_DEF(XML, VC_UNIQUE_NOTATION_NAME)
          

/**
    XML 1.x messages.

    @todo Move the XML1.x error codes to a separate header?

    @todo Sort XML 1.0 codes first, then XML 1.1 codes
*/
enum xml_errcode_e {
    XMLERR_XML
};

/// Error code and severity
typedef uint32_t xmlerr_info_t;

/// Combine severity, specification & code into a single number
#define XMLERR_MK(s, sp, cd) (((s) << 28) | ((sp) << 16) | (cd))

/// Get severity from combined code
#define XMLERR_SEVERITY(x)    (((x) >> 28) & 0x000F)

/// Get defining spec from combined code
#define XMLERR_SPEC(x)        (((x) >> 16) & 0x0FFF)

/// Get error code from combined code
#define XMLERR_CODE(x)        ((x) & 0xFFFF)


/// Combine severity/specification/code into a single initializer
#define XMLERR(s, sp, cd)                         \
        XMLERR_MK(XMLERR_##s, XMLERR_SPEC_##sp, XMLERR_##sp##_##cd)

/// Code for a undescript note
#define XMLERR_NOTE                               \
        XMLERR_MK(XMLERR_INFO, XMLERR_SPEC_NONE, 0)

/// Code for internal errors
#define XMLERR_INTERNAL                           \
        XMLERR_MK(XMLERR_ERROR, XMLERR_SPEC_NONE, 0)

/// Code for absence of errors
#define XMLERR_NOERROR                            \
        XMLERR_MK(XMLERR__NONE, XMLERR_SPEC_NONE, 0)

#endif
