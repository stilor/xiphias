/* vi: set ts=5 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Handle for reading an XML entity.
*/

#ifndef __xml_xmlerr_h_
#define __xml_xmlerr_h_

#include <stdint.h>

/// Marker used in line/pos fields to indicate "error at end of input"
/// @todo remove once all errors are raised at the end of locked input
/// (currently, the check for partial characters is using XMLERR_EOF -
/// lock every input before submitting it to processing and raise the error
/// at a position one-past-the-last character?)
#define XMLERR_EOF       ((uint32_t)-1)

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

/**
    XML 1.x messages.

    @todo Move the XML1.x error codes to a separate header?

    @todo Sort XML 1.0 codes first, then XML 1.1 codes
*/
enum xml_errcode_e {
    // Production mismatches
    XMLERR_XML_P_BASE              = 0x0000,
    XMLERR_XML_P_Char,
    XMLERR_XML_P_XMLDecl,          // XMLDecl or TextDecl
    XMLERR_XML_P_document,
    XMLERR_XML_P_element,
    XMLERR_XML_P_STag,             // STag or EmptyElemTag
    XMLERR_XML_P_ETag,
    XMLERR_XML_P_Attribute,
    XMLERR_XML_P_AttValue,
    XMLERR_XML_P_Reference,
    XMLERR_XML_P_CharRef,
    XMLERR_XML_P_EntityRef,
    XMLERR_XML_P_PEReference,
    XMLERR_XML_P_Comment,
    XMLERR_XML_P_PI,
    XMLERR_XML_P_CharData,
    XMLERR_XML_P_CDSect,
    XMLERR_XML_P_doctypedecl,
    XMLERR_XML_P_SystemLiteral,
    XMLERR_XML_P_PubidLiteral,
    XMLERR_XML_P_ExternalID,
    XMLERR_XML_P_EntityDecl,
    XMLERR_XML_P_EntityValue,

    // Other errors and recommendations (spelled in text of the spec)
    XMLERR_XML_OTHER_BASE          = 0x0100,
    XMLERR_XML_ENCODING_ERROR,
    XMLERR_XML_PREDEFINED_ENTITY,
    XMLERR_XML_ENTITY_REDECLARED,
    XMLERR_XML_FUTURE_VERSION,

    // Well-formedness constraints (spelled in production comments)
    XMLERR_XML_WFC_BASE            = 0x0200,
    XMLERR_XML_WFC_PES_IN_INTERNAL_SUBSET,
    XMLERR_XML_WFC_EXTERNAL_SUBSET,
    XMLERR_XML_WFC_PE_BETWEEN_DECLARATIONS,
    XMLERR_XML_WFC_ELEMENT_TYPE_MATCH,
    XMLERR_XML_WFC_UNIQUE_ATT_SPEC,
    XMLERR_XML_WFC_NO_EXTERNAL_ENTITY_REFERENCES,
    XMLERR_XML_WFC_NO_LT_IN_ATTRIBUTE_VALUES,
    XMLERR_XML_WFC_LEGAL_CHARACTER,
    XMLERR_XML_WFC_ENTITY_DECLARED,
    XMLERR_XML_WFC_PARSED_ENTITY,
    XMLERR_XML_WFC_NO_RECURSION,
    XMLERR_XML_WFC_IN_DTD,

    // Validity constraints
    XMLERR_XML_VC_BASE             = 0x0300,
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
