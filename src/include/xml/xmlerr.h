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
    XMLERR_NOTE,         ///< Informational (e.g. additional information for another message)
    XMLERR_WARN,         ///< Warning (can successfully recover)
    XMLERR_ERROR,        ///< Error (may continue processing but fail at the end)
};

/// Specifications that define error conditions
enum xmlerr_spec_e {
    XMLERR_SPEC_NONE,    ///< No specification (e.g. internal error)
    XMLERR_SPEC_XML,     ///< W3C: XML 1.x
    XMLERR_SPEC_XMLNS,   ///< W3C: Namespaces in XML 1.x
};

/// XML 1.x messages (TBD: move to a separate header)
enum {
    // Production mismatches
    XMLERR_XML_P_XMLDecl,
    XMLERR_XML_P_TextDecl,
    XMLERR_XML_P_VersionInfo,
    XMLERR_XML_P_EncodingDecl,
    XMLERR_XML_P_SDDecl,

    // Other errors (spelled in text of the spec)
    XMLERR_XML_ENCODING_ERROR,

    // Well-formedness constraints (spelled in production comments)
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
        XMLERR_MK(XMLERR_NOTE, XMLERR_SPEC_NONE, 0)

/// Code for internal errors
#define XMLERR_INTERNAL                           \
        XMLERR_MK(XMLERR_ERROR, XMLERR_SPEC_NONE, 0)

#endif
