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
    // Well-formedness constraints
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

    // Other errors (spelled in text of the spec)
};

/// Error code and severity
typedef struct {
    enum xmlerr_severity_e severity:4;  ///< Severity of the message
    enum xmlerr_spec_e spec:12;         ///< Defining specification for this message
    unsigned int code:16;               ///< Message code
} xmlerr_info_t;

/// Combine severity/specification/code into a single initializer
#define XMLERR(s, sp, cd)                         \
        ((xmlerr_info_t){                         \
               .severity = XMLERR_##s,            \
               .spec = XMLERR_SPEC_##sp,          \
               .code = XMLERR_##sp##_##cd         \
         })

#endif
