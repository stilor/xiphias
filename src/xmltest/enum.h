/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */
#ifndef __xmltest_enum_h_
#define __xmltest_enum_h_

/// Description of one enumerated value
typedef struct {
    unsigned int val;       ///< Value
    const char *str;        ///< String describing the value
    const char *id;         ///< String naming the ID
} enumval_t;

/// Description of enumerated values
typedef struct {
	const enumval_t *vals;  ///< Array of values
	size_t nvals;           ///< Number of enumeration elements
} enumtbl_t;

const char *enum2str(unsigned int val, const enumtbl_t *tbl);
const char *enum2id(unsigned int val, const enumtbl_t *tbl, const char *strip);

extern const enumtbl_t enum_xml_version;
extern const enumtbl_t enum_xml_standalone;
extern const enumtbl_t enum_cbtype;
extern const enumtbl_t enum_xmlerr_severity;
extern const enumtbl_t enum_xmlerr_spec;
extern const enumtbl_t enum_xmlerr_code;
extern const enumtbl_t enum_reftype;
extern const enumtbl_t enum_attrnorm;

#endif
