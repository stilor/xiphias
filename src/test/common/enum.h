/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */
#ifndef __test_common_enum_h_
#define __test_common_enum_h_

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

#define ENUM_DECLARE(x) \
        const enumtbl_t enum_##x = { \
            .vals = enumval_##x, \
            .nvals = sizeofarray(enumval_##x), \
        }

#define ENUM_VAL(a,s)  { .val = a, .id = #a, .str = s },

#endif
