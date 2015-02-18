/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    USC-4 character database definitions
*/
#ifndef __util_ucs4data_h_
#define __util_ucs4data_h_

#include <stdint.h>

/**
    Definition of a character information block. Note that the order of the fields
    is manually adjusted to put as many fields as possible on word/byte boundaries.
*/
typedef struct ucs4data_s {
    unsigned int decomp_idx:16;     ///< Index of full canonical decomposition
    unsigned int comp_idx:14;       ///< Index of 'composes with' pairs block
    unsigned int nfc_qc:2;          ///< Normalization Form C - Quick Check property
    unsigned int ccc:8;             ///< Canonical combining class
    unsigned int gencat:5;          ///< General category
    unsigned int decomp_cnt:3;      ///< Number of characters in full canonical decomposition
    unsigned int comp_cnt:9;        ///< Number of 'composing with' records
} ucs4data_t;

/// General character categories. See 4.5 "General Category" in Unicode spec.
enum {
    UCS4_GC_Lu,     ///< Uppercase letter
    UCS4_GC_Ll,     ///< Lowercase letter
    UCS4_GC_Lt,     ///< Titlecase letter (digraphic with 1st part uppercase)
    UCS4_GC_Lm,     ///< Modifier letter
    UCS4_GC_Lo,     ///< Other letters (inc. syllables and ideographs)
    UCS4_GC_Mn,     ///< Nonspacing combining mark
    UCS4_GC_Mc,     ///< Spacing combining mark
    UCS4_GC_Me,     ///< Enclosing combining mark
    UCS4_GC_Nd,     ///< Decimal digit
    UCS4_GC_Nl,     ///< Letterlike numeric character
    UCS4_GC_No,     ///< Numeric character of other type
    UCS4_GC_Pc,     ///< Connecting punctuation mark (e.g. tie)
    UCS4_GC_Pd,     ///< Dash or hyphen punctuation
    UCS4_GC_Ps,     ///< Opening punctuation mark (of a pair)
    UCS4_GC_Pe,     ///< Closing punctuation mark (of a pair)
    UCS4_GC_Pi,     ///< Initial quotation mark
    UCS4_GC_Pf,     ///< Final quotation mark
    UCS4_GC_Po,     ///< Other punctuation
    UCS4_GC_Sm,     ///< Symbol of mathematical use
    UCS4_GC_Sc,     ///< Currency symbol
    UCS4_GC_Sk,     ///< Non-letterlike modifier symbol
    UCS4_GC_So,     ///< Symbol of other type
    UCS4_GC_Zs,     ///< Space separator
    UCS4_GC_Zl,     ///< Line separator
    UCS4_GC_Zp,     ///< Paragraph separator
    UCS4_GC_Cc,     ///< C0 or C1 control code
    UCS4_GC_Cf,     ///< Format control
    UCS4_GC_Cs,     ///< Surrogate pair
    UCS4_GC_Co,     ///< Private use character
    UCS4_GC_Cn,     ///< Unassigned code or non-character
};

/// Values for NFC_QC ("Quick Check for Normalization Form C") property
enum {
    UCS4_NFC_QC_Y,  ///< Character allowed in NFC
    UCS4_NFC_QC_N,  ///< Characyer not allowed in NFC
    UCS4_NFC_QC_M,  ///< Characyer may be allowed in NFC (needs full check)
};

extern const uint32_t ucs4_full_decomp[];
extern const uint32_t ucs4_composes_with[];
extern const ucs4data_t ucs4_characters[];

/// Get canonical combining class for a character
#define ucs4_get_ccc(cp) (ucs4_characters[cp].ccc)

#endif
