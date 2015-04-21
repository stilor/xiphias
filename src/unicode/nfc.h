/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Checking for Normalization Form C.
*/
#ifndef __unicode_nfc_h_
#define __unicode_nfc_h_

#include "unicode/unicode.h"

typedef struct nfc_s nfc_t;

nfc_t *nfc_create(void);
void nfc_destroy(nfc_t *nfc);
bool nfc_check_nextchar(nfc_t *nfc, ucs4_t cp);

#endif
