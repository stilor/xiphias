/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Miscellaneous definitions.
*/
#ifndef __util_murmurhash_h_
#define __util_murmurhash_h_

#include <stddef.h>

uint32_t murmurhash32(const void *key, size_t len);

#endif
