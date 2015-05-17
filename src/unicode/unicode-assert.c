/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Assertions for UCS-4 characters testing other code assumptions.
*/
#include "unicode/unicode.h"

#if defined(OOPS_COVERAGE)

/**
    Check that a code point does not compose with any other code point,
    before or after, and has combining class of 0.

    @param cp Codepoint to check
    @return Nothing (triggers assertion if any of the assumptions fails)
*/
void
ucs4_assert_does_not_compose(ucs4_t cp)
{
    const ucs4_t *pair;

    if (ucs4_get_ccc(cp)) {
        OOPS; // Non-zero combining class
    }
    if (ucs4_get_cw_len(cp)) {
        OOPS; // Composes with preceding
    }
    for (pair = ucs4_composes_with; pair < ucs4_composes_with_end; pair += 2) {
        if (pair[0] == cp) {
            OOPS; // Composes with following
        }
    }
}

/**
    Check that a code point does not compose with any other code point,
    before, and has combining class of 0.

    @param cp Codepoint to check
    @return Nothing (triggers assertion if any of the assumptions fails)
*/
void
ucs4_assert_does_not_compose_with_preceding(ucs4_t cp)
{
    if (ucs4_get_ccc(cp)) {
        OOPS; // Non-zero combining class
    }
    if (ucs4_get_cw_len(cp)) {
        OOPS; // Composes with preceding
    }
}

#endif
