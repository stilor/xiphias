/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Checking for Normalization Form C.
*/
#include "util/xutil.h"

#include "unicode/unicode.h"
#include "unicode/nfc.h"

/// Opaque handle for normalization check
struct nfc_s {
    ucs4_t starter;         ///< First character in a combining sequence
    size_t seqlen;          ///< Current index in a sequence
    uint8_t last_ccc;       ///< Last character's canonical combining class
    bool suppress;          ///< Suppress denormalization errors until next starter
};

/**
    Check if two characters can form a primary composite.

    @param cp1 First character
    @param cp2 Second character
    @return UCS-4 code point for the composite, or UCS4_NOCHAR if the characters
        do not form a composite
*/
static inline ucs4_t
nfc_combines(ucs4_t cp1, ucs4_t cp2)
{
    size_t i, comp_cnt;
    const ucs4_t *cw;

    // This function is only used for 'quick check -- maybe' characters (in cp2)
    // and as of Unicode 7.0, there are no such characters that do not compose
    // with anything. Thus, no real benefit in checking comp_cnt != 0 before
    // retrieving the pointer to 'composes with' list.
    comp_cnt = ucs4_get_cw_len(cp2);
    cw = ucs4_get_cw(cp2); // UCS4 pairs
    for (i = 0; i < comp_cnt; i++, cw += 2) {
        if (cw[0] == cp1) {
            return cw[1];
        }
    }
    return UCS4_NOCHAR;
}

/**
    Create a new handle for normalization check.

    @return Allocated handle
*/
nfc_t *
nfc_create(void)
{
    nfc_t *nfc;

    nfc = xmalloc(sizeof(nfc_t));
    nfc->starter = UCS4_NOCHAR;
    nfc->seqlen = 0;
    nfc->last_ccc = 0;
    nfc->suppress = false;
    return nfc;
}

/**
    Destroy a normalization check handle.

    @param nfc Handle
    @return Nothing
*/
void
nfc_destroy(nfc_t *nfc)
{
    xfree(nfc);
}

/**
    Check if the next character breaks the normalization.

    @param nfc Handle
    @param cp Next character
    @return true if character is ok (string is still normalized), false otherwise
*/
bool
nfc_check_nextchar(nfc_t *nfc, ucs4_t cp)
{
    uint8_t ccc, new_last_ccc;
    unsigned int nfc_qc;
    size_t fcd_len;
    const ucs4_t *fcd;
    ucs4_t new_cp;

    ccc = ucs4_get_ccc(cp);
    fcd_len = ucs4_get_fcd_len(cp);
    if (!fcd_len) {
        // This character does not have a canonical decomposition, use its CCC
        new_last_ccc = ccc;
    }
    else {
        // For characters with a canonical decomposition, use the CCC from the last
        // character in the full canonical decomposition. The reason is that as we
        // go further, we may encounter a 'quick check -- maybe' characters which
        // will be subject to the same kind of CCC ordering. This also will allow
        // us to check if a given character is blocked more easily.
        //
        // We can do this because when we decompose this character, it will be canonically
        // ordered (since the character sequence was normalized up to this point), and
        // when recombining - these first characters will be recombining into the
        // original character first.
        /// @todo Record .last_ccc in UCS4 DB to avoid extra lookup here?
        fcd = ucs4_get_fcd(cp);
        new_last_ccc = ucs4_get_ccc(fcd[fcd_len - 1]);
    }
    if (ccc && ccc < nfc->last_ccc) {
        // Violates combining class constraint. This is a non-starter character.
        goto denorm;
    }

    nfc_qc = ucs4_get_nfc_qc(cp);
    switch (nfc_qc) {
    case UCS4_NFC_QC_Y:
        // This can happen with either starter character characters, or non-starters
        // that do not compose with anything (e.g. U+0305, "COMBINING OVERLINE").
        // For non-starters, continue accumulating the input (we may see violations
        // of combining class ordering. 
        if (ccc) {
            goto more;
        }
        // Starter character with 'quick check -- yes'  means we've reached a point
        // where the previous characters are confirmed to be normalized; reset
        // the handle to initial state. This character is also ok (so far).
        goto reset;

    case UCS4_NFC_QC_N:
        // Not allowed by decomposition rules. Store the character if it was a starter
        // (as it may influence which following starter characters reset the handle)
        if (!ccc) {
            nfc->starter = cp;
        }
        goto denorm;

    default:
        // The only value possible
        OOPS_ASSERT(nfc_qc == UCS4_NFC_QC_M);

        // Current Unicode version (7.0) does not have any 'quick check -- maybe' characters
        // that decompose into multiple codepoints, thus the assertion. It may change in
        // the future - the handling of such characters would have to be rethought
        // at that time: current algorithm assumes that the sequence of combining marks
        // recorded so far is ordered and the only starter is the 0th character.
        OOPS_ASSERT(fcd_len == 0);

        // At this point, we know the buffer satisfies the following conditions:
        // - Character #0 is the only starter: if there was another starter (ccc=0) character,
        //   and it didn't compose with character #0, the handle would've been reset, storing
        //   only the last starter.
        // - If the sequence is not marked as defective, character #0 is a starter (starters
        //   with non-starter decompositions are 'quick check -- no' and are not stored in
        //   handle's buffer)
        // - Non-starters, if any, are canonically ordered: they are either resulting from
        //   the full canonical decomposition we've just performed, or they have satisfied
        //   this very check at the previous steps.
        if (!ccc) {
            // This is a new starter. If the previous character was a non-starter (ccc!=0),
            // reset the handle - this character cannot continue the previous sequence.
            // (it is blocked from the previous starter and it becomes the "last starter"
            // for any characters that follow). If the last character was a starter, need
            // to see if this character combines with it (there are primary composites
            // of two starters). If we're already saw a denormalization, consider this
            // character a base for the new character.
            if (nfc->starter == UCS4_NOCHAR
                    || nfc->seqlen > 1
                    || nfc->suppress
                    || (new_cp = nfc_combines(nfc->starter, cp)) == UCS4_NOCHAR) {
                // Starter and it didn't combine with previous character. Becomes new base
                // for the sequence.
                goto reset;
            }
            // Two starters combining. We may get some other non-starters (or other starters
            // composing with the product of this two) following this would-be primary composite;
            // disregard until we get a proper starter. Replace the character with the composite
            // as further starters may compose further with it.
            nfc->starter = new_cp;
            goto denorm;
        }

        if (nfc->suppress) {
            // Still part of the previous denormalized sequence. Signaled error already;
            // no need to raise it again.
            goto more;
        }

        // See if the new character is non-blocked from the starter
        if ((ccc > nfc->last_ccc || nfc->seqlen == 1)
                && nfc->starter != UCS4_NOCHAR
                && nfc_combines(nfc->starter, cp) != UCS4_NOCHAR) {
            // Non-blocked and forms a primary composite. Don't need to remember the characters
            // until we recover: any starter will cause a reset (since it is blocked from the
            // current starter by this character with non-zero CCC).
            goto denorm;
        }

        // Good for now
        goto more;
    }

    OOPS_UNREACHABLE; // LCOV_EXCL_LINE

more:
    // This character is accepted (or part of a previously reported sequence)
    nfc->last_ccc = new_last_ccc;
    nfc->seqlen++;
    return true;

reset:
    // Previous characters are normalized and current character is a new starter.
    OOPS_ASSERT(ccc == 0);
    nfc->suppress = false;
    nfc->starter = cp;
    nfc->seqlen = 1;
    nfc->last_ccc = new_last_ccc;
    return true;

denorm:
    // Suppress further warnings on combining marks until the next starter. Note
    // that non-combining normalization failures (e.g. singletons) are still reported.
    nfc->suppress = true;
    nfc->last_ccc = new_last_ccc;
    nfc->seqlen++;
    return false;
}
