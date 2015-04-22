/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Checking for Normalization Form C.
*/
#include "util/xutil.h"

#include "unicode/unicode.h"
#include "unicode/nfc.h"

/**
    Unicode allows arbitrarily long sequences of combining characters.
    Typical strings are just a few characters, though. Thus, start small
    and reallocate the buffer as needed.
*/
#define INITIAL_BUFFER_SIZE     16

/// Opaque handle for normalization check
struct nfc_s {
    ucs4_t *buf;            ///< Buffer
    size_t idx;             ///< Current index
    size_t sz;              ///< Size of buffer (UCS-4 characters)

    uint8_t last_ccc;       ///< Last character's canonical combining class
    bool suppress;          ///< Suppress denormalization errors until next starter
    bool defective;         ///< Defective combining sequence at the start

    // TBD is it sufficient to just store the starter for the sequence and the
    // last_ccc? 
    /// Initial buffer
    ucs4_t ibuf[INITIAL_BUFFER_SIZE];
};

/**
    Reallocate the buffer doubling its size.

    @param nfc Handle
    @return Nothing
*/
static inline void
nfc_realloc(nfc_t *nfc)
{
    nfc->sz *= 2;
    if (nfc->buf == nfc->ibuf) {
        // Switch from static buffer
        nfc->buf = xmalloc(nfc->sz * sizeof(ucs4_t));
        memcpy(nfc->buf, nfc->ibuf, sizeof(nfc->ibuf));
    }
    else {
        nfc->buf = xrealloc(nfc->buf, nfc->sz * sizeof(ucs4_t));
    }
}

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

    if ((comp_cnt = ucs4_get_cw_len(cp2)) == 0) {
        return UCS4_NOCHAR; // does not combine with anything
    }
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
    nfc->buf = nfc->ibuf;
    nfc->idx = 0;
    nfc->sz = INITIAL_BUFFER_SIZE;
    nfc->last_ccc = 0;
    nfc->suppress = false;
    nfc->defective = 0;
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
    if (nfc->buf != nfc->ibuf) {
        xfree(nfc->buf);
    }
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
    size_t fcd_len;
    const ucs4_t *fcd;
    ucs4_t new_cp;
    bool rv = true;

    if ((ccc = ucs4_get_ccc(cp)) != 0 && ccc < nfc->last_ccc) {
        // Violates combining class constraint
        goto denorm;
    }
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

    switch (ucs4_get_nfc_qc(cp)) {
    case UCS4_NFC_QC_Y:
        // This can happen with either starter character characters, or non-starters
        // that do not compose with anything (e.g. U+0305, "COMBINING OVERLINE").
        // For non-starters, continue accumulating the input (we may see violations
        // of combining class ordering. 
        if (ccc) {
            goto store;
        }
        // Starter character with 'quick check -- yes'  means we've reached a point
        // where the previous characters are confirmed to be normalized; reset
        // the handle to initial state. This character is also ok (so far).
        goto reset;

    case UCS4_NFC_QC_N:
        // Not allowed by decomposition rules
        goto denorm;

    case UCS4_NFC_QC_M:
        // This character may alter the previous character(s). However, if this is
        // the very first character, it cannot change anything - just store it and,
        // if it is a non-starter, mark as defective combining sequence. Being
        // defective does not cause it to be considered denormalized - just makes
        // it easier to check the assumption that character #0 is a starter. Note
        // that characters with non-starter decomposition are considered 'full
        // composition exclusions' and are thus/ assigned a 'quick check -- no'
        // property; they are not handled in this case.
        if (!nfc->idx) {
            if (ccc) {
                // Non-starter at the beginning
                nfc->defective = true;
            }
            goto store;
        }

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
            if (nfc->idx != 1
                    || nfc->defective
                    || nfc->suppress
                    || (new_cp = nfc_combines(nfc->buf[0], cp)) == UCS4_NOCHAR) {
                // Starter and it didn't combine with previous character. Becomes new base
                // for the sequence.
                goto reset;
            }
            // Two starters combining. We may get some other non-starters (or other starters
            // composing with the product of this two) following this would-be primary composite;
            // disregard until we get a proper starter. Replace the character with the composite
            // as further starters may compose further with it.
            nfc->buf[0] = new_cp;
            goto denorm;
        }

        if (nfc->suppress) {
            // Still part of the previous denormalized sequence. Signaled error already;
            // no need to raise it again. Not storing the character, not updating CCC.
            return true;
        }

        // See if the new character is non-blocked from the starter
        if ((ccc > nfc->last_ccc || nfc->idx == 1)
                && !nfc->defective
                && nfc_combines(nfc->buf[0], cp) != UCS4_NOCHAR) {
            // Non-blocked and forms a primary composite. Don't need to store the characters
            // until we recover: any starter will cause a reset (since it is blocked from the
            // current starter by this character with non-zero CCC).
            goto denorm;
        }

        // Good for now. Store for further analysis.
        goto store;

    default:
        break;
    }

    OOPS_UNREACHABLE;

store:
    if (nfc->idx == nfc->sz) {
        nfc_realloc(nfc);
    }
    nfc->buf[nfc->idx++] = cp;
    nfc->last_ccc = new_last_ccc;
    return rv;

reset:
    // Previous characters are normalized and current character is a new starter.
    OOPS_ASSERT(ccc == 0);
    nfc->suppress = false;
    nfc->defective = false;
    nfc->buf[0] = cp; // Always enough for 1 character
    nfc->idx = 1;
    nfc->last_ccc = new_last_ccc;
    return true;

denorm:
    // Suppress further warnings on combining marks until the next starter. Note
    // that non-combining normalization failures (e.g. singletons) are still reported.
    nfc->suppress = true;
    rv = false;
    goto store;
}
