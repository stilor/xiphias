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
    size_t decomp;          ///< Number of pre-decomposed characters

    uint8_t last_ccc;       ///< Last character's canonical combining class
    bool suppress;          ///< Suppress denormalization errors until next starter
    bool defective;         ///< Defective combining sequence at the start

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
    Replace all characters currently in the buffer with their full canonical decompositions.

    @param nfc Handle
    @return Nothing
*/
static inline void
nfc_decompose_buf(nfc_t *nfc)
{
    size_t i, fcd_len;
    ucs4_t cp;

    for (i = nfc->decomp; i < nfc->idx; i++) {
        cp = nfc->buf[i];
        if ((fcd_len = ucs4_get_fcd_len(cp)) == 0) {
            continue; // No decomposition for this character
        }
        // Ensure there's enough space in buffer. Shouldn't require more than 1 realloc.
        while (nfc->idx + fcd_len - 1 > nfc->sz) {
            nfc_realloc(nfc);
        }
        // Make space for expansion and replace current character with FCD
        memmove(&nfc->buf[i + fcd_len], &nfc->buf[i + 1], (nfc->idx - i - 1) * sizeof(ucs4_t));
        memcpy(&nfc->buf[i], ucs4_get_fcd(cp), fcd_len * sizeof(ucs4_t));
        // Adjust current length and skip over added characters
        nfc->idx += fcd_len - 1;
        i += fcd_len - 1;
    }
    nfc->decomp = nfc->idx;
}

/**
    Check if two characters can form a primary composite.

    @param cp1 First character
    @param cp2 Second character
    @return true if the characters can combine
*/
static inline bool
nfc_combines(ucs4_t cp1, ucs4_t cp2)
{
    size_t i, comp_cnt;
    const ucs4_t *cw;

    if ((comp_cnt = ucs4_get_cw_len(cp2)) == 0) {
        return false; // does not combine with anything
    }
    cw = ucs4_get_cw(cp2); // UCS4 pairs
    for (i = 0; i < comp_cnt; i++, cw += 2) {
        if (cw[0] == cp1) {
            return true; // combines to cw[1]
        }
    }
    return false;
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
    nfc->decomp = 0;
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
    uint8_t ccc;

    if ((ccc = ucs4_get_ccc(cp)) != 0 && ccc < nfc->last_ccc) {
        // Violates combining class constraint
        goto denorm;
    }
    nfc->last_ccc = ccc;

    switch (ucs4_get_nfc_qc(cp)) {
    case UCS4_NFC_QC_Y:
        // This can happen with either starter character characters, or non-starters
        // that do not compose with anything (e.g. U+0305, "COMBINING OVERLINE").
        // For non-starters, continue accumulating the input (we may see violations
        // of combining class ordering. 
        if (ccc) {
            return true;
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
        // the very first character, it cannot change anything - just store it and
        // mark as defective combining sequence. Being defective does not cause it
        // to be considered denormalized - just makes it easier to check the assumption
        // that character #0 is a starter. Note that characters with non-starter
        // decomposition are considered 'full composition exclusions' and are thus
        // assigned a 'quick check -- no' property; they are not handled in this case.
        if (!nfc->idx) {
            nfc->buf[0] = cp; // Always enough for 1 character
            nfc->idx = 1;
            nfc->defective = true;
            return true;
        }

        // Need to decompose what we have so far and analyze the sequence for non-blocked pairs.
        nfc_decompose_buf(nfc);

        // Current Unicode version (7.0) does not have any 'quick check -- maybe' characters
        // that decompose into multiple codepoints, thus the assertion. It may change in
        // the future - the handling of such characters would have to be rethought
        // at that time: current algorithm assumes that the sequence of combining marks
        // recorded so far is ordered and the only starter is the 0th character.
        OOPS_ASSERT(ucs4_get_fcd_len(cp) == 0);

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
            // Note that we cannot check last_ccc here - as it may reflect the combining
            // class of the last character before the full canonical decomposition. If
            // the last character was a starter, need to see if this character combines
            // with it (there are primary composites of two starters). If we're already
            // saw a denormalization, consider this character a base for the new character.
            if (nfc->idx != 1
                    || nfc->defective
                    || nfc->suppress
                    || !nfc_combines(nfc->buf[0], cp)) {
                // Starter and it didn't combine with previous character. Becomes new base
                // for the sequence.
                goto reset;
            }
            // Two starters combining. We may get some other non-starters following
            // this would-be primary composite; disregard until we get a proper starter.
            goto denorm;
        }

        if (nfc->suppress) {
            // Still part of the previous denormalized sequence. Signaled error already;
            // no need to raise it again.
            return true;
        }

        // See if the new character is non-blocked from the starter
        if (ccc > ucs4_get_ccc(nfc->buf[nfc->idx - 1])
                && !nfc->defective
                && nfc_combines(nfc->buf[0], cp)) {
            // Non-blocked and forms a primary composite
            goto denorm;
        }

        // Good for now. Store for further analysis.
        if (nfc->idx == nfc->sz) {
            nfc_realloc(nfc);
        }
        nfc->buf[nfc->idx++] = cp;
        return true;

    default:
        break;
    }

    OOPS_UNREACHABLE;

reset:
    // Previous characters are normalized and current character is a new starter.
    // Current Unicode version (7.0) does not have any characters with non-zero CCC
    // that have 'quick check -- yes' property.
    OOPS_ASSERT(nfc->last_ccc == 0);
    nfc->suppress = false;
    nfc->defective = false;
    nfc->buf[0] = cp; // Always enough for 1 character
    nfc->decomp = 0;
    nfc->idx = 1;
    return true;

denorm:
    // No point in storing the character - we already know this sequence is broken.
    // Suppress further warnings on combining marks until the next starter. Note
    // that non-combining normalization failures (e.g. singletons) are still reported.
    nfc->suppress = true;
    return false;
}
