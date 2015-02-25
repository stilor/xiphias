#!/usr/bin/python

import os
import sys

ucd_db_path = ""

class CodePoint(object):
    def __init__(self, i):
        self.name = "<unassigned U+%06X>" % i
        self.code = i
        self.cat = "Cn" # Control, unassigned/not-a-character
        self.ccc = 0
        self.decomp = None
        self.full_decomp = None
        self.composes_with = None
        self.nfc_qc = "Y"
        self.decomp_idx = 0
        self.decomp_len = 0
        self.comp_idx = 0
        self.comp_len = 0

    def set_name(self, name):
        self.name = name

    def set_category(self, cat):
        self.cat = cat

    def set_ccc(self, ccc):
        self.ccc = ccc

    def set_decomp(self, decomp):
        self.decomp = decomp

    def set_full_decomp(self, decomp):
        self.full_decomp = decomp

    def set_composes_with(self, preceding, combined):
        if self.composes_with is None:
            self.composes_with = {}
        elif preceding in self.composes_with:
            raise ValueError("<%04X %04X> -> %04X but also %04X" % \
                    (preceding, self.code, self.composes_with[preceding], combined))
        self.composes_with[preceding] = combined

    def set_nfc_qc(self, val):
        self.nfc_qc = val

    def set_decomp_idx(self, idx, cnt):
        self.decomp_idx = idx
        self.decomp_len = cnt

    def set_comp_idx(self, idx, cnt):
        self.comp_idx = idx
        self.comp_len = cnt

class CodeRange(object):
    def __init__(self, first, cat, ccc):
        self.first = first
        self.last = None # Unknown yet
        self.cat = cat
        self.ccc = ccc

    def set_last(self, last, cat, ccc):
        if self.cat != cat or self.ccc != ccc:
            raise ValueError("Properties for range do not match: category %s/%s, CCC %u/%u" % \
                    (self.cat, cat, self.ccc, ccc))
        self.last = last

def read_data(fname):
    f = open(os.path.join(ucd_db_path, "%s.txt" % fname))
    for l in f:
        idx = l.find("#")
        if idx != -1:
            l = l[:idx]
        l = l.strip()
        if l == "":
            continue
        yield [x.strip() for x in l.split(';')]
    f.close()

def read_unicode_data(cps):
    #print("Reading in UnicodeData file...")
    ranges = {}
    for code, name, gencat, ccc, bidicls, decomp, \
            numval0, numval1, numval2, bidimirror, unicode1name, \
            isocomment, uc, lc, tc in read_data("UnicodeData"):
        code = int(code, 16)
        ccc = int(ccc, 10)
        if name[0] == '<' and name[-8:] == ', First>':
            ranges[name[1:-8]] = CodeRange(code, gencat, ccc)
        elif name[0] == '<' and name[-7:] == ', Last>':
            ranges[name[1:-7]].set_last(code, gencat, ccc)
        else:
            cps[code].set_name(name)
            cps[code].set_category(gencat)
            cps[code].set_ccc(ccc)
            # Ignore compatibility decompositions - we're only interested in Form C
            if decomp != "" and decomp[0] != '<':
                cps[code].set_decomp([int(x, 16) for x in decomp.split()])
    for k, r in ranges.items():
        #print("Filling range '%s' [%06X..%06X] with common settings..." % (k, r.first, r.last))
        for code in range(r.first, r.last + 1):
            # See 4.8 Name in Unicode spec. Hangul not handled here - will process
            # it algorithmically later
            if k == "CJK Ideograph":
                cps[code].set_name("CJK UNIFIED IDEOGRAPH-%4X" % code)
            elif k.startswith("CJK Ideograph Extension"):
                cps[code].set_name("CJK COMPATIBILITY IDEOGRAPH-%4X" % code)
            cps[code].set_category(r.cat)
            cps[code].set_ccc(r.ccc)

def generate_hangul_characters(cps):
    #print("Setting Hangul character properties...")
    jamo_name = {}
    for code, name in read_data("Jamo"):
        code = int(code, 16)
        jamo_name[code] = name
    # See 3.12, Conjoining Jamo Behavior
    SBase = 0xAC00
    LBase = 0x1100
    VBase = 0x1161
    TBase = 0x11A7
    LCount = 19
    VCount = 21
    TCount = 28
    NCount = VCount * TCount
    SCount = LCount * NCount
    for code in range(SBase, SBase + SCount):
        SIndex = code - SBase
        TIndex = SIndex % TCount
        if TIndex == 0:
            # LV-type syllable, decomposes to L-part and V-part
            LIndex = SIndex / NCount
            VIndex = (SIndex % NCount) / TCount
            LPart = LBase + LIndex
            VPart = VBase + VIndex
            cps[code].set_decomp([LPart, VPart])
            cps[code].set_name("HANGUL SYLLABLE %s%s" % \
                    (jamo_name[LPart], jamo_name[VPart]))
        else:
            # LVT-type syllable, decomposes to LV-part and T-part.
            # But need to get all 3 parts to generate the name.
            LVIndex = (SIndex / TCount) * TCount
            LIndex = SIndex / NCount
            VIndex = (SIndex % NCount) / TCount
            LVPart = SBase + LVIndex
            LPart = LBase + LIndex
            VPart = VBase + VIndex
            TPart = TBase + TIndex
            cps[code].set_decomp([LVPart, TPart])
            cps[code].set_name("HANGUL SYLLABLE %s%s%s" % \
                    (jamo_name[LPart], jamo_name[VPart], jamo_name[TPart]))

def find_compose_with(cps):
    #print("Determining composition exclusions...")
    excl = {}
    # Explicitly listed exclusions
    for code, in read_data("CompositionExclusions"):
        code = int(code, 16)
        excl[code] = True
    for c in cps:
        if c.decomp is None:
            continue
        # Singletons and non-starter composition exclusions. We are not so much
        # interested in singletons (since we're going to determine "composes with
        # previous" property), but check them for completeness
        if len(c.decomp) == 1:
            excl[c.code] = True
        elif c.ccc != 0 or cps[c.decomp[0]].ccc != 0:
            excl[c.code] = True
    #print("Determine preceding characters that can compose with each character...")
    for c in cps:
        if c.decomp is None:
            continue
        if c.code in excl:
            continue
        if len(c.decomp) != 2:
            raise ValueError("Canonical decomposition for %04X is %u characters (%s)" % \
                    (c.code, len(c.decomp), repr(c.decomp)))
        cps[c.decomp[1]].set_composes_with(c.decomp[0], c.code)
    # Now get the NFC_QC ("quick check for NFC") property
    #print("Reading NFC_QC properties...")
    for t in read_data("DerivedNormalizationProps"):
        if len(t) == 3 and t[1] == "NFC_QC":
            try:
                code = int(t[0], 16)
                cps[code].set_nfc_qc(t[2])
            except ValueError:
                start, end = [int(x, 16) for x in t[0].split('..')]
                for code in range(start, end + 1):
                    cps[code].set_nfc_qc(t[2])
    # And, determine full canonical decompositions
    #print("Determining full canonical decompositions...")
    for c in cps:
        if c.decomp is None:
            continue
        fulldecomp = list(c.decomp) # Copy to avoid modification of the original
        while True:
            c0 = fulldecomp[0]
            nextdecomp = cps[c0].decomp
            if nextdecomp is None:
                break # Ok, final
            # Substitute [0] with its decomposition
            fulldecomp[0:1] = cps[c0].decomp
        c.set_full_decomp(fulldecomp)

def set_decompositions(cps, decomps):
    for c in cps:
        if c.full_decomp is None:
            continue
        c.set_decomp_idx(len(decomps), len(c.full_decomp))
        decomps.extend(c.full_decomp)

def set_compositions(cps, comps):
    for c in cps:
        if c.composes_with is None:
            continue
        keys = sorted(c.composes_with.keys())
        c.set_comp_idx(len(comps) / 2, len(keys)) # Index of a pair of 32-bit values
        for k in keys:
            comps.append(k)
            comps.append(c.composes_with[k])

def print_array(f, name, data):
    f.write("const ucs4_t %s[%u] = {\n" % (name, len(data)))
    for i, d in enumerate(data):
        if i % 8 == 0:
            f.write("    /* %04X */"% i)
        f.write(" 0x%08x," % d)
        if i % 8 == 7:
            f.write("\n")
    f.write("\n};\n\n")

if __name__ == '__main__':
    ucd_db_path = sys.argv[1]
    #print("Initializing Unicode defaults...")
    cps = [CodePoint(i) for i in range(0, 0x110000)]
    read_unicode_data(cps)
    generate_hangul_characters(cps)
    find_compose_with(cps)
    decomps = []
    set_decompositions(cps, decomps)
    comps = []
    set_compositions(cps, comps)
    # Now we can write the output
    #print("Saving the generated data...")
    f = open(sys.argv[2], "w")
    f.write("""
// DO NOT EDIT! Auto-generated by %(scriptname)s

#include "unicode.h"

#define CODEPOINT(pcat, pccc, pdidx, pdcnt, pcidx, pccnt, pnfc) { \\
        .gencat = pcat, \\
        .ccc = pccc, \\
        .decomp_idx = pdidx, \\
        .decomp_cnt = pdcnt, \\
        .comp_idx = pcidx, \\
        .comp_cnt = pccnt, \\
        .nfc_qc = pnfc, \\
        }

""" % { 'scriptname' : sys.argv[0] })
    print_array(f, "ucs4_full_decomp", decomps)
    print_array(f, "ucs4_composes_with", comps)
    f.write("const ucs4data_t ucs4_characters[] = {\n")
    for c in cps:
        f.write("    CODEPOINT(UCS4_GC_%s, %u, 0x%x, %u, 0x%x, %u, UCS4_NFC_QC_%s)," % \
                (c.cat, c.ccc, c.decomp_idx, c.decomp_len, c.comp_idx, c.comp_len, c.nfc_qc))
	f.write(" // U+%06X: %s\n" % (c.code, c.name))
    f.write("};\n")
    f.close()
    #print("Done!")
