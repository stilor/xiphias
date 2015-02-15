#!/usr/bin/python

import os
import sys

class CodePoint(object):
    def __init__(self, i):
        self.name = "<unassigned U+%06X>" % i
        self.cat = "Cn" # Control, unassigned/not-a-character
        self.ccc = 0
        self.decomp = None

    def set_name(self, name):
        self.name = name

    def set_category(self, cat):
        self.cat = cat

    def set_ccc(self, ccc):
        self.ccc = ccc

    def set_decomp(self, decomp):
        self.decomp = decomp

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
    f = open(fname)
    for l in f:
        idx = l.find("#")
        if idx != -1:
            l = l[:idx]
        l = l.strip()
        if l == "":
            continue
        yield [x.strip() for x in l.split(';')]
    f.close()

def read_unicode_data(cps, fname):
    print("Reading in UnicodeData file...")
    ranges = {}
    for code, name, gencat, ccc, bidicls, decomp, numval0, numval1, numval2, bidimirror, unicode1name, \
            isocomment, uc, lc, tc in read_data(fname):
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
        print("Filling range '%s' [%06X..%06X] with common settings" % (k, r.first, r.last))
        for code in range(r.first, r.last + 1):
            # See 4.8 Name in Unicode spec. Hangul not handled here - will process it algorithmically later
            if k == "CJK Ideograph":
                cps[code].set_name("CJK UNIFIED IDEOGRAPH-%4X" % code)
            elif k.startswith("CJK Ideograph Extension"):
                cps[code].set_name("CJK COMPATIBILITY IDEOGRAPH-%4X" % code)
            cps[code].set_category(r.cat)
            cps[code].set_ccc(r.ccc)

def set_hangul_characters(cps, fname):
    print("Setting Hangul character properties")
    jamo_name = {}
    for code, name in read_data(fname):
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
            cps[code].set_name("HANGUL SYLLABLE %s%s" % (jamo_name[LPart], jamo_name[VPart]))
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
            cps[code].set_name("HANGUL SYLLABLE %s%s%s" % (jamo_name[LPart], jamo_name[VPart], jamo_name[TPart]))

if __name__ == '__main__':
    print("Initializing Unicode defaults...")
    cps = [CodePoint(i) for i in range(0, 0x110000)]
    read_unicode_data(cps, os.path.join(sys.argv[1], "UnicodeData.txt"))
    set_hangul_characters(cps, os.path.join(sys.argv[1], "Jamo.txt"))
    # TBD parse CompositionExclusions.txt before determining "composes with" arrays
    # TBD remove the debug print of the character DB
    for i, c in enumerate(cps):
        if c.cat == "Cs":
            continue
        if c.decomp is None:
            print("%06X :: %s [%s] [%3u]" % (i, c.name, c.cat, c.ccc))
        else:
            print("%06X :: %s [%s] [%3u] -> <%s>" % (i, c.name, c.cat, c.ccc, ' '.join(["%04X" % v for v in c.decomp])))
