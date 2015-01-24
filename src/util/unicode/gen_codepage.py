#!/usr/bin/python

import re

# Encoding names as defined by IANA (http://www.iana.org/assignments/character-sets/character-sets.xhtml)
encodings = (
        ( "ISO-8859-1",     "MAPPINGS/ISO8859/8859-1.TXT" ),
        ( "ISO-8859-2",     "MAPPINGS/ISO8859/8859-2.TXT" ),
        ( "ISO-8859-3",     "MAPPINGS/ISO8859/8859-3.TXT" ),
        ( "ISO-8859-4",     "MAPPINGS/ISO8859/8859-4.TXT" ),
        ( "ISO-8859-5",     "MAPPINGS/ISO8859/8859-5.TXT" ),
        ( "ISO-8859-6",     "MAPPINGS/ISO8859/8859-6.TXT" ),
        ( "ISO-8859-7",     "MAPPINGS/ISO8859/8859-7.TXT" ),
        ( "ISO-8859-8",     "MAPPINGS/ISO8859/8859-8.TXT" ),
        ( "ISO-8859-9",     "MAPPINGS/ISO8859/8859-9.TXT" ),
        ( "ISO-8859-10",    "MAPPINGS/ISO8859/8859-10.TXT" ),
        ( "ISO-8859-11",    "MAPPINGS/ISO8859/8859-11.TXT" ),
        ( "ISO-8859-13",    "MAPPINGS/ISO8859/8859-13.TXT" ),
        ( "ISO-8859-14",    "MAPPINGS/ISO8859/8859-14.TXT" ),
        ( "ISO-8859-15",    "MAPPINGS/ISO8859/8859-15.TXT" ),
        ( "ISO-8859-16",    "MAPPINGS/ISO8859/8859-16.TXT" ),
        ( "KOI8-R",         "MAPPINGS/VENDORS/MISC/KOI8-R.TXT" ),
        ( "KOI8-U",         "MAPPINGS/VENDORS/MISC/KOI8-U.TXT" ),
        ( "US-ASCII",       "MAPPINGS/VENDORS/MISC/US-ASCII-QUOTES.TXT" ),
        ( "IBM037",         "MAPPINGS/VENDORS/MICSFT/EBCDIC/CP037.TXT" ),
        ( "IBM500",         "MAPPINGS/VENDORS/MICSFT/EBCDIC/CP500.TXT" ),
        ( "IBM875",         "MAPPINGS/VENDORS/MICSFT/EBCDIC/CP875.TXT" ),
        ( "IBM1026",        "MAPPINGS/VENDORS/MICSFT/EBCDIC/CP1026.TXT" ),
        ( "IBM437",         "MAPPINGS/VENDORS/MICSFT/PC/CP437.TXT" ),
        ( "IBM737",         "MAPPINGS/VENDORS/MICSFT/PC/CP737.TXT" ),
        ( "IBM775",         "MAPPINGS/VENDORS/MICSFT/PC/CP775.TXT" ),
        ( "IBM850",         "MAPPINGS/VENDORS/MICSFT/PC/CP850.TXT" ),
        ( "IBM852",         "MAPPINGS/VENDORS/MICSFT/PC/CP852.TXT" ),
        ( "IBM855",         "MAPPINGS/VENDORS/MICSFT/PC/CP855.TXT" ),
        ( "IBM857",         "MAPPINGS/VENDORS/MICSFT/PC/CP857.TXT" ),
        ( "IBM860",         "MAPPINGS/VENDORS/MICSFT/PC/CP860.TXT" ),
        ( "IBM861",         "MAPPINGS/VENDORS/MICSFT/PC/CP861.TXT" ),
        ( "IBM862",         "MAPPINGS/VENDORS/MICSFT/PC/CP862.TXT" ),
        ( "IBM863",         "MAPPINGS/VENDORS/MICSFT/PC/CP863.TXT" ),
        ( "IBM864",         "MAPPINGS/VENDORS/MICSFT/PC/CP864.TXT" ),
        ( "IBM865",         "MAPPINGS/VENDORS/MICSFT/PC/CP865.TXT" ),
        ( "IBM866",         "MAPPINGS/VENDORS/MICSFT/PC/CP866.TXT" ),
        ( "IBM869",         "MAPPINGS/VENDORS/MICSFT/PC/CP869.TXT" ),
        ( "windows-874",    "MAPPINGS/VENDORS/MICSFT/WINDOWS/CP874.TXT" ),
        ( "windows-1250",   "MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1250.TXT" ),
        ( "windows-1251",   "MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1251.TXT" ),
        ( "windows-1252",   "MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1252.TXT" ),
        ( "windows-1253",   "MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1253.TXT" ),
        ( "windows-1254",   "MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1254.TXT" ),
        ( "windows-1255",   "MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1255.TXT" ),
        ( "windows-1256",   "MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1256.TXT" ),
        ( "windows-1257",   "MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1257.TXT" ),
        ( "windows-1258",   "MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1258.TXT" ),
        )

# Check a few characters to detemine compatibility class. Currently supported
# codepage-type encodings all fall in two classes, UTF-8 compatible (that
# shares characters 0x00..0x7F with ASCII) and EBCDIC
compat_patterns = (
        ( "UTF8", (
            ( 0x09, 0x09 ), # Tab
            ( 0x20, 0x20 ), # Space
            ( 0x3C, 0x3C ), # <
            ( 0x41, 0x41 ), # A
            ( 0x61, 0x61 ), # a
            )
        ),
        ( "EBCDIC", (
            ( 0x05, 0x09 ), # Tab
            ( 0x40, 0x20 ), # Space
            ( 0x4C, 0x3C ), # <
            ( 0xC1, 0x41 ), # A
            ( 0x81, 0x61 ), # a
            )
        ),
        ( "UNKNOWN", (
            )
        )
    )

re_cname = re.compile(r'[^A-Za-z0-9_]')
def gen_cname(name):
    return re_cname.sub('_', name)

re_mapping = re.compile(r'\s*0[Xx](?P<from>[0-9A-Fa-f]+)\s+0[Xx](?P<to>[0-9A-Fa-f]+)(\s+#\s*(?P<desc>.*?))?\s*$')
def gen_1(name, fname):
    '''Generate aa single codepage table from a given file source'''
    # Initialize a mapping table filled with unicode replacement characters
    mt = [ (0xFFFD, "not defined") for i in range(0,256) ]
    f = open(fname)
    for l in f:
        m = re_mapping.match(l)
        if not m:
            continue
        fr = int(m.group('from'), 16)
        to = int(m.group('to'), 16)
        if fr >= 256:
            raise ValueError("Not a single-byte encoding")
        if to >= 0x10FFFF:
            raise ValueError("Invalid unicode code point")
        if m.group('desc'):
            d = m.group('desc')
        else:
            d = "???"
        mt[fr] = (to, d)
    f.close()
    # Determine compatibility class
    for cc, chars in compat_patterns:
        for ec, uc in chars:
            if mt[ec][0] != uc:
                break
        else:
            # All reference characters matched
            compat = cc
            break
    cname = gen_cname(name)
    print("""
// Code page for '%s' code page
static const uint32_t codepage_table_%s[] = {
""" % (name, cname))
    for i in range(0, 256):
        print("\t[0x%02X] = 0x%04X, // %s" % (i, mt[i][0], mt[i][1]))
    print("""
};
static encoding_t encoding_%s = {
    .name = "%s",
    .enctype = ENCODING_T_%s,
    .init = init_codepage,
    .destroy = destroy_codepage,
    .xlate = xlate_codepage,
    .data = codepage_table_%s
};
""" % (cname, name, compat, cname))

if __name__ == '__main__':
    print("""
// DO NOT EDIT! Automatically generated by gen_codepage.py.

#include "util/defs.h"
#include "util/strbuf.h"
#include "util/encoding.h"

static void *
init_codepage(const void *data)
{
    return DECONST(data);
}

static void
destroy_codepage(void *baton)
{
    // no-op
}

static void
xlate_codepage(strbuf_t *buf, void *baton, uint32_t **pout, uint32_t *end_out)
{
    const uint32_t *cp = baton;
    uint32_t *out = *pout;
    uint8_t *ptr, *begin, *end;

    do {
        strbuf_getptr(buf, (void **)&begin, (void **)&end);
        if (begin == end) {
            // No more input available.
            break;
        }
        ptr = begin;
        while (ptr < end && out < end_out) {
            *out++ = cp[*ptr++];
        }
        // Mark the number of bytes we consumed as read
        strbuf_read(buf, NULL, ptr - begin, false);
    } while (out < end_out);
    *pout = out;
}

""")
    for n, f in encodings:
        gen_1(n, f)
    print("""
static void __constructor
codepages_autoinit(void)
{
""")
    for n, f in encodings:
        print("\tencoding_register(&encoding_%s);" % gen_cname(n))
    print("""
}
""")
