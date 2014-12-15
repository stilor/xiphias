#!/usr/bin/python

import re
import sys

re_start = re.compile(r'^\[(?P<num>[^]]*)\]\s+(?P<name>\S+)\s*::=\s*(?P<content>.*?)\s*$')
re_cont = re.compile(r'^\s+(?P<content>\S.*?)\s*$')
re_ws = re.compile(r'\s+')
def normalize_file(f):
    parsed = []
    for l in f:
        m = re_start.match(l)
        if m:
            parsed.append((m.group('num'), m.group('name'), re_ws.sub(' ', m.group('content'))))
            continue
        m = re_cont.match(l)
        if m:
            parsed.append((None, None, re_ws.sub(' ', m.group('content'))))
            continue
        raise ValueError("Line '%s' did not match" % l)
    maxnumlen = 0
    maxnamelen = 0
    for num, name, content in parsed:
        if num is not None and len(num) > maxnumlen:
            maxnumlen = len(num)
        if name is not None and len(name) > maxnamelen:
            maxnamelen = len(name)
    joined = []
    maxnumlen += 2 # Account for brackets
    for num, name, content in parsed:
        # TBD split long lines
        if num is not None and name is not None:
            joined.append("%-*s %*s ::= %s" % (maxnumlen, "[" + num + "]", maxnamelen, name, content))
        elif num is None and name is None:
            joined[-1] += " " + content
        else:
            raise ValueError("???")
    for j in joined:
        sys.stdout.write("%s\n" % j)



if __name__ == '__main__':
    normalize_file(sys.stdin)
