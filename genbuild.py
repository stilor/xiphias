#!/usr/bin/python

import ConfigParser
from optparse import OptionParser
import os
import sys

general = {}
outputs = {}
builddirs = {}

class Output(object):
    '''Single output binary of the build process'''
    def __init__(self, cp, section):
        self.outtype, self.name = section.split(':', 1)
	if section in outputs:
	    raise KeyError('Duplicate definition of [%s]' % self.name)
        self.subdir = cp.get(section, 'subdir')
        self.sources = cp.get(section, 'sources').split()
        self.localdep = cp.get(section, 'localdep').split()
	if self.outtype == 'lib':
	    self.outpath = "build/lib/lib%s_%s.so" % (general['prefix'], self.name)
	    self.extraldflags = "-Wl,-soname=lib%s_%s.so" % (general['prefix'], self.name)
	elif self.outtype == 'test':
	    self.outpath = "build/tests/%s" % self.name
	    self.extraldflags = ""
        elif self.outtype == 'app':
            self.outpath = "build/bin/%s" % self.name
	    self.extraldflags = ""
	else:
	    raise ValueError('Unknown output type [%s]' % self.outtype)
	builddirs[os.path.dirname(self.outpath)] = 1
	self.objs = []
	self.deps = []
        for s in self.sources:
            if s[-2:] != '.c':
                raise ValueError('Non C source') # Don't know how to handle
	    src = self.subdir + '/' + s
            obj = 'build/' + src[:-2] + '.o'
            dep = 'build/' + src[:-2] + '.d'
            builddirs[os.path.dirname(obj)] = 1
	    self.objs.append(obj)
	    self.deps.append(dep)
	outputs[section] = self

    def write_makefile(self, f):
	f.write('''
all: build-dirs %(outpath)s

%(outpath)s: %(objs)s %(localdeps)s $(__makefiles) | build-dirs
\t$(CC) -o $@ %(objs)s $(LDFLAGS_%(outtype)s) %(extraldflags)s %(locallibs)s

%(objs)s: build/%%.o: %%.c $(__makefiles) | build-dirs
\t$(CC) $(CFLAGS_%(outtype)s) -c -MMD -o $@ $<

-include %(deps)s
'''		% {
		'objs' : ' '.join(self.objs),
		'deps' : ' '.join(self.deps),
		'outpath' : self.outpath,
		'extraldflags' : self.extraldflags,
		'outtype' : self.outtype,
                'localdeps' : ' '.join([outputs['lib:' + x].outpath for x in self.localdep]),
		'locallibs' : ' '.join(["-l%s_%s" % (general['prefix'], x) for x in self.localdep]),
		})
        # Additional rules
        if self.outtype == 'test':
            f.write('''
check: check-%(name)s

check-%(name)s: %(outpath)s
\t%(outpath)s
'''             % {
                'name' : self.name,
		'outpath' : self.outpath,
                })

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-o', '--output', dest='output', help='Select output file', default='mk')
    opts, args = parser.parse_args()
    if len(args) != 1:
        parser.error('Input file required')
    # TBD: command line for specifying config options such as installation prefix
    cp = ConfigParser.ConfigParser({
	# Optional keys in each output section have default values provided
        'localdep' : ''
        })
    cp.read(args[0])
    for s in cp.sections():
        if s == "general":
            general.update(cp.items(s))
        else:
            Output(cp, s)
    f = open(opts.output, "w")
    f.write('''
# DO NOT EDIT! Automatically generated by %s
''' % sys.argv[0])
    for o in outputs.values():
	o.write_makefile(f)
    # Write common part
    f.write('''
%(builddirs)s:
\tmkdir -p $@

.PHONY: build-dirs
build-dirs: %(builddirs)s
''' % {
	'builddirs' : ' '.join(builddirs.keys())
	})
    f.close()
