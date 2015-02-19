# vi: set sw=4 ts=4 :

CC	= gcc
CFLAGS_common			:= -Werror -Wall -Wstrict-prototypes -Wmissing-prototypes \
						   -Wstrict-overflow=4 -Wignored-qualifiers -Wunused-but-set-parameter \
						   -Wmaybe-uninitialized -Wpointer-arith -Wtype-limits -Wbad-function-cast \
						   -Wcast-qual -Wcast-align -Wwrite-strings -Wclobbered \
						   -Wsign-compare -Wlogical-op -Waggregate-return \
						   -Wmissing-field-initializers -Wnested-externs \
						   -g -O0 -fno-common -iquote src

CFLAGS_lib				:= $(CFLAGS_common) -fPIC
CFLAGS_test				:= $(CFLAGS_common)

LDFLAGS_common			:= -L build/lib
LDFLAGS_lib				:= $(LDFLAGS_common) -fPIC -shared
LDFLAGS_test			:= $(LDFLAGS_common) -Wl,-rpath=build/lib

ifeq ($(COVERAGE),yes)
CFLAGS_common			+= --coverage
LDFLAGS_common			+= --coverage
endif

all:

GENERATED				:= src/util/encoding-codepages.c \
						   src/util/ucs4data.c

clean:
	rm -rf build
	rm -f $(GENERATED)

check:

docs:
	mkdir -p build/doc
	doxygen src/Doxyfile

build/outputs.mk: outputs.conf genbuild.py
	mkdir -p build
	python genbuild.py -o $@ $<

# Generated files.
# TBD: generate in build/?
# TBD: dependency on the input, and generate one file per codepage? Then how to get this list into output.conf?
src/util/encoding-codepages.c: src/util/unicode/gen_codepage.py
	python $< $@

src/util/ucs4data.c: src/util/unicode/gen_unicode_data.py
	python $< src/util/unicode/UCD $@

__makefiles	:= Makefile build/outputs.mk
-include build/outputs.mk
