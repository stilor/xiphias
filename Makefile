# vi: set sw=4 ts=4 :

CC	= gcc
CFLAGS_common			:= -Werror -Wall -Wstrict-prototypes -Wmissing-prototypes \
						   -Wstrict-overflow=4 -Wignored-qualifiers -Wunused-but-set-parameter \
						   -Wmaybe-uninitialized -Wpointer-arith -Wtype-limits -Wbad-function-cast \
						   -Wcast-qual -Wcast-align -Wwrite-strings -Wclobbered \
						   -Wsign-compare -Wlogical-op -Waggregate-return \
						   -Wmissing-field-initializers -Wnested-externs \
						   -g -O1 -fno-common -iquote src/include

CFLAGS_lib				:= $(CFLAGS_common) -fPIC
CFLAGS_test				:= $(CFLAGS_common)

LDFLAGS_common			:= -L build/lib
LDFLAGS_lib				:= $(LDFLAGS_common) -fPIC -shared
LDFLAGS_test			:= $(LDFLAGS_common) -Wl,-rpath=build/lib

all:

clean:
	rm -rf build

check:

docs:
	mkdir -p build/doc
	doxygen src/Doxyfile

build/outputs.mk: outputs.conf genbuild.py
	mkdir -p build
	python genbuild.py -o $@ $<

__makefiles	:= Makefile build/outputs.mk
-include build/outputs.mk
