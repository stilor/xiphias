# vi: set sw=4 ts=4 :

TARGETS = libxiphias testutil

SUBDIRS-libxiphias		:= util xml
FILES-util				:= xutil.c eh.c strbuf.c encoding.c
FILES-xml				:= reader.c
CFLAGS-libxiphias		:= -fPIC $(shell curl-config --cflags)
LDFLAGS-libxiphias		:= -shared -fPIC -Wl,-soname=libxiphias.so $(shell curl-config --libs)
PROGNAME-libxiphias		:= libxiphias.so
DEPS-libxiphias			:=

SUBDIRS-testutil		:= testutil
FILES-testutil			:= testutil.c
CFLAGS-testutil			:=
LDFLAGS-testutil		:= -lxiphias
PROGNAME-testutil		:= dotest
DEPS-testutil			:= libxiphias

CC						:= gcc
CFLAGS					:= -Werror -Wall -Wstrict-prototypes -Wmissing-prototypes \
						   -Wstrict-overflow=4 -Wignored-qualifiers -Wunused-but-set-parameter \
						   -Wmaybe-uninitialized -Wpointer-arith -Wtype-limits -Wbad-function-cast \
						   -Wcast-qual -Wcast-align -Wwrite-strings -Wclobbered \
						   -Wsign-compare -Wlogical-op -Waggregate-return -Wmissing-field-initializers \
						   -Wnested-externs -g -O2 -fno-common -iquote include -D_GNU_SOURCE
LDFLAGS					:= -L. -Wl,-rpath=.

#########################################
# Common rules

.DEFAULT_GOAL	:= all

__makefiles		:= $(filter-out %.d,$(MAKEFILE_LIST))

define targetrules
srcs-$t         := $$(foreach d,$$(SUBDIRS-$t),$$(patsubst %,$$d/%,$$(FILES-$$d)))
objs-$t         := $$(patsubst %.c,%.o,$$(srcs-$t))
deps-$t         := $$(patsubst %.c,%.d,$$(srcs-$t))

$$(objs-$t): %.o: %.c $$(__makefiles)
	$$(CC) -c -MMD $$(CFLAGS) $$(CFLAGS-$t) -o $$@ $$<

$$(PROGNAME-$t): $$(objs-$t) $$(foreach d,$$(DEPS-$t),$$(PROGNAME-$$d)) $$(__makefiles)
	$$(CC) -o $$@ $$(objs-$t) $$(LDFLAGS) $$(LDFLAGS-$t)

endef
$(foreach t,$(TARGETS),$(eval $(targetrules)))

__all_objs		:= $(foreach t,$(TARGETS),$(objs-$t))
__all_deps		:= $(foreach t,$(TARGETS),$(deps-$t))
__all_progs		:= $(foreach t,$(TARGETS),$(PROGNAME-$t))

all: $(__all_progs)
	@:

clean:
	rm -f $(__all_objs) $(__all_deps) $(__all_progs)

-include $(__all_deps)
