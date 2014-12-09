# vi: set sw=4 ts=4 :

TARGETS = libxiphias testutil

SUBDIRS-libxiphias		:= util
FILES-util				:= xutil.c
CFLAGS-libxiphias		:= -fPIC
LDFLAGS-libxiphias		:= -shared -fPIC -Wl,-soname=libxiphias.so
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
						   -Wcast-qual -Wcast-align -Wwrite-strings -Wclobbered -Wconversion \
						   -Wsign-compare -Wlogical-op -Waggregate-return -Wmissing-field-initializers \
						   -Wnested-externs -O2 -iquote include
LDFLAGS					:= -L. -Wl,-rpath=.

#########################################
# Common rules

.DEFAULT: all

define targetrules
srcs-$t         := $$(foreach d,$$(SUBDIRS-$t),$$(patsubst %,$$d/%,$$(FILES-$$d)))
objs-$t         := $$(patsubst %.c,%.o,$$(srcs-$t))
deps-$t         := $$(patsubst %.c,%.d,$$(srcs-$t))

$$(objs-$t): %.o: %.c $$(MAKEFILE_LIST)
	$$(CC) -c -MMD $$(CFLAGS) $$(CFLAGS-$t) -o $$@ $$<

$$(PROGNAME-$t): $$(objs-$t) $$(foreach d,$$(DEPS-$t),$$(PROGNAME-$$d)) $$(MAKEFILE_LIST)
	$$(CC) -o $$@ $$(objs-$t) $$(LDFLAGS) $$(LDFLAGS-$t)

endef
$(foreach t,$(TARGETS),$(eval $(targetrules)))

__all_objs		:= $(foreach t,$(TARGETS),$(objs-$t))
__all_deps		:= $(foreach t,$(TARGETS),$(deps-$t))

all: $(foreach t,$(TARGETS),$(PROGNAME-$t))
	@:

clean:
	rm -f $(__all_objs) $(__all_deps)

-include $(__all_deps)
