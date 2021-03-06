# vi: set sw=4 ts=4 :

# lcov: specify everything on the command line, in 1.10 lcov_branch_coverage
# option is recognized via --rc but not from the configuration file.
COVERAGE_TOOL			:= lcov
COVERAGE_IGNORED		:= "/usr/include/*" "src/util/oops.h" "src/test/*" "tests/*"
COVERAGE_CMD-gcovr		:= gcovr -r . -e "^tests/" --html --html-details \
						   -o build/coverage/index.html
COVERAGE_CMD-lcov		:= lcov --output-file build/lcov.tmp.info \
						   		--rc lcov_branch_coverage=1 \
								--directory build --capture && \
						   lcov --output-file build/lcov.info \
						   		--rc lcov_branch_coverage=1 \
								--remove build/lcov.tmp.info $(COVERAGE_IGNORED) && \
						   genhtml --output-directory build/coverage --show-details \
						   		--frames --title "Xiphias coverage" --legend \
						   		--rc lcov_branch_coverage=1 --branch-coverage \
						   		--function-coverage build/lcov.info

CC	= gcc
# TBD -Wextra?
WARNS					:= -Werror -Wall -Wstrict-prototypes -Wmissing-prototypes \
						   -Wstrict-overflow=4 -Wignored-qualifiers -Wunused-but-set-parameter \
						   -Wmaybe-uninitialized -Wpointer-arith -Wtype-limits -Wbad-function-cast \
						   -Wcast-qual -Wcast-align -Wwrite-strings -Wclobbered \
						   -Wsign-compare -Wlogical-op -Waggregate-return \
						   -Wmissing-field-initializers -Wnested-externs -Wfatal-errors
CFLAGS_common			:= -g -fno-common -iquote src
CFLAGS_normal			:= -O2
CFLAGS_coverage			:= -O0 --coverage -DOOPS_COVERAGE

CFLAGS_app				:= $(CFLAGS_common)
CFLAGS_lib				:= $(CFLAGS_common) -fPIC
CFLAGS_test				:= $(CFLAGS_common)

LDFLAGS_common			:= -L build/lib $(LDFLAGS_extra)
LDFLAGS_coverage		:= --coverage
LDFLAGS_app				:= $(LDFLAGS_common) -Wl,-rpath=build/lib
LDFLAGS_lib				:= $(LDFLAGS_common) -fPIC -shared
LDFLAGS_test			:= $(LDFLAGS_common) -Wl,-rpath=build/lib

EXT_normal				:=
EXT_coverage			:= .cov

ifeq ($(VALGRIND),yes)
runtest					= valgrind --leak-check=full $1 $2 2> $1.valgrind-log
else
runtest					= $1 $2
endif

all: all-normal

coverage: check-coverage
	mkdir -p build/coverage
	$(COVERAGE_CMD-$(COVERAGE_TOOL))
	find build -name "*.gcda" | xargs rm -f

GENERATED				:= src/unicode/encoding-codepages.c \
						   src/unicode/ucs4data.c

clean:
	rm -rf build
	rm -f $(GENERATED)

check: check-normal

docs: Doxyfile.tmpl
	rm -rf build/doc
	mkdir -p build/doc
	sed 's,@GENERATED@,$(GENERATED),g' $< > build/Doxyfile
	doxygen build/Doxyfile

build/outputs.mk: outputs.conf scripts/gen_outputs.py
	mkdir -p build
	python scripts/gen_outputs.py -o $@ $<

# Generated files.
# TBD: generate in build/?
# TBD: dependency on the input, and generate one file per codepage? Then how to get this list into output.conf?
src/unicode/encoding-codepages.c: scripts/gen_codepage.py
	python $< src/unicode/data $@

src/unicode/ucs4data.c: scripts/gen_unicode_data.py
	python $< src/unicode/data $@

__makefiles	:= Makefile build/outputs.mk
-include build/outputs.mk
