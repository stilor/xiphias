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
OPTIMIZE				:= -O2
CFLAGS_common			:= -Werror -Wall -Wstrict-prototypes -Wmissing-prototypes \
						   -Wstrict-overflow=4 -Wignored-qualifiers -Wunused-but-set-parameter \
						   -Wmaybe-uninitialized -Wpointer-arith -Wtype-limits -Wbad-function-cast \
						   -Wcast-qual -Wcast-align -Wwrite-strings -Wclobbered \
						   -Wsign-compare -Wlogical-op -Waggregate-return \
						   -Wmissing-field-initializers -Wnested-externs \
						   -g $(OPTIMIZE) -fno-common -iquote src $(CFLAGS_extra)

CFLAGS_app				:= $(CFLAGS_common)
CFLAGS_lib				:= $(CFLAGS_common) -fPIC
CFLAGS_test				:= $(CFLAGS_common)

LDFLAGS_common			:= -L build/lib $(LDFLAGS_extra)
LDFLAGS_app				:= $(LDFLAGS_common) -Wl,-rpath=build/lib
LDFLAGS_lib				:= $(LDFLAGS_common) -fPIC -shared
LDFLAGS_test			:= $(LDFLAGS_common) -Wl,-rpath=build/lib

all:

coverage:
	find build -name "*.gcda" | xargs rm -f
	@$(MAKE) all check CFLAGS_extra='--coverage -DOOPS_COVERAGE' LDFLAGS_extra='--coverage' OPTIMIZE='-O0'
	mkdir -p build/coverage
	$(COVERAGE_CMD-$(COVERAGE_TOOL))

GENERATED				:= src/util/encoding-codepages.c \
						   src/util/ucs4data.c

clean:
	rm -rf build
	rm -f $(GENERATED)

check:

docs:
	rm -rf build/doc
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
