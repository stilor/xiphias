/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Parsing of command-like arguments.
*/
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "util/defs.h"
#include "util/xutil.h"

#include "opt.h"

/// State of the option parser
struct opt_parse_state_s {
    char **argv;            ///< Current option pointer
    const opt_t *opts;      ///< Array of all options
    size_t nopts;           ///< Number of options
    size_t nargs;           ///< Number of arguments
    const char *progname;   ///< Program name
    const opt_t *usage;     ///< Option for usage
    const opt_t *current;   ///< Currently handled option
    const char *msg;        ///< Error message for usage, if any
    size_t *counters;       ///< How many times this option was seen
};

/// Check if an option is an argument
#define is_arg(o) ((o)->optlong == NULL)

/// Check if an option is a terminator
#define is_term(o) ((o)->opttype == OPT_TYPE_MAX)

/**
    Handler for an argument

    @param st Option parsing state
    @return Nothing
*/
typedef void (*opt_handler_t)(struct opt_parse_state_s *st);


/**
    Display a usage message and exit.

    @param st Option parsing state
    @return Nothing
*/
static void
handler_usage(struct opt_parse_state_s *st)
{
    struct opt_arg_USAGE_s *data = st->current->optarg;
    const opt_t *opt;
    const char *p, *base;
    int rv;

    // Get base name of the program
    base = st->progname;
    for (p = base; *p; p++) {
        if (*p == '/') {
            base = p + 1;
        }
    }

    if (st->msg) {
        fprintf(stderr, "%s: %s\n", base, st->msg);
        xfree(st->msg);
        st->msg = NULL;
    }
    fprintf(stderr, "Usage: %s", base);
    for (opt = st->opts; !is_term(opt); opt++) {
        fprintf(stderr, " %s", opt->optmin ? "" : "[");
        if (!is_arg(opt)) {
            fprintf(stderr, "--%s%s%s",
                    opt->optlong,
                    opt->optmeta ? " " : "",
                    opt->optmeta ? opt->optmeta : "");
        }
        else {
            fprintf(stderr, "%s%s",
                    opt->optmeta,
                    opt->optmax > 1 ? "..." : "");
        }
        fprintf(stderr, "%s", opt->optmin ? "" : "]");
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "%s\n", data->desc);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    for (opt = st->opts; !is_term(opt) && !is_arg(opt); opt++) {
        if (opt->optmeta) {
            if (opt->optshort) {
                rv = fprintf(stderr, "    -%c %s, --%s %s",
                        opt->optshort, opt->optmeta,
                        opt->optlong, opt->optmeta);
            }
            else {
                rv = fprintf(stderr, "    --%s %s",
                        opt->optlong, opt->optmeta);
            }
        }
        else {
            if (opt->optshort) {
                rv = fprintf(stderr, "    -%c, --%s",
                        opt->optshort, opt->optlong);
            }
            else {
                rv = fprintf(stderr, "    --%s",
                        opt->optlong);
            }
        }
        if (rv < 30) {
            fprintf(stderr, "%*s%s\n", 30 - rv, "", opt->opthelp);
        }
        else {
            fprintf(stderr, "\n%*s%s\n", 30, "", opt->opthelp);
        }
    }
    fprintf(stderr, "\n");
    if (!is_term(opt)) {
        fprintf(stderr, "Arguments:\n");
        for (/* continue above loop */; !is_term(opt); opt++) {
            rv = fprintf(stderr, "    %s", opt->optmeta);
            if (rv < 30) {
                fprintf(stderr, "%*s%s\n", 30 - rv, "", opt->opthelp);
            }
            else {
                fprintf(stderr, "\n%*s%s\n", 30, "", opt->opthelp);
            }
        }
    }
    exit(EX_USAGE);
}

/**
    Set a boolean option to true.

    @param st Option parsing state
    @return Nothing
*/
static void
handler_bool(struct opt_parse_state_s *st)
{
    struct opt_arg_BOOL_s *data = st->current->optarg;

    *data->pvar = true;
}

/**
    Set a string option.

    @param st Option parsing state
    @return Nothing
*/
static void
handler_string(struct opt_parse_state_s *st)
{
    struct opt_arg_STRING_s *data = st->current->optarg;

    if (*st->argv == NULL) {
        // This should never happen for arguments - this function wouldn't be
        // called if we ran out of arguments.
        OOPS_ASSERT(!is_arg(st->current));
        opt_usage(st, "Option --%s requires an argument", st->current->optlong);
    }
    *data->pstr = *st->argv;
    st->argv++;
}

/**
    Callback function handling an option.

    @param st Option parsing state
    @return Nothing
*/
static void
handler_func(struct opt_parse_state_s *st)
{
    struct opt_arg_FUNC_s *data = st->current->optarg;

    data->func(st, &st->argv, data->arg);
}

/// Known option types
static const opt_handler_t handlers[OPT_TYPE_MAX] = {
    [OPT_TYPE_USAGE] = handler_usage,
    [OPT_TYPE_BOOL] = handler_bool,
    [OPT_TYPE_STRING] = handler_string,
    [OPT_TYPE_FUNC] = handler_func,
};

/**
    Invoke option type-specific handler.

    @param opt Option description
    @param st Option parsing state
    @return Nothing
*/
static void
handle_option(const opt_t *opt, struct opt_parse_state_s *st)
{
    size_t optidx;

    OOPS_ASSERT(opt->opttype < sizeofarray(handlers));
    OOPS_ASSERT(opt >= st->opts && opt < st->opts + st->nopts + st->nargs);

    optidx = opt - st->opts;
    if (opt->optmax && st->counters[optidx] >= opt->optmax) {
        opt_usage(st, "At most %zu instances of the %s%s %s are allowed",
                opt->optmax,
                is_arg(opt) ? "" : "--",
                is_arg(opt) ? opt->optmeta : opt->optlong,
                is_arg(opt) ? "argument" : "option");
    }
    st->current = opt;
    handlers[opt->opttype](st);
    st->counters[optidx]++;
}

/// Default usage option.
static const opt_t default_usage = { OPT_USAGE("") };

/**
    Find an option by its long name.

    @param opts Array of known options
    @param name Option name
    @return Option structure or NULL if not found
*/
static const opt_t *
find_long_opt(const opt_t *opts, const char *name)
{
    const opt_t *opt;

    for (opt = opts; !is_term(opt) && !is_arg(opt); opt++) {
        /// @todo Handle --foo=bar flavor (where option argument follows equal sign rather than
        /// provided as a separate argument)
        if (!strcmp(opt->optlong, name)) {
            return opt;
        }
    }
    return NULL;
}

/**
    Find an option by the short character.

    @param opts Array of known options
    @param ch Character
    @return Option structure or NULL if not found
*/
static const opt_t *
find_short_opt(const opt_t *opts, char ch)
{
    const opt_t *opt;

    for (opt = opts; !is_term(opt) && !is_arg(opt); opt++) {
        if (opt->optshort == ch) {
            return opt;
        }
    }
    return NULL;
}

/**
    Parse the options.

    @param opts Known options
    @param argv Program arguments; the array is modified by the parser.
    @return Nothing
*/
void
opt_parse(const opt_t *opts, char *argv[])
{
    struct opt_parse_state_s st;
    const opt_t *opt;
    char *p, *saved_arg;
    char **saved_argv;
    size_t i;

    // Argument #0 is program name
    st.progname = argv[0];
    st.argv = argv + 1;
    st.opts = opts;
    st.nopts = 0;
    st.nargs = 0;
    st.usage = &default_usage;
    st.current = NULL;
    st.msg = NULL;
    for (i = 0; !is_term(&opts[i]); i++) {
        if (is_arg(&opts[i])) {
            OOPS_ASSERT(opts[i].optmeta); // Mandatory for arguments
            st.nargs++;
        }
        else {
            OOPS_ASSERT(!st.nargs); // Args must follow opts
            st.nopts++;
            if (opts[i].opttype == OPT_TYPE_USAGE) {
                OOPS_ASSERT(st.usage == &default_usage); // Only one allowed
                st.usage = &opts[i];
            }
        }
    }
    st.counters = xmalloc(sizeof(size_t) * (st.nargs + st.nopts));
    memset(st.counters, 0, sizeof(size_t) * (st.nargs + st.nopts));

    // Handle options first
    while ((p = *st.argv) != NULL) {
        if (p[0] == '-') {
            if (p[1] == '-') {
                // The rest of this is a long option or argument delimiter
                if (!p[2]) {
                    st.argv++;
                    break; // Arguments follow
                }
                else if ((opt = find_long_opt(opts, p + 2)) == NULL) {
                    opt_usage(&st, "Unknown option %s", p);
                }
                else {
                    st.argv++; // Option arguments, if any, follow
                    handle_option(opt, &st);
                }
            }
            else {
                // Short option. Several of them can be combined into
                // a single argument, and argument to an option may be in
                // that very same argument
                saved_argv = st.argv;
                saved_arg = p;
                *st.argv = p + 1;
                while (st.argv == saved_argv && *(p = *st.argv) != '\0') {
                    if ((opt = find_short_opt(opts, *p)) == NULL) {
                        opt_usage(&st, "Unknown option -%c", *p);
                    }
                    *st.argv = p + 1; // Consume the character
                    if (!**st.argv) {
                        st.argv++; // This consumed the rest of this argument
                    }
                    handle_option(opt, &st);
                }
                if (st.argv == saved_argv) {
                    // Exited the loop above by consuming all characters in this arg
                    st.argv++;
                }
                *saved_argv = saved_arg; // Restore original value
            }
        }
        else {
            break; // Off to arguments
        }
    }

    // Consume any positional arguments
    for (opt = opts + st.nopts; !is_term(opt) && *st.argv; opt++) {
        // TBD what would be semantics of optmin/optmax? Invoke each option optmin times?
        handle_option(opt, &st);
    }

    // Any unconsumed options? Display the usage
    if (*st.argv) {
        opt_usage(&st, "Unexpected arguments");
    }

    // Check if the required options were seen
    for (i = 0; !is_term(&opts[i]); i++) {
        opt = &opts[i];
        if (st.counters[i] < opt->optmin) {
            opt_usage(&st, "At least %zu instance(s) of the %s%s %s are required",
                    opt->optmax,
                    is_arg(opt) ? "" : "--",
                    is_arg(opt) ? opt->optmeta : opt->optlong,
                    is_arg(opt) ? "argument" : "option");
        }
    }

    xfree(st.counters);
}

/**
    Report usage and exit.

    @param st Option parsing state
    @param fmt Message format, or NULL if usage is to be displayed without a message
    @return Does not return
*/
void
opt_usage(struct opt_parse_state_s *st, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    st->msg = xvasprintf(fmt, ap);
    va_end(ap);
    handle_option(st->usage, st);
}
