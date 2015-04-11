/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Parsing of command-like arguments.
*/
#include <stdlib.h>
#include <string.h>

#include "util/defs.h"
#include "util/xutil.h"

#include "opt.h"

/// State of the option parser
struct parse_state_s {
    char **argv;            ///< Current option pointer
    void *data;             ///< Type-specific data
    const opt_t *opts;      ///< Array of all options
    size_t nopts;           ///< Number of options
    size_t nargs;           ///< Number of arguments
    const char *progname;   ///< Program name
    const opt_t *usage;     ///< Option for usage
    const char *msg;        ///< Error message for usage, if any
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
typedef void (*opt_handler_t)(struct parse_state_s *st);


/**
    Display a usage message and exit.

    @param st Option parsing state
    @return Nothing
*/
static void
handler_usage(struct parse_state_s *st)
{
    struct opt_arg_USAGE_s *data = st->data;
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
        printf("%s: %s\n", base, st->msg);
        xfree(st->msg);
        st->msg = NULL;
    }
    printf("Usage: %s", base);
    for (opt = st->opts; !is_term(opt); opt++) {
        if (!is_arg(opt)) {
            printf(" [--%s%s%s]",
                    opt->optlong,
                    opt->optmeta ? " " : "",
                    opt->optmeta ? opt->optmeta : "");
        }
        else {
            printf(" %s", opt->optmeta);
        }
    }
    printf("\n");
    printf("%s\n", data->progdesc);
    printf("\n");
    printf("Options:\n");
    for (opt = st->opts; !is_term(opt) && !is_arg(opt); opt++) {
        if (opt->optmeta) {
            if (opt->optshort) {
                rv = printf("    -%c %s, --%s %s",
                        opt->optshort, opt->optmeta,
                        opt->optlong, opt->optmeta);
            }
            else {
                rv = printf("    --%s %s",
                        opt->optlong, opt->optmeta);
            }
        }
        else {
            if (opt->optshort) {
                rv = printf("    -%c, --%s",
                        opt->optshort, opt->optlong);
            }
            else {
                rv = printf("    --%s",
                        opt->optlong);
            }
        }
        if (rv < 30) {
            printf("%*s%s\n", 30 - rv, "", opt->opthelp);
        }
        else {
            printf("\n%*s%s\n", 30, "", opt->opthelp);
        }
    }
    printf("\n");
    if (!is_term(opt)) {
        printf("Arguments:\n");
        for (/* continue above loop */; !is_term(opt); opt++) {
            rv = printf("    %s", opt->optmeta);
            if (rv < 30) {
                printf("%*s%s\n", 30 - rv, "", opt->opthelp);
            }
            else {
                printf("\n%*s%s\n", 30, "", opt->opthelp);
            }
        }
    }
    exit(1);
}

/**
    Set a boolean option to true.

    @param st Option parsing state
    @return Nothing
*/
static void
handler_bool(struct parse_state_s *st)
{
    struct opt_arg_BOOL_s *data = st->data;

    *data->pvar = true;
}

/**
    Set a string option.

    @param st Option parsing state
    @return Nothing
*/
static void
handler_string(struct parse_state_s *st)
{
    struct opt_arg_STRING_s *data = st->data;

    *data->pstr = *st->argv;
    st->argv++;
}

/// Known option types
static const opt_handler_t handlers[OPT_TYPE_MAX] = {
    [OPT_TYPE_USAGE] = handler_usage,
    [OPT_TYPE_BOOL] = handler_bool,
    [OPT_TYPE_STRING] = handler_string,
};

/**
    Invoke option type-specific handler.

    @param opt Option description
    @param st Option parsing state
    @return Nothing
*/
static void
handle_option(const opt_t *opt, struct parse_state_s *st)
{
    OOPS_ASSERT(opt->opttype < sizeofarray(handlers));
    st->data = opt->optarg;
    handlers[opt->opttype](st);
}

/// Default usage option.
static const opt_t default_usage = OPT_USAGE("");

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
    struct parse_state_s st;
    const opt_t *opt;
    char *p, *saved_arg;
    char **saved_argv;
    size_t i;

    // Argument #0 is program name
    st.progname = argv[0];
    st.argv = argv + 1;
    st.data = NULL;
    st.opts = opts;
    st.nopts = 0;
    st.nargs = 0;
    st.usage = &default_usage;
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
                    st.msg = xasprintf("Unexpected option %s", p);
                    handle_option(st.usage, &st);
                }
                else {
                    st.argv++; // Option arguments, if any, follow
                    handle_option(opt, &st);
                }
            }
            else {
                // Short option. Several of them can be combined into
                // a single argument, and argument to an option may be in
                saved_argv = st.argv;
                saved_arg = p;
                *st.argv = p + 1;
                while (st.argv == saved_argv && *(p = *st.argv) != '\0') {
                    if ((opt = find_short_opt(opts, *p)) == NULL) {
                        st.msg = xasprintf("Unexpected option -%c", *p);
                        handle_option(st.usage, &st);
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
        handle_option(opt, &st);
    }

    // Any unconsumed options? Display the usage
    if (*st.argv) {
        st.msg = xstrdup("Unexpected arguments");
        handle_option(st.usage, &st);
    }
    else if (!is_term(opt)) {
        st.msg = xasprintf("Missing %s argument", opt->optmeta);
        handle_option(st.usage, &st);
    }
}
