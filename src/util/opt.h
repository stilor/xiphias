/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Parsing of command-line arguments
*/

#ifndef __util_opt_h_
#define __util_opt_h_

#include <stdbool.h>
#include "util/defs.h"

/// Opaque handle if option callback needs to raise an error
struct opt_parse_state_s;

/// Known option types
enum opt_type_e {
    OPT_TYPE_USAGE,             ///< Option to display the usage
    OPT_TYPE_BOOL,              ///< Boolean option
    OPT_TYPE_STRING,            ///< String option
    OPT_TYPE_FUNC,              ///< Callback function handles
    OPT_TYPE_MAX,               ///< Max number of option types
};

/// Short option
typedef struct opt_s {
    char optshort;              ///< Short option
    const char *optlong;        ///< Long option
    const char *optmeta;        ///< Metavariable for help message
    const char *opthelp;        ///< Help message
    size_t optmin;              ///< Minimum number of instances
    size_t optmax;              ///< Maximum number of instances (0==any)
    enum opt_type_e opttype;    ///< Option type
    void *optarg;               ///< Type-specific argument
} opt_t;

/// Option for usage
struct opt_arg_USAGE_s {
    const char *desc;           ///< Text description
};

/// Option for boolean options
struct opt_arg_BOOL_s {
    bool *pvar;                 ///< Pointer to a variable being set
};

/// Option for string values
struct opt_arg_STRING_s {
    const char **pstr;          ///< Pointer where string will be saved
};

/// Callback function
struct opt_arg_FUNC_s {
    /// Callback function
    void (*func)(struct opt_parse_state_s *, char ***pargv, void *arg);

    /// Argument to callback
    void *arg;
};

/// Option short/long key
#define OPT_KEY(s,l) \
    .optshort = s, \
    .optlong = l

/// Positional argument
#define OPT_ARGUMENT \
    .optshort = '\0', \
    .optlong = NULL

/// Help message for this option
#define OPT_HELP(m,h) \
    .optmeta = m, \
    .opthelp = h

/// Any number of repetions
#define OPT_CNT_ANY \
    .optmin = 0, \
    .optmax = 0

/// Optional (none or 1)
#define OPT_CNT_OPTIONAL \
    .optmin = 0, \
    .optmax = 1

/// Single instance of this option is allowed
#define OPT_CNT_SINGLE \
    .optmin = 1, \
    .optmax = 1

/// Specified number of instances
#define OPT_CNT(a,b) \
    .optmin = a, \
    .optmax = b

/// Type-specific info
#define OPT_TYPE(t,...) \
    .opttype = OPT_TYPE_##t, \
    .optarg = &(struct opt_arg_##t##_s){ __VA_ARGS__ }

/// End of options
#define OPT_END { \
    .opttype = OPT_TYPE_MAX, \
    .optarg = NULL, \
}

/// Common option: usage on -? or --help options
#define OPT_USAGE(progdesc) \
    OPT_KEY('?', "help"), \
    OPT_HELP(NULL, "Display the usage"), \
    OPT_CNT_ANY, \
    OPT_TYPE(USAGE, .desc = progdesc)

void opt_parse(const opt_t *opts, char *argv[]);
void opt_usage(struct opt_parse_state_s *st, const char *fmt, ...) __printflike(2,3);

#endif
