/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Parsing of command-line arguments
*/

#ifndef __util_opt_h_
#define __util_opt_h_

#include <stdbool.h>

/// Known option types
enum opt_type_e {
    OPT_TYPE_USAGE,             ///< Option to display the usage
    OPT_TYPE_BOOL,              ///< Boolean option
    OPT_TYPE_STRING,            ///< String option
    OPT_TYPE_MAX,               ///< Max number of option types
};

/// Short option
typedef struct opt_s {
    char optshort;              ///< Short option
    const char *optlong;        ///< Long option
    const char *optmeta;        ///< Metavariable for help message
    enum opt_type_e opttype;    ///< Option type
    const char *opthelp;        ///< Help message
    void *optarg;               ///< Type-specific argument
} opt_t;

/// Option for usage
struct opt_arg_USAGE_s {
    const char *progdesc;       ///< Program description
};

/// Option for boolean options
struct opt_arg_BOOL_s {
    bool *pvar;                 ///< Pointer to a variable being set
};

/// Option for string values
struct opt_arg_STRING_s {
    const char **pstr;          ///< Pointer where string will be saved
};

/// Common part of option declarations
#define OPT(s,l,t,m,h,...) { \
    .opttype = OPT_TYPE_##t, \
    .optshort = s, \
    .optlong = l, \
    .optmeta = m, \
    .opthelp = h, \
    .optarg = &(struct opt_arg_##t##_s){ __VA_ARGS__ }, \
}

/// Argument (passed after the options, consumed in the order defined
#define OPT_ARGUMENT(t,m,h,...) { \
    .opttype = OPT_TYPE_##t, \
    .optlong = NULL, \
    .optshort = '\0', \
    .optmeta = m, \
    .opthelp = h, \
    .optarg = &(struct opt_arg_##t##_s){ __VA_ARGS__ }, \
}

/// End of options
#define OPT_END { \
    .opttype = OPT_TYPE_MAX, \
    .optlong = NULL, \
    .optshort = '\0', \
    .optmeta = NULL, \
    .opthelp = NULL, \
    .optarg = NULL, \
}

/// Common option: usage on -? or --help options
#define OPT_USAGE(progdesc) \
        OPT('?', "help", USAGE, NULL, "Display the usage", progdesc)

void opt_parse(const opt_t *opts, char *argv[]);

#endif
