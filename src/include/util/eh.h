/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Error handling interfaces.
*/

#ifndef __util_eh_h_
#define __util_eh_h_

#include <stdint.h>

/// Error severity levels
enum eh_severity_e {
    EH_NOTE,            ///< Not an error
    EH_WARNING,         ///< Warning
    EH_ERROR,           ///< Error
    EH_FATAL,           ///< Fatal error
};

typedef struct {
    const char *src;    ///< Source (file or URI)
    uint32_t line;      ///< Line number
    uint32_t offs;      ///< Offset into the line
} eh_location_t;

/// Opaque structure for storing errors
typedef struct eh_s eh_t;

/// Callback function for EH dump
typedef void (*eh_cb_t)(void *arg, const eh_location_t *loc,
        enum eh_severity_e severity, const char *msg);

/**
    Create a new error handler.

    @return Error handler pointer
*/
eh_t *eh_new(void);


/**
    Free the data associated with the error handler.

    @param eh Error handler
    @return None
*/
void eh_delete(eh_t *eh);

/**
    Remove error records from the list.

    @param eh Error handler
    @return None
*/
void eh_clear(eh_t *eh);

/**
    Report all accumulated errors.

    @param eh Error handler
    @param func Function to be called for each recorded error
    @param arg Arbitrary argument for the function
    @return None
*/
void eh_foreach(eh_t *eh, eh_cb_t func, void *arg);

/**
    Log an error to the EH.

    @param eh Error handler
    @param loc Location of the error, or NULL if undetermined
    @param severity Severity of the error
    @param fmt Log message format
    @return None
*/
void eh_log(eh_t *eh, const eh_location_t *loc, enum eh_severity_e severity,
        const char *fmt, ...);

#endif
