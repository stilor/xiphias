/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Error handling. Note that the xutils.c interfaces are not used here,
    lest it would pose a chicken-and-egg problem: where do we get the EH
    to handle the failures if, say, malloc() cannot get memory?
*/
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "util/defs.h"
#include "util/queue.h"
#include "util/eh.h"

/// One error record
typedef struct eh_record_s {
    STAILQ_ENTRY(eh_record_s) link;     ///< Record list pointer
    eh_location_t loc;                  ///< Location of the error
    enum eh_severity_e severity;        ///< Severity of the error
    const char *msg;                    ///< Error message
} eh_record_t;

/// Error handler flag bits
enum {
    F_INTERR            = 0x0001,       ///< Internal error occurred
};

/// Error handler contents
struct eh_s {
    STAILQ_HEAD(, eh_record_s) errlst;  ///< List of errors
    uint32_t flags;                     ///< Flags
    // TBD jump buffer
    // TBD string hash for locations?
};

// Create a new error handler
eh_t *
eh_new(void)
{
    eh_t *eh;

    if ((eh = malloc(sizeof(eh_t))) != NULL) {
        STAILQ_INIT(&eh->errlst);
        eh->flags = 0;
    }
    return eh;
}

// Destroy an error handler
void
eh_delete(eh_t *eh)
{
    eh_clear(eh);
    free(eh);
}

// Remove error records
void
eh_clear(eh_t *eh)
{
    eh_record_t *er;

    while ((er = STAILQ_FIRST(&eh->errlst)) != NULL) {
        STAILQ_REMOVE_HEAD(&eh->errlst, link);
        if (er->msg) {
            free(DECONST(er->msg));
        }
        if (er->loc.src) {
            free(DECONST(er->loc.src));
        }
        free(er);
    }
    eh->flags &= ~F_INTERR;
}

// Go over recorded errors
void
eh_foreach(eh_t *eh, eh_cb_t func, void *arg)
{
    eh_record_t *er;

    STAILQ_FOREACH(er, &eh->errlst, link) {
        func(arg, er->loc.src ? &er->loc : NULL, er->severity, er->msg);
    }
    if (eh->flags & F_INTERR) {
        // Internal error noted that may or may not have been reported via the list
        func(arg, NULL, EH_FATAL, "<possibly unknown internal error>");
    }
}

// Log an error
void
eh_log(eh_t *eh, const eh_location_t *loc, enum eh_severity_e severity, const char *fmt, ...)
{
    char *msg;
    va_list ap;
    eh_record_t *er;

    if (eh->flags & F_INTERR) {
        // Everything is broken beyond repair already
        return;
    }

    if ((er = malloc(sizeof(eh_record_t))) != NULL) {
        // Record original severity; the behavior may be changed to fatal in case of internal errors
        er->severity = severity;
        if (loc) { // Copy location info
            if ((er->loc.src = strdup(loc->src)) == NULL) {
                eh->flags |= F_INTERR;
                severity = EH_FATAL;
            }
            er->loc.line = loc->line;
            er->loc.offs = loc->offs;
        }
        else { // Not bound to any input document
            er->loc.src = NULL;
            er->loc.line = 0;
            er->loc.offs = 0;
        }
        va_start(ap, fmt);
        if (vasprintf(&msg, fmt, ap) == -1) {
            eh->flags |= F_INTERR;
            severity = EH_FATAL;
        }
        va_end(ap);
        STAILQ_INSERT_TAIL(&eh->errlst, er, link);
    }
    else {
        // Cannot get memory to record the error: upgrade severity to fatal and mark an internal
        // error.
        eh->flags |= F_INTERR;
        severity = EH_FATAL;
    }

    if (severity == EH_FATAL) {
        // TBD run cleanups
        // TBD jump
    }
}
