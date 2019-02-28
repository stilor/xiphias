/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "util/strbuf.h"
#include "util/xutil.h"

#include "unicode/encoding.h"

#include "xml/reader.h"

#include "test/common/testlib.h"
#include "test/xml/enum.h"
#include "test/xml/reader-event.h"

/// Per-event methods
typedef struct event_s {
    void (*print)(const xml_reader_cbparam_t *e);   ///< Print a text description of an event
    void (*gencode)(const xml_reader_cbparam_t *e); ///< Code generation for test case
    bool (*equal)(const xml_reader_cbparam_t *e1,
            const xml_reader_cbparam_t *e2);        ///< Check events for equality
    bool (*isset)(const xml_reader_cbparam_t *e);   ///< Check if type-specific part is not default
} event_t;

static char *
string_escape(const char *s)
{
    char *p, *px;
    const char *sx;
    size_t len;

    len = 0;
    for (sx = s; *sx; sx++) {
        len += (*sx == '"' || *sx == '\\') ? 2 : 1;
    }
    p = px = xmalloc(len + 1);
    while (*s) {
        if (*s == '"' || *s == '\\') {
            *px++ = '\\';
        }
        *px++ = *s++;
    }
    *px = '\0';
    return p;
}

static char *
string_escape_utf8(const utf8_t *s, int len)
{
    /// @todo Assumes 1-to-1 correspondence between UTF-8 and local charset
    const utf8_t *sx;
    size_t lenx, nlen;
    char *p, *px;

    if (len < 0) {
        len = utf8_len(s);
    }

    nlen = 0;
    for (sx = s, lenx = len; lenx; lenx--, sx++) {
        if (*sx >= 0x7F) {
            nlen += 4; // \xHH
        }
        else if (*sx == '"' || *sx == '\\' || *sx == '\n' || *sx == '\t' || *sx == '\r') {
            nlen += 2;
        }
        else {
            nlen += 1;
        }
    }

    p = px = xmalloc(nlen + 1);
    for (sx = s, lenx = len; lenx; lenx--, sx++) {
        if (*sx >= 0x7F) {
            sprintf(px, "\\x%02X", *sx);
            px += 4;
            continue;
        }
        if (*sx == '\n') {
            *px++ = '\\';
            *px++ = 'n';
            continue;
        }
        if (*sx == '\r') {
            *px++ = '\\';
            *px++ = 'r';
            continue;
        }
        if (*sx == '\t') {
            *px++ = '\\';
            *px++ = 't';
            continue;
        }
        if (*sx == '"' || *sx == '\\') {
            *px++ = '\\';
        }
        *px++ = *sx;
    }
    *px = '\0';
    return p;
}

static char *
string_escape_unicode_control(const utf8_t *s, size_t len)
{
    /// @todo Assumes 1-to-1 correspondence between UTF-8 and local charset
    const utf8_t *sx;
    size_t lenx, nlen;
    char *p, *px;

    nlen = 0;
    for (sx = s, lenx = len; lenx; lenx--, sx++) {
        if (*sx < 0x20 || *sx == 0x7F) {
            nlen += 3; // U+24xx, 'Control Pictures' - 3 bytes
        }
        else if (lenx >= 2 && sx[0] == 0xC2 && sx[1] == 0x85) {
            nlen += 3; // U+24xx, 'Control Pictures' - 3 bytes
            sx++; // swallow one extra byte
        }
        // TBD U+2028 - there doesn't seem to be a good 'control picture'
        else {
            nlen += 1;
        }
    }

    p = px = xmalloc(nlen + 1);
    for (sx = s, lenx = len; lenx; lenx--, sx++) {
        if (*sx < 0x20) {
            // E2 90 xx (where xx is '80h + yy') is UTF-8 representation of U+24yy
            *px++ = '\xE2';
            *px++ = '\x90';
            *px++ = '\x80' + *sx;
            continue;
        }
        if (*sx == 0x7F) { // U+2421
            *px++ = '\xE2';
            *px++ = '\x90';
            *px++ = '\xA1';
            continue;
        }
        if (lenx >= 2 && sx[0] == 0xC2 && sx[1] == 0x85) { // U+2422
            sx++; // swallow one extra byte
            *px++ = '\xE2';
            *px++ = '\x90';
            *px++ = '\xA2';
            continue;
        }
        *px++ = *sx;
    }
    *px = '\0';
    return p;
}

static void
print_prefix(const char *msg)
{
    if (msg) {
        printf("  %s: ", msg);
    }
    else {
        printf("  ");
    }
}

static void
print_token(const char *pfx, const xml_reader_token_t *tk)
{
    char *s;

    if (xml_reader_token_isset(tk)) {
        s = string_escape_unicode_control(tk->str, tk->len);
        print_prefix(pfx);
        printf("'%s' [%zu]", s, tk->len);
        xfree(s);
    }
}

static bool
equal_token(const xml_reader_token_t *tk1, const xml_reader_token_t *tk2)
{
    if (tk1->str == NULL && tk2->str == NULL) {
        return true; // Both unset
    }
    if (tk1->str == NULL || tk2->str == NULL) {
        return false; // One set, one unset
    }
    if (tk1->len != tk2->len) {
        return false; // Different length
    }
    return !memcmp(tk1->str, tk2->str, tk1->len); // Compare content
}

#define INDENT                  "    "

#define GENC_FMT(f, fmt)       INDENT INDENT INDENT ".%s = " fmt ",\n", f

#define ISSET_BOOL(x,f,e) \
        true
#define GENC_BOOL(x,f,e) do { \
            printf(GENC_FMT(#f, "%s"), (x)->f ? "true" : "false"); \
        } while (0)
#define P_BOOL(x,f,e,n) do { \
            if (n || (x)->f) { \
                print_prefix(n); /* only if we would print anything */ \
            } \
            if (!e) { \
                printf("%s", (x)->f ? "true" : "false"); \
            } \
            else if ((x)->f) { \
                printf("(%s)", e); \
            } \
        } while (0)
#define EQ_BOOL(x1,x2,f,e) \
        ((x1)->f == (x2)->f)

#define ISSET_STR_OR_NULL(x,f,e) \
        ((x)->f)
#define GENC_STR_OR_NULL(x,f,e) do { \
            char *s; \
            s = string_escape((x)->f); \
            printf(GENC_FMT(#f, "\"%s\""), s); \
            xfree(s); \
        } while (0)
#define P_STR_OR_NULL(x,f,e,n) do { \
            print_prefix(n); \
            if ((x)->f) { \
                printf("'%s'", (x)->f); \
            } \
            else { \
                printf("not set"); \
            } \
        } while (0)
#define EQ_STR_OR_NULL(x1,x2,f,e) \
        ((!(x1)->f && !(x2)->f) || ((x1)->f && (x2)->f && !strcmp((x1)->f, (x2)->f)))

#define ISSET_UTF8_OR_NULL(x,f,e) \
        ((x)->f)
#define GENC_UTF8_OR_NULL(x,f,e) do { \
            char *s; \
            s = string_escape_utf8((x)->f, -1); \
            printf(GENC_FMT(#f, "\"%s\""), s); \
            xfree(s); \
        } while (0)
#define P_UTF8_OR_NULL(x,f,e,n) do { \
            print_prefix(n); \
            if ((x)->f) { \
                printf("'%s'", (x)->f); \
            } \
            else { \
                printf("not set"); \
            } \
        } while (0)
#define EQ_UTF8_OR_NULL(x1,x2,f,e) \
        ((!(x1)->f && !(x2)->f) || ((x1)->f && (x2)->f && !utf8_cmp((x1)->f, (x2)->f)))

#define ISSET_TOKEN(x,f,e) \
        (xml_reader_token_isset(&(x)->f))
#define GENC_TOKEN(x,f,e) do { \
            char *s; \
            s = string_escape_utf8((x)->f.str, (x)->f.len); \
            printf(GENC_FMT(#f, "TOK(\"%s\")"), s); \
            xfree(s); \
        } while (0)
#define P_TOKEN(x,f,e,n) do { \
            print_token(n, &(x)->f); \
        } while (0)
#define EQ_TOKEN(x1,x2,f,e) \
        (equal_token(&(x1)->f, &(x2)->f))

#define ISSET_ENUM(x,f,e) \
        true
#define GENC_ENUM(x,f,e) do { \
            printf(GENC_FMT(#f, "%s"), enum2id((x)->f, &enum_##e, NULL)); \
        } while (0)
#define P_ENUM(x,f,e,n) do { \
            print_prefix(n); \
            printf("%s", enum2str((x)->f, &enum_##e)); \
        } while (0)
#define EQ_ENUM(x1,x2,f,e) \
        ((x1)->f == (x2)->f)


#define ISSET_CUSTOM(x,f,e)     t_isset_##e(&(x)->f)
#define GENC_CUSTOM(x,f,e)      t_genc_##e(&(x)->f, #f)
#define P_CUSTOM(x,f,e,n)       t_print_##e(&(x)->f, n)
#define EQ_CUSTOM(x1,x2,f,e)    t_equal_##e(&(x1)->f, &(x2)->f)

// xmlerr_info_t ops
static bool
t_isset_xmlerr(const xmlerr_info_t *xi)
{
    return true; // always initialized
}

static void
t_genc_xmlerr(const xmlerr_info_t *xi, const char *fldname)
{
    xmlerr_info_t spec_code = XMLERR_MK(XMLERR__NONE, XMLERR_SPEC(*xi), XMLERR_CODE(*xi));

    if (*xi == XMLERR_NOTE) {
        printf(GENC_FMT(fldname, "XMLERR_NOTE"));
    }
    else if (*xi == XMLERR_INTERNAL) {
        printf(GENC_FMT(fldname, "XMLERR_INTERNAL"));
    }
    else {
        printf(GENC_FMT(fldname, "XMLERR(%s, %s, %s)"),
                enum2id(XMLERR_SEVERITY(*xi), &enum_xmlerr_severity, "XMLERR_"),
                enum2id(XMLERR_SPEC(*xi), &enum_xmlerr_spec, "XMLERR_SPEC_"),
                enum2id(spec_code, &enum_xmlerr_code, NULL));
    }
}

static void
t_print_xmlerr(const xmlerr_info_t *xi, const char *name)
{
    xmlerr_info_t spec_code = XMLERR_MK(XMLERR__NONE, XMLERR_SPEC(*xi), XMLERR_CODE(*xi));

    print_prefix(name);
    if (*xi == XMLERR_NOTE) {
        printf("[NOTE]");
    }
    else if (*xi == XMLERR_INTERNAL) {
        printf("[INTERNAL]");
    }
    else {
        printf("[%s %s:%s]",
            enum2str(XMLERR_SEVERITY(*xi), &enum_xmlerr_severity),
            enum2str(XMLERR_SPEC(*xi), &enum_xmlerr_spec),
            enum2str(spec_code, &enum_xmlerr_code));
    }
}

static bool
t_equal_xmlerr(const xmlerr_info_t *xi1, const xmlerr_info_t *xi2)
{
    return *xi1 == *xi2;
}


#define FIELDS_message \
        FLD(info, CUSTOM, xmlerr, NULL) \
        FLD(msg, STR_OR_NULL, NULL, NULL) \

#define FIELDS_entity \
        FLD(type, ENUM, reftype, NULL) \
        FLD(name, TOKEN, NULL, NULL) \
        FLD(text, TOKEN, NULL, "text") \
        FLD(system_id, TOKEN, NULL, "sysid") \
        FLD(public_id, TOKEN, NULL, "pubid") \
        FLD(ndata, TOKEN, NULL, "ndata") \
        FLD(nsystem_id, TOKEN, NULL, "n/sysid") \
        FLD(npublic_id, TOKEN, NULL, "n/pubid") \

#define FIELDS_notation \
        FLD(name, TOKEN, NULL, NULL) \
        FLD(system_id, TOKEN, NULL, "sysid") \
        FLD(public_id, TOKEN, NULL, "pubid") \

#define FIELDS_xmldecl \
        FLD(encoding, UTF8_OR_NULL, NULL, "encoding") \
        FLD(standalone, ENUM, xml_standalone, "standalone") \
        FLD(version, ENUM, xml_version, "version") \

#define FIELDS_dtd \
        FLD(root, TOKEN, NULL, "root") \
        FLD(system_id, TOKEN, NULL, "sysid") \
        FLD(public_id, TOKEN, NULL, "pubid") \

#define FIELDS_comment \
        FLD(text, TOKEN, NULL, NULL) \

#define FIELDS_pi \
        FLD(target, TOKEN, NULL, NULL) \
        FLD(content, TOKEN, NULL, "content") \
        FLD(nsystem_id, TOKEN, NULL, "n/sysid") \
        FLD(npublic_id, TOKEN, NULL, "n/pubid") \

#define FIELDS_text \
        FLD(text, TOKEN, NULL, NULL) \
        FLD(ws, BOOL, "whitespace", NULL) \

#define FIELDS_tag \
        FLD(name, TOKEN, NULL, NULL) \

#define FIELDS_attr \
        FLD(name, TOKEN, NULL, NULL) \
        FLD(value, TOKEN, NULL, "value") \

#define MSGTYPES \
        MT(message) \
        MT(entity) \
        MT(notation) \
        MT(xmldecl) \
        MT(dtd) \
        MT(comment) \
        MT(pi) \
        MT(text) \
        MT(tag) \
        MT(attr) \

// Checking for non-default initializer
#define FLD(f,t,e,n) || ISSET_##t(x,f,e)
#define MT(n) \
static bool \
ev_isset_##n(const xml_reader_cbparam_t *cbp) \
{ \
    const xml_reader_cbparam_##n##_t *x = &cbp->n; \
    return false FIELDS_##n; \
}
MSGTYPES
#undef MT
#undef FLD

// Printing in human readable form
#define FLD(f,t,e,n) P_##t(x,f,e,n);
#define MT(n) \
static void \
ev_print_##n(const xml_reader_cbparam_t *cbp) \
{ \
    const xml_reader_cbparam_##n##_t *x = &cbp->n; \
    FIELDS_##n \
}
MSGTYPES
#undef MT
#undef FLD

// Code generation
#define FLD(f,t,e,n) if (ISSET_##t(x,f,e)) { GENC_##t(x,f,e); }
#define MT(n) \
static void \
ev_genc_##n(const xml_reader_cbparam_t *cbp) \
{ \
    const xml_reader_cbparam_##n##_t *x = &cbp->n; \
    FIELDS_##n \
}
MSGTYPES
#undef MT
#undef FLD

// Checking for equality
#define FLD(f,t,e,n) && EQ_##t(x1,x2,f,e)
#define MT(n) \
static bool \
ev_equal_##n(const xml_reader_cbparam_t *cbp1, const xml_reader_cbparam_t *cbp2) \
{ \
    const xml_reader_cbparam_##n##_t *x1 = &cbp1->n; \
    const xml_reader_cbparam_##n##_t *x2 = &cbp2->n; \
    return true FIELDS_##n; \
}
MSGTYPES
#undef MT
#undef FLD


#define ev_isset___no_extra_data     NULL
#define ev_print___no_extra_data     NULL
#define ev_genc___no_extra_data      NULL
#define ev_equal___no_extra_data     NULL

#define X(t) \
        [XML_READER_CB_##t] = { \
            .isset = concat(ev_isset_, FL(t)), \
            .print = concat(ev_print_, FL(t)), \
            .equal = concat(ev_equal_, FL(t)), \
            .gencode = concat(ev_genc_, FL(t)), \
        },

static const event_t events[] = {
    X(NONE)
    X(MESSAGE)
    X(ENTITY_UNKNOWN)
    X(ENTITY_NOT_LOADED)
    X(ENTITY_PARSE_START)
    X(ENTITY_PARSE_END)
    X(XMLDECL)
    X(DTD_BEGIN)
    X(DTD_END)
    X(COMMENT)
    X(PI)
    X(ENTITY_DEF)
    X(NOTATION_DEF)
    X(TEXT)
    X(STAG)
    X(ETAG)
    X(ATTR)
};
#undef X

/**
    Print an information about XML reader event to stdout.

    @param cbparam Callback parameter
    @return Nothing
*/
void
xmlreader_event_print(const xml_reader_cbparam_t *cbparam)
{
    const event_t *evt;

    evt = &events[cbparam->cbtype < sizeofarray(events) ? cbparam->cbtype : XML_READER_CB_NONE];
    printf("[%s:%u:%u] %s:",
            cbparam->loc.src ? S(cbparam->loc.src) : "<undef>",
            cbparam->loc.line, cbparam->loc.pos,
            enum2str(cbparam->cbtype, &enum_cbtype));
    if (evt && evt->print) {
        evt->print(cbparam);
    }
    printf("\n");
}

/**
    Compare two XML reader events.

    @param e1 First event
    @param e2 Second event
    @return true if equal, false otherwise
*/
bool
xmlreader_event_equal(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    if (e1->cbtype != e2->cbtype
            || e1->cbtype >= sizeofarray(events)
            || !utf8_null_or_equal(e1->loc.src, e2->loc.src)
            || e1->loc.line != e2->loc.line
            || e1->loc.pos != e2->loc.pos) {
        return false;
    }
    if (!events[e1->cbtype].equal) {
        return true; // nothing else to compare
    }
    return events[e1->cbtype].equal(e1, e2);
}

/**
    Generate code for XML reader test case

    @param cbparam Callback parameter
    @return Nothing
*/
void
xmlreader_event_gencode(const xml_reader_cbparam_t *cbparam)
{
    const event_t *evt;
    bool isset;
    char *s;

    // .isset is due to peculiarity of C syntax: empty structure initializers
    // are not allowed, even though the intent is to have all members initialized
    // with default values. GCC accepts this, but issues a warning. Thus, 'EV' is
    // used for regular events and 'E0' for events with empty initializers for
    // type-specific portion.
    evt = &events[cbparam->cbtype < sizeofarray(events) ? cbparam->cbtype : XML_READER_CB_NONE];
    isset = evt->isset && evt->isset(cbparam);
    printf(INDENT "%s(%s,\n",
            isset ? "EV" : "E0",
            enum2id(cbparam->cbtype, &enum_cbtype, "XML_READER_CB_"));
    if (cbparam->loc.src) {
        s = string_escape_utf8(cbparam->loc.src, -1);
        printf(INDENT INDENT INDENT "LOC(\"%s\", %u, %u)%s\n",
                s, cbparam->loc.line, cbparam->loc.pos,
                isset ? "," : "");
        xfree(s);
    }
    else {
        printf(INDENT INDENT INDENT "NOLOC%s\n",
                isset ? "," : "");
    }
    if (isset && evt->gencode) {
        evt->gencode(cbparam);
    }
    printf(INDENT "),\n");
}
