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

#include "xmltest/enum.h"
#include "xmltest/xmlreader-event.h"

/// Per-event methods
typedef struct event_s {
    void (*print)(const xml_reader_cbparam_t *e);   ///< Print a text description of an event
    void (*gencode)(const xml_reader_cbparam_t *e); ///< Code generation for test case
    bool (*equal)(const xml_reader_cbparam_t *e1,
            const xml_reader_cbparam_t *e2);        ///< Check events for equality
} event_t;

static bool
str_null_or_equal(const char *s1, const char *s2)
{
    return (!s1 && !s2) || (s1 && s2 && !strcmp(s1, s2));
}

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
string_escape_utf8(const utf8_t *s, size_t len)
{
    /// @todo Assumes 1-to-1 correspondence between UTF-8 and local charset
    const utf8_t *sx;
    size_t lenx, nlen;
    char *p, *px;

    nlen = 0;
    for (sx = s, lenx = len; lenx; lenx--, sx++) {
        if (*sx >= 0x7F) {
            nlen += 4; // \xHH
        }
        else if (*sx == '"' || *sx == '\\' || *sx == '\n' || *sx == '\t') {
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

#define INDENT                  "    "

#define FIELD_FMT(f, fmt)       INDENT INDENT "." #f " = " fmt ",\n"

#define FIELD_BOOL(x,f) do { \
    printf(FIELD_FMT(f, "%s"), (x)->f ? "true" : "false"); \
} while (0)

#define FIELD_STR_OR_NULL(x,f) do { \
    if ((x)->f) { \
        char *s; \
        s = string_escape((x)->f); \
        printf(FIELD_FMT(f, "\"%s\""), s); \
        xfree(s); \
    } \
   else { \
        printf(FIELD_FMT(f, "NULL")); \
    } \
} while (0)

#define FIELD_ENUM(x,f,e) do { \
    printf(FIELD_FMT(f, "%s"), enum2id((x)->f, &enum_##e, NULL)); \
} while (0)

// Supporting functions: print event data

// MESSAGE

static void
evprint_message(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_message_t *x = &cbparam->message;
    xmlerr_info_t spec_code = XMLERR_MK(XMLERR__NONE,
            XMLERR_SPEC(x->info), XMLERR_CODE(x->info));

    printf("%s ", x->msg ? x->msg : "<no message>");
    if (x->info == XMLERR_NOTE) {
        printf("[NOTE]");
    }
    else if (x->info == XMLERR_INTERNAL) {
        printf("[INTERNAL]");
    }
    else {
        printf("[%s %s:%s]",
            enum2str(XMLERR_SEVERITY(x->info), &enum_xmlerr_severity),
            enum2str(XMLERR_SPEC(x->info), &enum_xmlerr_spec),
            enum2str(spec_code, &enum_xmlerr_code));
    }
}

static void
evgenc_message(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_message_t *x = &cbparam->message;
    xmlerr_info_t spec_code = XMLERR_MK(XMLERR__NONE,
            XMLERR_SPEC(x->info), XMLERR_CODE(x->info));

    if (x->info == XMLERR_NOTE) {
        printf(FIELD_FMT(info, "XMLERR_NOTE"));
    }
    else if (x->info == XMLERR_INTERNAL) {
        printf(FIELD_FMT(info, "XMLERR_INTERNAL"));
    }
    else {
        printf(FIELD_FMT(info, "XMLERR(%s, %s, %s)"),
                enum2id(XMLERR_SEVERITY(x->info), &enum_xmlerr_severity, "XMLERR_"),
                enum2id(XMLERR_SPEC(x->info), &enum_xmlerr_spec, "XMLERR_SPEC_"),
                enum2id(spec_code, &enum_xmlerr_code, NULL));
    }
    FIELD_STR_OR_NULL(x, msg);
}

static bool
evequal_message(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_message_t *x1 = &e1->message;
    const xml_reader_cbparam_message_t *x2 = &e2->message;

    return str_null_or_equal(x1->msg, x2->msg)
            && x1->info == x2->info;
}

// ENTITY_{UNKNOWN,START,END}

static void
evprint_entity(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_entity_t *x = &cbparam->entity;

    printf("%s", enum2str(x->type, &enum_reftype));
    if (x->system_id) {
        printf(", system ID '%s'", x->system_id);
    }
    if (x->public_id) {
        printf(", public ID '%s'", x->public_id);
    }
}

static void
evgenc_entity(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_entity_t *x = &cbparam->entity;

    FIELD_ENUM(x, type, reftype);
    FIELD_STR_OR_NULL(x, system_id);
    FIELD_STR_OR_NULL(x, public_id);
}

static bool
evequal_entity(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_entity_t *x1 = &e1->entity;
    const xml_reader_cbparam_entity_t *x2 = &e2->entity;

    return x1->type == x2->type
            && str_null_or_equal(x1->system_id, x2->system_id)
            && str_null_or_equal(x1->public_id, x2->public_id);
}

// XMLDECL

static void
evprint_xmldecl(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_xmldecl_t *x = &cbparam->xmldecl;

    printf("encoding '%s', standalone '%s', version '%s'",
            x->encoding ? x->encoding : "<unknown>",
            enum2str(x->standalone, &enum_xml_standalone),
            enum2str(x->version, &enum_xml_version));
}

static void
evgenc_xmldecl(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_xmldecl_t *x = &cbparam->xmldecl;

    FIELD_STR_OR_NULL(x, encoding);
    FIELD_ENUM(x, standalone, xml_standalone);
    FIELD_ENUM(x, version, xml_version);
}

static bool
evequal_xmldecl(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_xmldecl_t *x1 = &e1->xmldecl;
    const xml_reader_cbparam_xmldecl_t *x2 = &e2->xmldecl;

    return str_null_or_equal(x1->encoding, x2->encoding)
            && x1->standalone == x2->standalone
            && x1->version == x2->version;
}

// ENTITY_DEF_START

static void
evprint_entitydef(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_entitydef_t *x = &cbparam->entitydef;

    printf("%s entity", x->parameter ? "parameter" : "general");
}

static void
evgenc_entitydef(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_entitydef_t *x = &cbparam->entitydef;

    FIELD_BOOL(x, parameter);
}

static bool
evequal_entitydef(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_entitydef_t *x1 = &e1->entitydef;
    const xml_reader_cbparam_entitydef_t *x2 = &e2->entitydef;

    return x1->parameter == x2->parameter;
}

// NDATA, PI_TARGET

static void
evprint_ndata(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_ndata_t *x = &cbparam->ndata;
    bool comma = false;

    if (x->system_id) {
        printf("system ID '%s'", x->system_id);
        comma = true;
    }
    if (x->public_id) {
        printf("%spublic ID '%s'", comma ? ", " : "", x->public_id);
    }
}

static void
evgenc_ndata(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_ndata_t *x = &cbparam->ndata;

    FIELD_STR_OR_NULL(x, system_id);
    FIELD_STR_OR_NULL(x, public_id);
}

static bool
evequal_ndata(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_ndata_t *x1 = &e1->ndata;
    const xml_reader_cbparam_ndata_t *x2 = &e2->ndata;

    return str_null_or_equal(x1->system_id, x2->system_id)
            && str_null_or_equal(x1->public_id, x2->public_id);
}

// APPEND, CDSECT

static void
evprint_append(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_append_t *x = &cbparam->append;

    if (x->ws) {
        printf("(whitespace)");
    }
}

static void
evgenc_append(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_append_t *x = &cbparam->append;

    FIELD_BOOL(x, ws);
}

static bool
evequal_append(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_append_t *x1 = &e1->append;
    const xml_reader_cbparam_append_t *x2 = &e2->append;

    return x1->ws == x2->ws;
}

// STAG_END

static void
evprint_stag_end(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_stag_end_t *x = &cbparam->stag_end;

    printf("Used %s production", x->is_empty ? "EmptyElemTag" : "STag");
}

static void
evgenc_stag_end(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_stag_end_t *x = &cbparam->stag_end;

    FIELD_BOOL(x, is_empty);
}

static bool
evequal_stag_end(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_stag_end_t *x1 = &e1->stag_end;
    const xml_reader_cbparam_stag_end_t *x2 = &e2->stag_end;

    return x1->is_empty == x2->is_empty;
}

// ATTR

static void
evprint_attr(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_attr_t *x = &cbparam->attr;

    printf("Normalization: %u", x->attrnorm);
}

static void
evgenc_attr(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_attr_t *x = &cbparam->attr;

    FIELD_ENUM(x, attrnorm, attrnorm);
}

static bool
evequal_attr(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_attr_t *x1 = &e1->attr;
    const xml_reader_cbparam_attr_t *x2 = &e2->attr;

    return x1->attrnorm == x2->attrnorm;
}

#define evprint___dummy     NULL
#define evequal___dummy     NULL
#define evgenc___dummy      NULL
#define XF1(p,s) p##_##s
#define XF(p,s) XF1(p,s)

#define X(t) \
        [XML_READER_CB_##t] = { \
            .print = XF(evprint, FL(t)), \
            .equal = XF(evequal, FL(t)), \
            .gencode = XF(evgenc, FL(t)), \
        },

static const event_t events[] = {
    X(NONE)
    X(MESSAGE)
    X(ENTITY_UNKNOWN)
    X(ENTITY_START)
    X(ENTITY_END)
    X(PUBID)
    X(SYSID)
    X(NDATA)
    X(APPEND)
    X(CDSECT)
    X(XMLDECL)
    X(COMMENT)
    X(PI_TARGET)
    X(PI_CONTENT)
    X(DTD_BEGIN)
    X(DTD_INTERNAL)
    X(DTD_END)
    X(ENTITY_DEF_START)
    X(ENTITY_DEF_END)
    X(NOTATION_DEF_START)
    X(NOTATION_DEF_END)
    X(STAG)
    X(STAG_END)
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
    printf("[%s:%u:%u]", cbparam->loc.src ? cbparam->loc.src : "<undef>",
            cbparam->loc.line, cbparam->loc.pos);
    printf(" %s: ", enum2str(cbparam->cbtype, &enum_cbtype));
    if (cbparam->token.str) {
        // TBD: mixes UTF-8/local encodings
        printf("'%.*s' [%zu] ",
                (int)cbparam->token.len, cbparam->token.str,
                cbparam->token.len);
    }
    if (cbparam->cbtype < sizeofarray(events) && events[cbparam->cbtype].print) {
        events[cbparam->cbtype].print(cbparam);
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
            || !str_null_or_equal(e1->loc.src, e2->loc.src)
            || e1->token.len != e2->token.len
            || memcmp(e1->token.str, e2->token.str, e1->token.len)
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
    char *s;

    printf(INDENT "E(%s,\n", enum2id(cbparam->cbtype, &enum_cbtype, "XML_READER_CB_"));
    s = string_escape(cbparam->loc.src);
    printf(INDENT INDENT "LOC(\"%s\", %u, %u),\n",
            s, cbparam->loc.line, cbparam->loc.pos);
    xfree(s);
    if (cbparam->token.str) {
        s = string_escape_utf8(cbparam->token.str, cbparam->token.len);
        printf(INDENT INDENT "TOK(\"%s\"),\n", s);
        xfree(s);
    }
    else {
        printf(INDENT INDENT "NOTOK,\n");
    }
    if (events[cbparam->cbtype].gencode) {
        events[cbparam->cbtype].gencode(cbparam);
    }
    printf(INDENT "),\n");
}
