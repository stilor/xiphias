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

#define FIELD_TOKEN(x,f) do { \
    if (xml_reader_token_isset(&(x)->f)) { \
        char *s; \
        s = string_escape_utf8((x)->f.str, (x)->f.len); \
        printf(FIELD_FMT(f, "TOK(\"%s\")"), s); \
        xfree(s); \
    } \
    else { \
        printf(FIELD_FMT(f, "NOTOK")); \
    } \
} while (0)

#define FIELD_ENUM(x,f,e) do { \
    printf(FIELD_FMT(f, "%s"), enum2id((x)->f, &enum_##e, NULL)); \
} while (0)

// Supporting functions: print event data

static void
print_token(const char *pfx, const xml_reader_token_t *tk)
{
    char *s;

    if (xml_reader_token_isset(tk)) {
        s = string_escape_unicode_control(tk->str, tk->len);
        printf("  %s: '%s' [%zu]", pfx, s, tk->len);
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

// ENTITY_{UNKNOWN,NOT_LOADED,START,END,DEF}

static void
evprint_entity(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_entity_t *x = &cbparam->entity;

    printf("%s", enum2str(x->type, &enum_reftype));
    print_token("name", &x->name);
    print_token("text", &x->text);
    print_token("sysid", &x->system_id);
    print_token("pubid", &x->public_id);
    print_token("ndata", &x->ndata);
    print_token("n/sysid", &x->nsystem_id);
    print_token("n/pubid", &x->npublic_id);
}

static void
evgenc_entity(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_entity_t *x = &cbparam->entity;

    FIELD_ENUM(x, type, reftype);
    FIELD_TOKEN(x, name);
    FIELD_TOKEN(x, text);
    FIELD_TOKEN(x, system_id);
    FIELD_TOKEN(x, public_id);
    FIELD_TOKEN(x, ndata);
    FIELD_TOKEN(x, nsystem_id);
    FIELD_TOKEN(x, npublic_id);
}

static bool
evequal_entity(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_entity_t *x1 = &e1->entity;
    const xml_reader_cbparam_entity_t *x2 = &e2->entity;

    return x1->type == x2->type
            && equal_token(&x1->name, &x2->name)
            && equal_token(&x1->text, &x2->text)
            && equal_token(&x1->system_id, &x2->system_id)
            && equal_token(&x1->public_id, &x2->public_id)
            && equal_token(&x1->ndata, &x2->ndata)
            && equal_token(&x1->nsystem_id, &x2->nsystem_id)
            && equal_token(&x1->npublic_id, &x2->npublic_id);
}

// NOTATION

static void
evprint_notation(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_notation_t *x = &cbparam->notation;

    print_token("name", &x->name);
    print_token("sysid", &x->system_id);
    print_token("pubid", &x->public_id);
}

static void
evgenc_notation(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_notation_t *x = &cbparam->notation;

    FIELD_TOKEN(x, name);
    FIELD_TOKEN(x, system_id);
    FIELD_TOKEN(x, public_id);
}

static bool
evequal_notation(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_notation_t *x1 = &e1->notation;
    const xml_reader_cbparam_notation_t *x2 = &e2->notation;

    return equal_token(&x1->name, &x2->name)
            && equal_token(&x1->system_id, &x2->system_id)
            && equal_token(&x1->public_id, &x2->public_id);
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

// DTD

static void
evprint_dtd(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_dtd_t *x = &cbparam->dtd;

    print_token("root", &x->root);
    print_token("sysid", &x->system_id);
    print_token("pubid", &x->public_id);
}

static void
evgenc_dtd(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_dtd_t *x = &cbparam->dtd;

    FIELD_TOKEN(x, root);
    FIELD_TOKEN(x, system_id);
    FIELD_TOKEN(x, public_id);
}

static bool
evequal_dtd(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_dtd_t *x1 = &e1->dtd;
    const xml_reader_cbparam_dtd_t *x2 = &e2->dtd;

    return equal_token(&x1->root, &x2->root)
            && equal_token(&x1->system_id, &x2->system_id)
            && equal_token(&x1->public_id, &x2->public_id);
}

// COMMENT

static void
evprint_comment(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_comment_t *x = &cbparam->comment;

    print_token("text", &x->text);
}

static void
evgenc_comment(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_comment_t *x = &cbparam->comment;

    FIELD_TOKEN(x, text);
}

static bool
evequal_comment(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_comment_t *x1 = &e1->comment;
    const xml_reader_cbparam_comment_t *x2 = &e2->comment;

    return equal_token(&x1->text, &x2->text);
}

// PI

static void
evprint_pi(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_pi_t *x = &cbparam->pi;

    print_token("target", &x->target);
    print_token("content", &x->content);
    print_token("n/sysid", &x->nsystem_id);
    print_token("n/pubid", &x->npublic_id);
}

static void
evgenc_pi(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_pi_t *x = &cbparam->pi;

    FIELD_TOKEN(x, target);
    FIELD_TOKEN(x, content);
    FIELD_TOKEN(x, nsystem_id);
    FIELD_TOKEN(x, npublic_id);
}

static bool
evequal_pi(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_pi_t *x1 = &e1->pi;
    const xml_reader_cbparam_pi_t *x2 = &e2->pi;

    return equal_token(&x1->target, &x2->target)
            && equal_token(&x1->content, &x2->content)
            && equal_token(&x1->nsystem_id, &x2->nsystem_id)
            && equal_token(&x1->npublic_id, &x2->npublic_id);
}

// TEXT, CDSECT

static void
evprint_text(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_text_t *x = &cbparam->text;

    print_token("text", &x->text);
    if (x->ws) {
        printf(" (whitespace)");
    }
}

static void
evgenc_text(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_text_t *x = &cbparam->text;

    FIELD_TOKEN(x, text);
    FIELD_BOOL(x, ws);
}

static bool
evequal_text(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_text_t *x1 = &e1->text;
    const xml_reader_cbparam_text_t *x2 = &e2->text;

    return equal_token(&x1->text, &x2->text)
            && x1->ws == x2->ws;
}

// STAG/ETAG

static void
evprint_tag(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_tag_t *x = &cbparam->tag;

    print_token("name", &x->name);
}

static void
evgenc_tag(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_tag_t *x = &cbparam->tag;

    FIELD_TOKEN(x, name);
}

static bool
evequal_tag(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_tag_t *x1 = &e1->tag;
    const xml_reader_cbparam_tag_t *x2 = &e2->tag;

    return equal_token(&x1->name, &x2->name);
}

// ATTR

static void
evprint_attr(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_attr_t *x = &cbparam->attr;

    print_token("name", &x->name);
    print_token("value", &x->value);
}

static void
evgenc_attr(const xml_reader_cbparam_t *cbparam)
{
    const xml_reader_cbparam_attr_t *x = &cbparam->attr;

    FIELD_TOKEN(x, name);
    FIELD_TOKEN(x, value);
}

static bool
evequal_attr(const xml_reader_cbparam_t *e1, const xml_reader_cbparam_t *e2)
{
    const xml_reader_cbparam_attr_t *x1 = &e1->attr;
    const xml_reader_cbparam_attr_t *x2 = &e2->attr;

    return equal_token(&x1->name, &x2->name)
            && equal_token(&x1->value, &x2->value);
}


#define evprint___dummy     NULL
#define evequal___dummy     NULL
#define evgenc___dummy      NULL

#define X(t) \
        [XML_READER_CB_##t] = { \
            .print = concat(evprint_, FL(t)), \
            .equal = concat(evequal_, FL(t)), \
            .gencode = concat(evgenc_, FL(t)), \
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
    X(DTD_END_INTERNAL)
    X(DTD_END)
    X(COMMENT)
    X(PI)
    X(ENTITY_DEF)
    X(NOTATION_DEF)
    X(TEXT)
    X(CDSECT)
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
    printf("[%s:%u:%u]", cbparam->loc.src ? cbparam->loc.src : "<undef>",
            cbparam->loc.line, cbparam->loc.pos);
    printf(" %s: ", enum2str(cbparam->cbtype, &enum_cbtype));
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
    if (cbparam->loc.src) {
        s = string_escape(cbparam->loc.src);
        printf(INDENT INDENT "LOC(\"%s\", %u, %u),\n",
                s, cbparam->loc.line, cbparam->loc.pos);
        xfree(s);
    }
    else {
        printf(INDENT INDENT "LOC(NULL, %u, %u),\n",
                cbparam->loc.line, cbparam->loc.pos);
    }
    if (events[cbparam->cbtype].gencode) {
        events[cbparam->cbtype].gencode(cbparam);
    }
    printf(INDENT "),\n");
}
