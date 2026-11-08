/* OpenGDS Auditor - plan files (plan.h, docs/auditor/plan-files.md).
 *
 * The file format is a subset of TOML v1.0.0: comments, top-level keys,
 * the tables [target], [identity], [tests], [hooks] and [report], bare keys,
 * basic and literal strings, decimal integers, booleans and arrays of
 * strings (which may span lines). Anything else (floats, dates, inline or
 * nested tables, multi-line strings, dotted or quoted keys) is refused with
 * the line number, so a plan never means something the Auditor did not
 * read. Every key is checked against the plan's profile.
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "gdsaudit/plan.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/banned.h"

/* ---- keys ---- */

enum { P_SERVER = 0, P_CLIENT, P_GDS, P_COUNT };
static const char *const profileNames[P_COUNT] = {"server", "client", "gds"};

typedef struct {
    const char *key;
    const char *opt[P_COUNT]; /* server, client, gds; NULL: not for that profile */
    ga_plan_type type;
} key_row;

#define ALL(o) {o, o, o}

/* Order: the order of the options on the command line and in a saved
 * file. The client's trigger (after "--") stays last. */
static const key_row keys[] = {
    {"target.url", {"--url", NULL, "--url"}, GA_PLAN_STRING},
    {"target.server_cert", {"--server-cert", NULL, NULL}, GA_PLAN_PATH},
    {"target.tofu", {"--tofu", NULL, NULL}, GA_PLAN_BOOL},
    {"target.trust", {"--target-trust", NULL, "--trust"}, GA_PLAN_PATHS},
    {"target.crl", {"--target-crl", NULL, "--crl"}, GA_PLAN_PATHS},
    {"target.listen", {NULL, "--listen", NULL}, GA_PLAN_INT},
    {"target.listen_any", {NULL, "--listen-any", NULL}, GA_PLAN_BOOL},
    {"identity.work", ALL("--work"), GA_PLAN_PATH},
    {"identity.admin_cert", {"--admin-cert", NULL, NULL}, GA_PLAN_PATH},
    {"identity.admin_key", {"--admin-key", NULL, NULL}, GA_PLAN_PATH},
    {"identity.admin_user", {"--admin-user", NULL, NULL}, GA_PLAN_STRING},
    {"identity.admin_password_file", {"--admin-password-file", NULL, NULL}, GA_PLAN_PATH},
    {"identity.user", {"--user", NULL, "--user"}, GA_PLAN_STRING},
    {"identity.password_file", {"--user-password-file", NULL, "--password-file"}, GA_PLAN_PATH},
    {"identity.client_user", {NULL, "--user", NULL}, GA_PLAN_STRING},
    {"tests.allow_changes", {"--allow-changes", NULL, "--allow-changes"}, GA_PLAN_BOOL},
    {"tests.only", ALL("--only"), GA_PLAN_STRING},
    {"tests.slow", {"--slow", "--slow", NULL}, GA_PLAN_BOOL},
    {"tests.expect", ALL("--expect"), GA_PLAN_PATH},
    {"tests.stop_after", {"--stop-after", NULL, NULL}, GA_PLAN_STRING},
    {"tests.settle_timeout", {"--settle-timeout", NULL, NULL}, GA_PLAN_INT},
    {"tests.poll_seconds", {NULL, NULL, "--poll-seconds"}, GA_PLAN_INT},
    {"tests.cycle_timeout", {NULL, "--cycle-timeout", NULL}, GA_PLAN_INT},
    {"tests.cycle_period", {NULL, "--cycle-period", NULL}, GA_PLAN_INT},
    {"report.dir", ALL("--report"), GA_PLAN_PATH},
    {"report.events", ALL("--events"), GA_PLAN_PATH},
    {"hooks.trigger", {NULL, "--", NULL}, GA_PLAN_COMMAND},
};
#define NKEYS (sizeof(keys) / sizeof(keys[0]))

static const char *const tables[] = {"target", "identity", "tests", "hooks", "report"};
#define NTABLES (sizeof(tables) / sizeof(tables[0]))

static const char *const presets[] = {"quick", "full", "certification"};

typedef struct {
    char **v;
    size_t n;
} values;

struct ga_plan {
    int profile;
    char *name, *preset;
    values vals[NKEYS];
};

static int profile_index(const char *name) {
    for(int i = 0; name && i < P_COUNT; i++)
        if(strcmp(name, profileNames[i]) == 0)
            return i;
    return -1;
}

static int key_index(int profile, const char *key) {
    for(size_t i = 0; key && profile >= 0 && i < NKEYS; i++)
        if(strcmp(keys[i].key, key) == 0)
            return keys[i].opt[profile] ? (int)i : -1;
    return -1;
}

static bool is_array(ga_plan_type t) {
    return t == GA_PLAN_PATHS || t == GA_PLAN_COMMAND;
}

bool ga_plan_key_type(const char *profile, const char *key, ga_plan_type *type) {
    int k = key_index(profile_index(profile), key);
    if(k < 0)
        return false;
    if(type)
        *type = keys[k].type;
    return true;
}

const char *ga_plan_key_option(const char *profile, const char *key) {
    int p = profile_index(profile);
    int k = key_index(p, key);
    return k < 0 ? NULL : keys[k].opt[p];
}

/* ---- the plan ---- */

ga_plan *ga_plan_new(const char *profile) {
    int p = profile_index(profile);
    if(p < 0)
        return NULL;
    ga_plan *plan = calloc(1, sizeof(*plan));
    if(plan)
        plan->profile = p;
    return plan;
}

static void values_clear(values *v) {
    for(size_t i = 0; i < v->n; i++)
        free(v->v[i]);
    free((void *)v->v);
    v->v = NULL;
    v->n = 0;
}

void ga_plan_free(ga_plan *p) {
    if(!p)
        return;
    for(size_t i = 0; i < NKEYS; i++)
        values_clear(&p->vals[i]);
    free(p->name);
    free(p->preset);
    free(p);
}

const char *ga_plan_profile(const ga_plan *p) {
    return profileNames[p->profile];
}

const char *ga_plan_name(const ga_plan *p) {
    return p->name;
}

const char *ga_plan_preset(const ga_plan *p) {
    return p->preset;
}

static bool replace_str(char **dst, const char *src) {
    char *copy = NULL;
    if(src && !(copy = strdup(src)))
        return false;
    free(*dst);
    *dst = copy;
    return true;
}

bool ga_plan_set_name(ga_plan *p, const char *name) {
    if(name && strlen(name) > GA_PLAN_MAX_VALUE)
        return false;
    return replace_str(&p->name, name && *name ? name : NULL);
}

static bool known_preset(const char *s) {
    for(size_t i = 0; i < sizeof(presets) / sizeof(presets[0]); i++)
        if(strcmp(s, presets[i]) == 0)
            return true;
    return false;
}

bool ga_plan_set_preset(ga_plan *p, const char *preset) {
    if(preset && *preset && !known_preset(preset))
        return false;
    return replace_str(&p->preset, preset && *preset ? preset : NULL);
}

/* TOML decimal integer: [+-]?(0|[1-9][0-9]*), at most 18 digits */
static bool valid_int(const char *s) {
    if(*s == '+' || *s == '-')
        s++;
    size_t n = strspn(s, "0123456789");
    return n > 0 && n <= 18 && s[n] == '\0' && !(s[0] == '0' && n > 1);
}

static bool valid_value(ga_plan_type t, const char *v) {
    if(!v || !*v || strlen(v) > GA_PLAN_MAX_VALUE)
        return false;
    if(t == GA_PLAN_BOOL)
        return strcmp(v, "true") == 0 || strcmp(v, "false") == 0;
    if(t == GA_PLAN_INT)
        return valid_int(v);
    return true;
}

static bool append(values *vs, const char *v) {
    if(vs->n >= GA_PLAN_MAX_ITEMS)
        return false;
    char **grown = (char **)realloc((void *)vs->v, (vs->n + 1) * sizeof(*grown));
    if(!grown)
        return false;
    vs->v = grown;
    if(!(vs->v[vs->n] = strdup(v)))
        return false;
    vs->n++;
    return true;
}

bool ga_plan_set(ga_plan *p, const char *key, const char *value) {
    int k = key_index(p->profile, key);
    if(k < 0 || !valid_value(keys[k].type, value))
        return false;
    values fresh = {NULL, 0};
    if(!append(&fresh, value)) {
        values_clear(&fresh);
        return false;
    }
    values_clear(&p->vals[k]);
    p->vals[k] = fresh;
    return true;
}

bool ga_plan_add(ga_plan *p, const char *key, const char *value) {
    int k = key_index(p->profile, key);
    return k >= 0 && is_array(keys[k].type) && valid_value(keys[k].type, value) &&
           append(&p->vals[k], value);
}

void ga_plan_unset(ga_plan *p, const char *key) {
    int k = key_index(p->profile, key);
    if(k >= 0)
        values_clear(&p->vals[k]);
}

size_t ga_plan_count(const ga_plan *p, const char *key) {
    int k = key_index(p->profile, key);
    return k < 0 ? 0 : p->vals[k].n;
}

const char *ga_plan_get(const ga_plan *p, const char *key, size_t i) {
    int k = key_index(p->profile, key);
    return k < 0 || i >= p->vals[k].n ? NULL : p->vals[k].v[i];
}

/* ---- parser ---- */

typedef struct {
    const char *p, *end;
    unsigned line;
    const char *name;
    char *err;
    size_t errLen;
    bool failed;
} cursor;

static bool fail(cursor *c, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static bool fail(cursor *c, const char *fmt, ...) {
    if(c->failed)
        return false;
    c->failed = true;
    char why[200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(why, sizeof(why), fmt, ap); /* NOLINT(clang-analyzer-valist.Uninitialized): va_start above */
    va_end(ap);
    snprintf(c->err, c->errLen, "%s:%u: %s", c->name, c->line, why);
    return false;
}

static bool at_end(const cursor *c) {
    return c->p >= c->end;
}

static void skip_ws(cursor *c) {
    while(!at_end(c) && (*c->p == ' ' || *c->p == '\t'))
        c->p++;
}

static void skip_comment(cursor *c) {
    if(!at_end(c) && *c->p == '#')
        while(!at_end(c) && *c->p != '\n')
            c->p++;
}

/* After a value or a header: spaces, an optional comment, then the end of
 * the line (consumed) or of the text. */
static bool end_of_line(cursor *c) {
    skip_ws(c);
    skip_comment(c);
    if(at_end(c))
        return true;
    if(*c->p == '\r' && c->p + 1 < c->end && c->p[1] == '\n')
        c->p++;
    if(*c->p != '\n')
        return fail(c, "unexpected text after the value");
    c->p++;
    c->line++;
    return true;
}

/* Blank lines and comment lines, also inside arrays. */
static void skip_blank(cursor *c) {
    for(;;) {
        skip_ws(c);
        skip_comment(c);
        if(at_end(c))
            return;
        if(*c->p == '\r' && c->p + 1 < c->end && c->p[1] == '\n')
            c->p++;
        if(*c->p != '\n')
            return;
        c->p++;
        c->line++;
    }
}

static bool bare_key_char(char ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
           ch == '_' || ch == '-';
}

static bool read_key(cursor *c, char *out, size_t outLen) {
    size_t n = 0;
    while(!at_end(c) && bare_key_char(*c->p)) {
        if(n + 1 >= outLen)
            return fail(c, "key too long");
        out[n++] = *c->p++;
    }
    out[n] = '\0';
    if(n == 0)
        return fail(c, "expected a bare key (quoted and dotted keys are not supported)");
    return true;
}

typedef struct {
    char *s;
    size_t n, cap;
} sbuf;

static bool sb_put(cursor *c, sbuf *b, const char *bytes, size_t len) {
    if(b->n + len > GA_PLAN_MAX_VALUE)
        return fail(c, "string longer than %d bytes", GA_PLAN_MAX_VALUE);
    if(b->n + len + 1 > b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 64;
        while(cap < b->n + len + 1)
            cap *= 2;
        char *grown = realloc(b->s, cap);
        if(!grown)
            return fail(c, "out of memory");
        b->s = grown;
        b->cap = cap;
    }
    memcpy(b->s + b->n, bytes, len);
    b->n += len;
    b->s[b->n] = '\0';
    return true;
}

static int hexval(char ch) {
    if(ch >= '0' && ch <= '9')
        return ch - '0';
    if(ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if(ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return -1;
}

static size_t utf8_encode(uint32_t cp, char *o) {
    if(cp < 0x80) {
        o[0] = (char)cp;
        return 1;
    }
    if(cp < 0x800) {
        o[0] = (char)(0xc0 | (cp >> 6));
        o[1] = (char)(0x80 | (cp & 0x3f));
        return 2;
    }
    if(cp < 0x10000) {
        o[0] = (char)(0xe0 | (cp >> 12));
        o[1] = (char)(0x80 | ((cp >> 6) & 0x3f));
        o[2] = (char)(0x80 | (cp & 0x3f));
        return 3;
    }
    o[0] = (char)(0xf0 | (cp >> 18));
    o[1] = (char)(0x80 | ((cp >> 12) & 0x3f));
    o[2] = (char)(0x80 | ((cp >> 6) & 0x3f));
    o[3] = (char)(0x80 | (cp & 0x3f));
    return 4;
}

/* \uXXXX or \UXXXXXXXX: a Unicode scalar value (TOML 1.0.0) */
static bool unicode_escape(cursor *c, sbuf *b, size_t digits) {
    if((size_t)(c->end - c->p) < digits)
        return fail(c, "short \\u escape");
    uint32_t cp = 0;
    for(size_t i = 0; i < digits; i++) {
        int h = hexval(c->p[i]);
        if(h < 0)
            return fail(c, "bad \\u escape");
        cp = (cp << 4) | (uint32_t)h;
    }
    c->p += digits;
    if(cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
        return fail(c, "\\u escape is not a Unicode scalar value");
    if(cp == 0)
        return fail(c, "NUL is not allowed in plan strings");
    char o[4];
    return sb_put(c, b, o, utf8_encode(cp, o));
}

static bool basic_escape(cursor *c, sbuf *b) {
    if(at_end(c))
        return fail(c, "unterminated string");
    char e = *c->p++;
    const char *simple = NULL;
    switch(e) {
    case 'b': simple = "\b"; break;
    case 't': simple = "\t"; break;
    case 'n': simple = "\n"; break;
    case 'f': simple = "\f"; break;
    case 'r': simple = "\r"; break;
    case '"': simple = "\""; break;
    case '\\': simple = "\\"; break;
    case 'u': return unicode_escape(c, b, 4);
    case 'U': return unicode_escape(c, b, 8);
    default: return fail(c, "unknown escape \\%c", e);
    }
    return sb_put(c, b, simple, 1);
}

/* A basic ("...") or literal ('...') string on one line; *out is malloc'd. */
static bool read_string(cursor *c, char **out) {
    char quote = *c->p;
    if(c->end - c->p >= 3 && c->p[1] == quote && c->p[2] == quote)
        return fail(c, "multi-line strings are not supported in plan files");
    c->p++;
    sbuf b = {NULL, 0, 0};
    for(;;) {
        if(at_end(c) || *c->p == '\n') {
            free(b.s);
            return fail(c, "unterminated string");
        }
        unsigned char ch = (unsigned char)*c->p++;
        bool ok;
        if(ch == (unsigned char)quote)
            break;
        if(ch == '\\' && quote == '"')
            ok = basic_escape(c, &b);
        else if((ch < 0x20 && ch != '\t') || ch == 0x7f)
            ok = fail(c, "control character in a string (use an escape)");
        else
            ok = sb_put(c, &b, (const char *)&ch, 1);
        if(!ok) {
            free(b.s);
            return false;
        }
    }
    if(!b.s && !sb_put(c, &b, "", 0))
        return false;
    *out = b.s;
    return true;
}

typedef enum { V_STRING, V_INT, V_BOOL, V_ARRAY } value_kind;

typedef struct {
    value_kind kind;
    values items; /* one item for a scalar */
} parsed;

static bool push(cursor *c, parsed *v, char *s) {
    if(v->items.n >= GA_PLAN_MAX_ITEMS) {
        free(s);
        return fail(c, "array with more than %d items", GA_PLAN_MAX_ITEMS);
    }
    char **grown = (char **)realloc((void *)v->items.v, (v->items.n + 1) * sizeof(*grown));
    if(!grown) {
        free(s);
        return fail(c, "out of memory");
    }
    v->items.v = grown;
    v->items.v[v->items.n++] = s;
    return true;
}

static bool read_array(cursor *c, parsed *v) {
    unsigned startLine = c->line;
    c->p++; /* [ */
    v->kind = V_ARRAY;
    for(;;) {
        skip_blank(c);
        if(at_end(c)) {
            c->line = startLine;
            return fail(c, "unterminated array");
        }
        if(*c->p == ']') {
            c->p++;
            return true;
        }
        if(*c->p != '"' && *c->p != '\'')
            return fail(c, "arrays in plan files hold strings only");
        char *s = NULL;
        if(!read_string(c, &s) || !push(c, v, s))
            return false;
        skip_blank(c);
        if(!at_end(c) && *c->p == ',')
            c->p++;
        else if(at_end(c) || *c->p != ']') {
            c->line = at_end(c) ? startLine : c->line;
            return fail(c, at_end(c) ? "unterminated array" : "expected ',' or ']' in the array");
        }
    }
}

static bool read_scalar_token(cursor *c, parsed *v) {
    char tok[32];
    size_t n = 0;
    while(!at_end(c) && n + 1 < sizeof(tok) && *c->p != ' ' && *c->p != '\t' &&
          *c->p != '\n' && *c->p != '\r' && *c->p != '#')
        tok[n++] = *c->p++;
    tok[n] = '\0';
    if(strcmp(tok, "true") == 0 || strcmp(tok, "false") == 0)
        v->kind = V_BOOL;
    else if(valid_int(tok))
        v->kind = V_INT;
    else if(n == 0)
        return fail(c, "missing value");
    else
        return fail(c, "unsupported value '%s' (plan files take strings, integers, "
                       "true/false and arrays of strings)", tok);
    char *s = strdup(tok[0] == '+' ? tok + 1 : tok);
    if(!s)
        return fail(c, "out of memory");
    return push(c, v, s);
}

static bool read_value(cursor *c, parsed *v) {
    memset(v, 0, sizeof(*v));
    skip_ws(c);
    if(at_end(c))
        return fail(c, "missing value");
    if(*c->p == '"' || *c->p == '\'') {
        char *s = NULL;
        v->kind = V_STRING;
        return read_string(c, &s) && push(c, v, s);
    }
    if(*c->p == '[')
        return read_array(c, v);
    if(*c->p == '{')
        return fail(c, "inline tables are not supported in plan files");
    return read_scalar_token(c, v);
}

typedef struct {
    ga_plan *plan;
    int table;       /* -1: top level */
    bool seenTable[NTABLES];
    bool seenTop[5]; /* schema, version, profile, name, preset */
    bool seenKey[NKEYS];
} parse_state;

static bool top_level(cursor *c, parse_state *st, const char *key, parsed *v) {
    static const char *const names[] = {"schema", "version", "profile", "name", "preset"};
    size_t i = 0;
    while(i < 5 && strcmp(key, names[i]) != 0)
        i++;
    if(i == 5)
        return fail(c, "unknown top-level key '%s'", key);
    if(st->seenTop[i])
        return fail(c, "'%s' is set twice", key);
    st->seenTop[i] = true;
    const char *s = v->items.v[0];
    if(i == 1) {
        if(v->kind != V_INT || strcmp(s, "1") != 0)
            return fail(c, "plan version %s is not supported (this Auditor reads version %d)", s,
                        GA_PLAN_VERSION);
        return true;
    }
    if(v->kind != V_STRING)
        return fail(c, "'%s' must be a string", key);
    if(i == 0)
        return strcmp(s, GA_PLAN_SCHEMA) == 0 ? true : fail(c, "schema must be \"%s\"", GA_PLAN_SCHEMA);
    if(i == 2) {
        if(!(st->plan = ga_plan_new(s)))
            return fail(c, "unknown profile '%s' (server, client or gds)", s);
        return true;
    }
    if(!st->plan)
        return fail(c, "'profile' must come first");
    if(i == 3)
        return ga_plan_set_name(st->plan, s) ? true : fail(c, "bad name");
    return ga_plan_set_preset(st->plan, s) ? true
                                           : fail(c, "unknown preset '%s' (quick, full or certification)", s);
}

static bool kind_fits(ga_plan_type t, value_kind k) {
    switch(t) {
    case GA_PLAN_STRING:
    case GA_PLAN_PATH: return k == V_STRING;
    case GA_PLAN_BOOL: return k == V_BOOL;
    case GA_PLAN_INT: return k == V_INT;
    case GA_PLAN_PATHS:
    case GA_PLAN_COMMAND: return k == V_ARRAY;
    }
    return false;
}

static const char *type_name(ga_plan_type t) {
    static const char *const n[] = {"a string", "a path string", "true or false", "an integer",
                                     "an array of paths", "an array of strings (the command)"};
    return n[t];
}

static bool table_key(cursor *c, parse_state *st, const char *key, parsed *v) {
    char full[96];
    snprintf(full, sizeof(full), "%s.%s", tables[st->table], key);
    int k = key_index(st->plan->profile, full);
    if(k < 0)
        return fail(c, "unknown key %s for profile %s", full, ga_plan_profile(st->plan));
    if(st->seenKey[k])
        return fail(c, "%s is set twice", full);
    st->seenKey[k] = true;
    if(!kind_fits(keys[k].type, v->kind))
        return fail(c, "%s must be %s", full, type_name(keys[k].type));
    if(keys[k].type == GA_PLAN_COMMAND && v->items.n == 0)
        return fail(c, "%s must name a command", full);
    for(size_t i = 0; i < v->items.n; i++)
        if(!valid_value(keys[k].type, v->items.v[i]))
            return fail(c, "%s: empty value", full);
    values_clear(&st->plan->vals[k]);
    st->plan->vals[k] = v->items; /* moved */
    v->items.v = NULL;
    v->items.n = 0;
    return true;
}

static bool header(cursor *c, parse_state *st) {
    c->p++; /* [ */
    if(!at_end(c) && *c->p == '[')
        return fail(c, "arrays of tables are not supported in plan files");
    skip_ws(c);
    char name[32];
    if(!read_key(c, name, sizeof(name)))
        return false;
    skip_ws(c);
    if(at_end(c) || *c->p != ']')
        return fail(c, "expected ']' (nested and dotted tables are not supported)");
    c->p++;
    if(!st->plan)
        return fail(c, "'profile' must be set before the first table");
    size_t t = 0;
    while(t < NTABLES && strcmp(name, tables[t]) != 0)
        t++;
    if(t == NTABLES)
        return fail(c, "unknown table [%s] (target, identity, tests, hooks, report)", name);
    if(st->seenTable[t])
        return fail(c, "table [%s] appears twice", name);
    st->seenTable[t] = true;
    st->table = (int)t;
    return end_of_line(c);
}

static bool key_value(cursor *c, parse_state *st) {
    char key[64];
    if(!read_key(c, key, sizeof(key)))
        return false;
    skip_ws(c);
    if(at_end(c) || *c->p != '=')
        return fail(c, "expected '=' after %s", key);
    c->p++;
    unsigned line = c->line;
    parsed v;
    bool ok = read_value(c, &v);
    if(ok) {
        unsigned after = c->line;
        c->line = line; /* errors about the key name its line */
        ok = st->table < 0 ? top_level(c, st, key, &v) : table_key(c, st, key, &v);
        c->line = after;
    }
    values_clear(&v.items);
    return ok && end_of_line(c);
}

ga_plan *ga_plan_parse(const char *text, size_t len, const char *name, char *err,
                       size_t errLen) {
    cursor c = {text, text + len, 1, name ? name : "plan", err, errLen, false};
    if(len > GA_PLAN_MAX_FILE) {
        snprintf(err, errLen, "%s: larger than %zu bytes", c.name, GA_PLAN_MAX_FILE);
        return NULL;
    }
    if(memchr(text, '\0', len)) {
        snprintf(err, errLen, "%s: holds a NUL byte", c.name);
        return NULL;
    }
    parse_state st;
    memset(&st, 0, sizeof(st));
    st.table = -1;
    bool ok = true;
    for(;;) {
        skip_blank(&c);
        if(at_end(&c))
            break;
        ok = *c.p == '[' ? header(&c, &st) : key_value(&c, &st);
        if(!ok)
            break;
    }
    if(ok && !st.plan) {
        c.line = 1;
        ok = fail(&c, "no profile (server, client or gds)");
    }
    if(!ok) {
        ga_plan_free(st.plan);
        return NULL;
    }
    return st.plan;
}

ga_plan *ga_plan_load(const char *path, char *err, size_t errLen) {
    FILE *f = fopen(path, "rb");
    if(!f) {
        snprintf(err, errLen, "%s: %s", path, strerror(errno));
        return NULL;
    }
    char *buf = malloc(GA_PLAN_MAX_FILE + 1);
    size_t n = buf ? fread(buf, 1, GA_PLAN_MAX_FILE + 1, f) : 0;
    bool readErr = ferror(f) != 0;
    fclose(f);
    if(!buf || readErr) {
        snprintf(err, errLen, "%s: %s", path, buf ? "read error" : "out of memory");
        free(buf);
        return NULL;
    }
    ga_plan *p = ga_plan_parse(buf, n, path, err, errLen);
    free(buf);
    return p;
}

/* ---- writer ---- */

static void put_toml_string(FILE *f, const char *s) {
    fputc('"', f);
    for(const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch(*p) {
        case '"': fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\b': fputs("\\b", f); break;
        case '\t': fputs("\\t", f); break;
        case '\n': fputs("\\n", f); break;
        case '\f': fputs("\\f", f); break;
        case '\r': fputs("\\r", f); break;
        default:
            if(*p < 0x20 || *p == 0x7f)
                fprintf(f, "\\u%04x", *p);
            else
                fputc(*p, f);
        }
    }
    fputc('"', f);
}

static void write_value(FILE *f, ga_plan_type ty, const values *v) {
    if(is_array(ty)) {
        fputc('[', f);
        for(size_t i = 0; i < v->n; i++) {
            if(i)
                fputs(", ", f);
            put_toml_string(f, v->v[i]);
        }
        fputs("]\n", f);
    } else if(ty == GA_PLAN_BOOL || ty == GA_PLAN_INT) {
        fprintf(f, "%s\n", v->v[0]);
    } else {
        put_toml_string(f, v->v[0]);
        fputc('\n', f);
    }
}

static void write_table(const ga_plan *p, FILE *f, const char *table) {
    size_t tl = strlen(table);
    bool opened = false;
    for(size_t k = 0; k < NKEYS; k++) {
        if(p->vals[k].n == 0 || strncmp(keys[k].key, table, tl) != 0 || keys[k].key[tl] != '.')
            continue;
        if(!opened)
            fprintf(f, "\n[%s]\n", table);
        opened = true;
        fprintf(f, "%s = ", keys[k].key + tl + 1);
        write_value(f, keys[k].type, &p->vals[k]);
    }
}

bool ga_plan_write(const ga_plan *p, FILE *f) {
    fputs("# OpenGDS Auditor plan (docs/auditor/plan-files.md).\n"
          "# Run it with: gdsaudit run THIS-FILE. Relative paths are relative to this file.\n",
          f);
    fprintf(f, "schema = \"%s\"\nversion = %d\nprofile = \"%s\"\n", GA_PLAN_SCHEMA,
            GA_PLAN_VERSION, ga_plan_profile(p));
    if(p->name) {
        fputs("name = ", f);
        put_toml_string(f, p->name);
        fputc('\n', f);
    }
    if(p->preset)
        fprintf(f, "preset = \"%s\"\n", p->preset);
    for(size_t t = 0; t < NTABLES; t++)
        write_table(p, f, tables[t]);
    return !ferror(f);
}

bool ga_plan_save(const ga_plan *p, const char *path, char *err, size_t errLen) {
    char tmp[4200];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if(n < 0 || (size_t)n >= sizeof(tmp)) {
        snprintf(err, errLen, "plan path too long");
        return false;
    }
    FILE *f = fopen(tmp, "w");
    if(!f) {
        snprintf(err, errLen, "%s: %s", tmp, strerror(errno));
        return false;
    }
    bool ok = ga_plan_write(p, f);
    ok = (fclose(f) == 0) && ok;
    if(!ok || rename(tmp, path) != 0) {
        snprintf(err, errLen, "%s: %s", path, ok ? strerror(errno) : "write failed");
        unlink(tmp);
        return false;
    }
    return true;
}

/* ---- command line ---- */

static bool is_absolute(const char *s) {
    return s[0] == '/' || s[0] == '\\' ||
           (((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) && s[1] == ':');
}

/* Whether value i of key k is joined to the base folder. */
static bool joins(const key_row *k, size_t i, const char *v) {
    if(k->type == GA_PLAN_PATH || k->type == GA_PLAN_PATHS)
        return !is_absolute(v);
    if(k->type == GA_PLAN_COMMAND)
        return i == 0 && strchr(v, '/') && !is_absolute(v);
    return false;
}

typedef struct {
    char **argv;
    char *strs;
    size_t argc, used;
} argv_out;

/* With out->argv NULL only counts. */
static void emit(argv_out *o, const char *a, const char *b) {
    size_t la = strlen(a), lb = b ? strlen(b) + 1 : 0;
    if(o->argv) {
        char *s = o->strs + o->used;
        memcpy(s, a, la);
        if(b) {
            s[la] = '/';
            memcpy(s + la + 1, b, lb - 1);
        }
        s[la + lb] = '\0';
        o->argv[o->argc] = s;
    }
    o->argc++;
    o->used += la + lb + 1;
}

/* The options one key gives. */
static void build_key(const ga_plan *p, const key_row *row, const values *v, const char *base,
                      argv_out *o) {
    const char *opt = row->opt[p->profile];
    if(row->type == GA_PLAN_BOOL) {
        if(strcmp(v->v[0], "true") == 0)
            emit(o, opt, NULL);
        return;
    }
    if(row->type == GA_PLAN_COMMAND)
        emit(o, "--", NULL);
    for(size_t i = 0; i < v->n; i++) {
        if(row->type != GA_PLAN_COMMAND && (i == 0 || row->type == GA_PLAN_PATHS))
            emit(o, opt, NULL);
        bool j = base && joins(row, i, v->v[i]);
        emit(o, j ? base : v->v[i], j ? v->v[i] : NULL);
    }
}

static void build(const ga_plan *p, const char *base, argv_out *o) {
    if(base && !*base)
        base = NULL;
    emit(o, ga_plan_profile(p), NULL);
    for(int pass = 0; pass < 2; pass++) { /* the trigger after "--" goes last */
        for(size_t k = 0; k < NKEYS; k++) {
            const key_row *row = &keys[k];
            bool last = row->type == GA_PLAN_COMMAND;
            if(p->vals[k].n > 0 && row->opt[p->profile] && last == (pass == 1))
                build_key(p, row, &p->vals[k], base, o);
        }
    }
}

char **ga_plan_argv(const ga_plan *p, const char *baseDir, int *argc) {
    argv_out count = {NULL, NULL, 0, 0};
    build(p, baseDir, &count);
    size_t ptrs = (count.argc + 1) * sizeof(char *);
    char **argv = (char **)malloc(ptrs + count.used);
    if(!argv)
        return NULL;
    argv_out o = {argv, (char *)argv + ptrs, 0, 0};
    build(p, baseDir, &o);
    argv[o.argc] = NULL;
    if(argc)
        *argc = (int)o.argc;
    return argv;
}
