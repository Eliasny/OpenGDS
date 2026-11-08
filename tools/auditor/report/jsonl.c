/* OpenGDS Auditor - the event stream as JSON Lines (schema in engine.h).
 *
 * The writer emits valid UTF-8 JSON whatever the evidence holds (bytes from
 * the target are not trusted to be UTF-8). The parser reads only what the
 * writer can produce plus unknown keys of any JSON type, so newer engines
 * stay readable; it has fixed limits and never recurses deeper than
 * GA_JSON_DEPTH.
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "results.h"

#include "common/banned.h"

#define GA_JSON_DEPTH 16

/* ---- writer ---- */

/* Length of the valid UTF-8 sequence at s (max n bytes), or 0. */
static size_t utf8_len(const unsigned char *s, size_t n) {
    unsigned char c = s[0];
    size_t len;
    uint32_t cp;
    if(c < 0x80)
        return 1;
    if(c >= 0xc2 && c <= 0xdf) {
        len = 2;
        cp = c & 0x1fu;
    } else if(c >= 0xe0 && c <= 0xef) {
        len = 3;
        cp = c & 0x0fu;
    } else if(c >= 0xf0 && c <= 0xf4) {
        len = 4;
        cp = c & 0x07u;
    } else {
        return 0;
    }
    if(len > n)
        return 0;
    for(size_t i = 1; i < len; i++) {
        if((s[i] & 0xc0) != 0x80)
            return 0;
        cp = (cp << 6) | (s[i] & 0x3fu);
    }
    if((len == 3 && cp < 0x800) || (len == 4 && (cp < 0x10000 || cp > 0x10ffff)) ||
       (cp >= 0xd800 && cp <= 0xdfff))
        return 0;
    return len;
}

void ga_json_put_string(FILE *f, const char *s) {
    fputc('"', f);
    const unsigned char *p = (const unsigned char *)(s ? s : "");
    size_t n = strlen((const char *)p);
    while(n > 0) {
        unsigned char c = *p;
        if(c == '"' || c == '\\') {
            fputc('\\', f);
            fputc(c, f);
        } else if(c == '\n') {
            fputs("\\n", f);
        } else if(c < 0x20 || c == 0x7f) {
            fprintf(f, "\\u%04x", c);
        } else if(c >= 0x80) {
            size_t len = utf8_len(p, n);
            if(len == 0) {
                fputs("\\ufffd", f); /* not UTF-8: replacement character */
                len = 1;
            } else {
                fwrite(p, 1, len, f);
            }
            p += len;
            n -= len;
            continue;
        } else {
            fputc(c, f);
        }
        p++;
        n--;
    }
    fputc('"', f);
}

static void put_key_str(FILE *f, const char *key, const char *val) {
    fprintf(f, ",\"%s\":", key);
    ga_json_put_string(f, val);
}

/* By ga_event_kind */
static const char *const kinds[] = {"run_started", "test_started", "note",
                                    "verdict",     "run_finished", "paused",
                                    "resumed",     "prompt",       "prompt_answered"};

bool ga_jsonl_write(FILE *f, const ga_event *ev) {
    if((size_t)ev->kind >= sizeof(kinds) / sizeof(kinds[0]))
        return false;
    fprintf(f, "{\"v\":%d,\"ev\":\"%s\"", GA_EVENTS_SCHEMA, kinds[ev->kind]);
    switch(ev->kind) {
    case GA_EV_RUN_STARTED:
        put_key_str(f, "profile", ev->profile);
        put_key_str(f, "target", ev->target);
        fprintf(f, ",\"planned\":%zu,\"allow_changes\":%s", ev->planned,
                ev->allowChanges ? "true" : "false");
        put_key_str(f, "time", ev->time);
        break;
    case GA_EV_TEST_STARTED:
        fprintf(f, ",\"n\":%zu", ev->n);
        put_key_str(f, "id", ev->id);
        put_key_str(f, "clause", ev->clause);
        put_key_str(f, "title", ev->title);
        fprintf(f, ",\"changes\":%s,\"operator\":%s", ev->needsWrite ? "true" : "false",
                ev->needsOperator ? "true" : "false");
        break;
    case GA_EV_NOTE:
        fprintf(f, ",\"n\":%zu", ev->n);
        put_key_str(f, "text", ev->text);
        break;
    case GA_EV_VERDICT:
        fprintf(f, ",\"n\":%zu", ev->n);
        put_key_str(f, "id", ev->id);
        fprintf(f, ",\"verdict\":\"%s\",\"ms\":%.0f", ga_verdict_name(ev->verdict),
                ev->ms >= 0 ? ev->ms : 0.0);
        put_key_str(f, "evidence", ev->text);
        break;
    case GA_EV_RUN_FINISHED:
        for(size_t i = 0; i < GA_VERDICT_COUNT; i++)
            fprintf(f, ",\"%s\":%zu", ga_verdict_name((ga_verdict)i), ev->counts[i]);
        fprintf(f, ",\"exit\":%d,\"aborted\":%s", ev->exitCode, ev->aborted ? "true" : "false");
        put_key_str(f, "time", ev->time);
        break;
    case GA_EV_PAUSED:
    case GA_EV_RESUMED:
        break;
    case GA_EV_PROMPT:
        fprintf(f, ",\"n\":%zu,\"seq\":%zu", ev->n, ev->seq);
        put_key_str(f, "text", ev->text);
        break;
    case GA_EV_PROMPT_ANSWERED:
        fprintf(f, ",\"n\":%zu,\"seq\":%zu,\"answer\":\"%s\"", ev->n, ev->seq,
                ga_answer_name(ev->answer));
        put_key_str(f, "text", ev->text);
        break;
    }
    fputs("}\n", f);
    return !ferror(f);
}

void ga_jsonl_sink(const ga_event *ev, void *user) {
    FILE *f = (FILE *)user;
    if(!ga_jsonl_write(f, ev) || fflush(f) != 0)
        fprintf(stderr, "gdsaudit: cannot write the events file\n");
}

/* ---- parser ---- */

typedef struct {
    const char *p, *end;
} cursor;

static void ws(cursor *c) {
    while(c->p < c->end && (*c->p == ' ' || *c->p == '\t' || *c->p == '\r' || *c->p == '\n'))
        c->p++;
}

static bool lit(cursor *c, const char *word) {
    size_t n = strlen(word);
    if((size_t)(c->end - c->p) < n || memcmp(c->p, word, n) != 0)
        return false;
    c->p += n;
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

static bool hex4(cursor *c, uint32_t *out) {
    if(c->end - c->p < 4)
        return false;
    uint32_t v = 0;
    for(int i = 0; i < 4; i++) {
        int h = hexval(c->p[i]);
        if(h < 0)
            return false;
        v = (v << 4) | (uint32_t)h;
    }
    c->p += 4;
    *out = v;
    return true;
}

static size_t put_utf8(uint32_t cp, char *o) {
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

static bool escape(cursor *c, char *o, size_t *k) {
    char e = *c->p++;
    switch(e) {
    case '"': o[(*k)++] = '"'; return true;
    case '\\': o[(*k)++] = '\\'; return true;
    case '/': o[(*k)++] = '/'; return true;
    case 'b': o[(*k)++] = '\b'; return true;
    case 'f': o[(*k)++] = '\f'; return true;
    case 'n': o[(*k)++] = '\n'; return true;
    case 'r': o[(*k)++] = '\r'; return true;
    case 't': o[(*k)++] = '\t'; return true;
    case 'u': {
        uint32_t cp;
        if(!hex4(c, &cp))
            return false;
        if(cp >= 0xd800 && cp <= 0xdbff) {
            uint32_t lo;
            if(!lit(c, "\\u") || !hex4(c, &lo) || lo < 0xdc00 || lo > 0xdfff)
                return false;
            cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
        } else if(cp >= 0xdc00 && cp <= 0xdfff) {
            return false;
        }
        if(cp == 0)
            cp = 0xfffd; /* no NUL inside C strings */
        *k += put_utf8(cp, o + *k);
        return true;
    }
    default:
        return false;
    }
}

/* Parse a string; with out, return a malloc'd copy (an escape never makes
 * the text longer than its source, so the source length bounds it). */
static bool str(cursor *c, char **out) {
    if(c->p >= c->end || *c->p != '"')
        return false;
    c->p++;
    const char *start = c->p;
    char *o = malloc((size_t)(c->end - start) + 1);
    if(!o)
        return false;
    size_t k = 0;
    bool bad = false;
    while(!bad && c->p < c->end && *c->p != '"') {
        unsigned char ch = (unsigned char)*c->p;
        if(ch < 0x20) {
            bad = true;
            break;
        }
        if(ch == '\\') {
            c->p++;
            bad = c->p >= c->end || !escape(c, o, &k);
            continue;
        }
        o[k++] = (char)ch;
        c->p++;
    }
    if(bad || c->p >= c->end || *c->p != '"') {
        free(o);
        return false;
    }
    c->p++;
    o[k] = '\0';
    if(out)
        *out = o;
    else
        free(o);
    return true;
}

static bool num(cursor *c, double *out) {
    const char *s = c->p;
    if(c->p < c->end && *c->p == '-')
        c->p++;
    size_t digits = 0;
    while(c->p < c->end && ((*c->p >= '0' && *c->p <= '9') || *c->p == '.' || *c->p == 'e' ||
                            *c->p == 'E' || *c->p == '+' || *c->p == '-')) {
        c->p++;
        digits++;
    }
    if(digits == 0 || c->p - s > 40)
        return false;
    char buf[48];
    memcpy(buf, s, (size_t)(c->p - s));
    buf[c->p - s] = '\0';
    char *e = NULL;
    double v = strtod(buf, &e);
    if(!e || *e != '\0')
        return false;
    if(out)
        *out = v;
    return true;
}

static bool skip_value(cursor *c, int depth);

/* Recursion is bounded by GA_JSON_DEPTH. */
// NOLINTNEXTLINE(misc-no-recursion)
static bool skip_container(cursor *c, int depth, char close, bool keyed) {
    c->p++;
    ws(c);
    if(c->p < c->end && *c->p == close) {
        c->p++;
        return true;
    }
    for(;;) {
        if(keyed) {
            if(!str(c, NULL))
                return false;
            ws(c);
            if(!lit(c, ":"))
                return false;
            ws(c);
        }
        if(!skip_value(c, depth + 1))
            return false;
        ws(c);
        if(lit(c, ","))
            ws(c);
        else if(c->p < c->end && *c->p == close) {
            c->p++;
            return true;
        } else
            return false;
    }
}

// NOLINTNEXTLINE(misc-no-recursion): bounded by GA_JSON_DEPTH
static bool skip_value(cursor *c, int depth) {
    if(depth > GA_JSON_DEPTH || c->p >= c->end)
        return false;
    switch(*c->p) {
    case '"': return str(c, NULL);
    case '{': return skip_container(c, depth, '}', true);
    case '[': return skip_container(c, depth, ']', false);
    case 't': return lit(c, "true");
    case 'f': return lit(c, "false");
    case 'n': return lit(c, "null");
    default: return num(c, NULL);
    }
}

bool ga_json_valid(const char *s, size_t len) {
    if(!s)
        return false;
    cursor c = {s, s + len};
    ws(&c);
    if(!skip_value(&c, 0))
        return false;
    ws(&c);
    return c.p == c.end;
}

void ga_jsonl_strings_free(ga_jsonl_strings *strs) {
    for(size_t i = 0; i < sizeof(strs->s) / sizeof(strs->s[0]); i++) {
        free(strs->s[i]);
        strs->s[i] = NULL;
    }
}

/* Keys with string values, by slot in ga_jsonl_strings */
enum { S_EV, S_PROFILE, S_TARGET, S_ID, S_CLAUSE, S_TITLE, S_TEXT, S_TIME };

static int string_slot(const char *key) {
    static const struct {
        const char *key;
        int slot;
    } keys[] = {{"ev", S_EV},         {"profile", S_PROFILE}, {"target", S_TARGET},
                {"id", S_ID},         {"clause", S_CLAUSE},   {"title", S_TITLE},
                {"text", S_TEXT},     {"evidence", S_TEXT},   {"time", S_TIME},
                {"verdict", -2},      {"answer", -3}};
    for(size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        if(strcmp(key, keys[i].key) == 0)
            return keys[i].slot;
    return -1;
}

static bool to_size(double d, size_t *out) {
    if(d < 0 || d > (double)GA_MAX_RESULTS * 1024.0 || d != (double)(size_t)d)
        return false;
    *out = (size_t)d;
    return true;
}

/* A number or boolean member: store it in ev. Unknown keys are ignored. */
static bool scalar_member(const char *key, double d, bool isBool, bool b, ga_event *ev,
                          double *schema) {
    if(!strcmp(key, "v"))
        *schema = d;
    else if(!strcmp(key, "n"))
        return !isBool && to_size(d, &ev->n);
    else if(!strcmp(key, "seq"))
        return !isBool && to_size(d, &ev->seq);
    else if(!strcmp(key, "planned"))
        return !isBool && to_size(d, &ev->planned);
    else if(!strcmp(key, "ms"))
        ev->ms = d < 0 ? 0 : d;
    else if(!strcmp(key, "exit"))
        ev->exitCode = (d >= -1000 && d <= 1000) ? (int)d : 2;
    else if(!strcmp(key, "allow_changes"))
        ev->allowChanges = b;
    else if(!strcmp(key, "changes"))
        ev->needsWrite = b;
    else if(!strcmp(key, "operator"))
        ev->needsOperator = b;
    else if(!strcmp(key, "aborted"))
        ev->aborted = b;
    else {
        ga_verdict v;
        if(!isBool && ga_verdict_parse(key, &v))
            return to_size(d, &ev->counts[v]);
    }
    return true;
}

static bool member(cursor *c, ga_event *ev, ga_jsonl_strings *strs, double *schema,
                   bool *verdictSeen) {
    char *key = NULL;
    if(!str(c, &key))
        return false;
    bool ok = false;
    ws(c);
    if(!lit(c, ":"))
        goto out;
    ws(c);
    int slot = string_slot(key);
    if(c->p < c->end && *c->p == '"' && slot != -1) {
        char *val = NULL;
        if(!str(c, &val))
            goto out;
        if(slot == -2) {
            ok = ga_verdict_parse(val, &ev->verdict);
            *verdictSeen = ok;
            free(val);
            goto out;
        }
        if(slot == -3) {
            ok = ga_answer_parse(val, &ev->answer);
            free(val);
            goto out;
        }
        free(strs->s[slot]);
        strs->s[slot] = val;
        ok = true;
    } else if(c->p < c->end && (*c->p == 't' || *c->p == 'f')) {
        bool b = *c->p == 't';
        ok = lit(c, b ? "true" : "false") && scalar_member(key, 0, true, b, ev, schema);
    } else if(c->p < c->end && (*c->p == '-' || (*c->p >= '0' && *c->p <= '9'))) {
        double d;
        ok = num(c, &d) && scalar_member(key, d, false, false, ev, schema);
    } else {
        ok = slot == -1 && skip_value(c, 1); /* unknown key of another type */
    }
out:
    free(key);
    return ok;
}

static int finish(ga_event *ev, const ga_jsonl_strings *strs, double schema, bool verdictSeen) {
    if(schema < 1 || !strs->s[S_EV])
        return -1;
    int kind = -1;
    for(size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++)
        if(!strcmp(strs->s[S_EV], kinds[i]))
            kind = (int)i;
    if(kind < 0)
        return 0; /* an event this reader does not know */
    ev->kind = (ga_event_kind)kind;
    ev->profile = strs->s[S_PROFILE];
    ev->target = strs->s[S_TARGET];
    ev->id = strs->s[S_ID];
    ev->clause = strs->s[S_CLAUSE];
    ev->title = strs->s[S_TITLE];
    ev->text = strs->s[S_TEXT];
    ev->time = strs->s[S_TIME];
    bool numbered = ev->kind == GA_EV_TEST_STARTED || ev->kind == GA_EV_NOTE ||
                    ev->kind == GA_EV_VERDICT;
    if(numbered && ev->n == 0)
        return -1;
    if(ev->kind == GA_EV_VERDICT && !verdictSeen)
        return -1;
    if((ev->kind == GA_EV_PROMPT || ev->kind == GA_EV_PROMPT_ANSWERED) && ev->seq == 0)
        return -1;
    return 1;
}

int ga_jsonl_parse(const char *line, size_t len, ga_event *ev, ga_jsonl_strings *strs) {
    memset(ev, 0, sizeof(*ev));
    memset(strs, 0, sizeof(*strs));
    if(len > GA_MAX_LINE)
        return -1;
    cursor c = {line, line + len};
    double schema = 0;
    bool verdictSeen = false;
    ws(&c);
    if(!lit(&c, "{"))
        return -1;
    ws(&c);
    if(!lit(&c, "}")) {
        for(;;) {
            if(!member(&c, ev, strs, &schema, &verdictSeen))
                return -1;
            ws(&c);
            if(lit(&c, ",")) {
                ws(&c);
                continue;
            }
            if(lit(&c, "}"))
                break;
            return -1;
        }
    }
    ws(&c);
    if(c.p != c.end)
        return -1;
    return finish(ev, strs, schema, verdictSeen);
}
