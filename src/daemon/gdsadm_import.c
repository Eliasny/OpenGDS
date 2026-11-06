/* gdsadm apps import: CSV and JSON files of application records
 * (gdsadm_import.h). Everything here works on untrusted input: lengths are
 * bounded by the GDS limits and every failure names its line.
 * SPDX-License-Identifier: MPL-2.0 */
#include "gdsadm_import.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/limits.h"
#include "common/banned.h"

GDS_FORMAT(3, 4) static void set_err(char *err, size_t errLen, const char *fmt, ...) {
    if(!err || errLen == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(err, errLen, fmt, ap); // NOLINT(clang-analyzer-valist.Uninitialized): va_start above
    va_end(ap);
}

void gdsadm_import_clear(gdsadm_import *im) {
    if(!im)
        return;
    for(size_t i = 0; i < im->n; i++)
        UA_ApplicationRecordDataType_clear(&im->recs[i]);
    free(im->recs);
    free(im->lines);
    memset(im, 0, sizeof(*im));
}

static gds_status grow(gdsadm_import *im, size_t *cap) {
    if(im->n < *cap)
        return GDS_OK;
    if(im->n >= GDSADM_IMPORT_MAX_ROWS)
        return GDS_ETOOBIG;
    size_t nc = *cap ? *cap * 2 : 64;
    if(nc > GDSADM_IMPORT_MAX_ROWS)
        nc = GDSADM_IMPORT_MAX_ROWS;
    UA_ApplicationRecordDataType *r = realloc(im->recs, nc * sizeof(*r));
    if(!r)
        return GDS_ENOMEM;
    im->recs = r;
    size_t *l = realloc(im->lines, nc * sizeof(*l));
    if(!l)
        return GDS_ENOMEM;
    im->lines = l;
    *cap = nc;
    return GDS_OK;
}

/* ---- CSV (RFC 4180) ---- */

enum { COL_URI, COL_NAME, COL_TYPE, COL_LOCALE, COL_PRODUCT, COL_URLS, COL_CAPS, COL_N };
static const char *const colNames[COL_N] = {
    "ApplicationUri", "ApplicationName", "ApplicationType", "ApplicationNameLocale",
    "ProductUri",     "DiscoveryUrls",   "ServerCapabilities"};

#define MAX_FIELDS 16
#define MAX_FIELD  GDS_MAX_STRING

typedef struct {
    const UA_Byte *p;
    size_t len, pos, line;
    char field[MAX_FIELDS][MAX_FIELD + 1];
    size_t fieldLen[MAX_FIELDS];
    size_t nFields;
} csv;

/* The scanner's state inside one row */
typedef struct {
    size_t line;     /* where the row starts */
    size_t f, fl;    /* field index, bytes in it */
    bool quoted;     /* inside quotes */
    bool wasQuoted;  /* the field was quoted and the quote is closed */
} row_state;

typedef enum { STEP_NEXT, STEP_STORE, STEP_FIELD_END, STEP_ROW_END, STEP_ERROR } step;

/* A character inside quotes: "" is one quote, " ends the quotes */
static step quoted_char(csv *c, row_state *r, UA_Byte ch) {
    if(ch == '"') {
        if(c->pos < c->len && c->p[c->pos] == '"') {
            c->pos++;
            return STEP_STORE; /* one quote */
        }
        r->quoted = false;
        return STEP_NEXT;
    }
    if(ch == '\n')
        c->line++;
    return STEP_STORE;
}

/* ',' ends a field; LF or CRLF (or the end of input) ends the row */
static step separator(csv *c, UA_Byte ch, char *err, size_t errLen) {
    if(ch == '\r') {
        if(c->pos < c->len && c->p[c->pos] == '\n') {
            c->pos++;
        } else if(c->pos < c->len) {
            set_err(err, errLen, "line %zu: bare carriage return", c->line);
            return STEP_ERROR;
        }
    }
    return ch == ',' ? STEP_FIELD_END : STEP_ROW_END;
}

static gds_status end_field(csv *c, row_state *r, char *err, size_t errLen) {
    if(r->f >= MAX_FIELDS) {
        set_err(err, errLen, "line %zu: more than %d fields", r->line, MAX_FIELDS);
        return GDS_EINVAL;
    }
    c->field[r->f][r->fl] = '\0';
    c->fieldLen[r->f] = r->fl;
    r->f++;
    r->fl = 0;
    r->wasQuoted = false;
    return GDS_OK;
}

static gds_status store_char(csv *c, row_state *r, UA_Byte ch, char *err, size_t errLen) {
    if(ch == '\0') {
        set_err(err, errLen, "line %zu: NUL byte", c->line);
        return GDS_EINVAL;
    }
    if(r->fl >= MAX_FIELD || r->f >= MAX_FIELDS) {
        set_err(err, errLen, "line %zu: field longer than %zu bytes", r->line, MAX_FIELD);
        return GDS_EINVAL;
    }
    c->field[r->f][r->fl++] = (char)ch;
    return GDS_OK;
}

/* One character outside quotes */
static step plain_char(csv *c, row_state *r, UA_Byte ch, char *err, size_t errLen) {
    if(ch == '"') {
        if(r->fl != 0 || r->wasQuoted) {
            set_err(err, errLen, "line %zu: quote inside an unquoted field", c->line);
            return STEP_ERROR;
        }
        r->quoted = r->wasQuoted = true;
        return STEP_NEXT;
    }
    if(ch == ',' || ch == '\n' || ch == '\r')
        return separator(c, ch, err, errLen);
    if(r->wasQuoted) {
        set_err(err, errLen, "line %zu: text after a closing quote", c->line);
        return STEP_ERROR;
    }
    return STEP_STORE;
}

/* One record (a row) into c->field; *line is where it starts. *got is false
 * at the end of the input. A row may span lines inside quotes. */
static gds_status csv_row(csv *c, bool *got, size_t *line, char *err, size_t errLen) {
    *got = false;
    c->nFields = 0;
    if(c->pos >= c->len)
        return GDS_OK;
    row_state r = {c->line, 0, 0, false, false};
    *line = c->line;
    for(;;) {
        bool end = c->pos >= c->len;
        UA_Byte ch = end ? '\n' : c->p[c->pos];
        if(!end)
            c->pos++;
        if(end && r.quoted) {
            set_err(err, errLen, "line %zu: unterminated quoted field", r.line);
            return GDS_EINVAL;
        }
        step st = r.quoted ? quoted_char(c, &r, ch) : plain_char(c, &r, ch, err, errLen);
        gds_status s = GDS_OK;
        if(st == STEP_ERROR)
            return GDS_EINVAL;
        if(st == STEP_STORE)
            s = store_char(c, &r, ch, err, errLen);
        else if(st == STEP_FIELD_END || st == STEP_ROW_END)
            s = end_field(c, &r, err, errLen);
        if(s != GDS_OK)
            return s;
        if(st == STEP_ROW_END) {
            c->line++;
            c->nFields = r.f;
            *got = true;
            return GDS_OK;
        }
    }
}

static bool blank_row(const csv *c) {
    return c->nFields == 1 && c->fieldLen[0] == 0;
}

static gds_status csv_header(csv *c, int cols[COL_N], char *err, size_t errLen) {
    bool got = false;
    size_t line = 0;
    gds_status s;
    do
        s = csv_row(c, &got, &line, err, errLen);
    while(s == GDS_OK && got && blank_row(c));
    if(s != GDS_OK)
        return s;
    if(!got) {
        set_err(err, errLen, "no header row");
        return GDS_EINVAL;
    }
    for(int i = 0; i < COL_N; i++)
        cols[i] = -1;
    for(size_t f = 0; f < c->nFields; f++) {
        int k = -1;
        for(int i = 0; i < COL_N; i++)
            if(strcmp(c->field[f], colNames[i]) == 0)
                k = i;
        if(k < 0) {
            set_err(err, errLen, "line %zu: unknown column '%s'", line, c->field[f]);
            return GDS_EINVAL;
        }
        if(cols[k] >= 0) {
            set_err(err, errLen, "line %zu: column '%s' given twice", line, c->field[f]);
            return GDS_EINVAL;
        }
        cols[k] = (int)f;
    }
    for(int i = COL_URI; i <= COL_TYPE; i++) {
        if(cols[i] < 0) {
            set_err(err, errLen, "line %zu: column '%s' is missing", line, colNames[i]);
            return GDS_EINVAL;
        }
    }
    return GDS_OK;
}

static const char *col(const csv *c, const int cols[COL_N], int k) {
    return cols[k] >= 0 && (size_t)cols[k] < c->nFields ? c->field[cols[k]] : "";
}

static gds_status set_string(UA_String *dst, const char *v) {
    if(v[0] == '\0') {
        UA_String_init(dst);
        return GDS_OK;
    }
    *dst = UA_STRING_ALLOC(v);
    return dst->data ? GDS_OK : GDS_ENOMEM;
}

/* Space-separated values into an array of strings */
static gds_status set_list(UA_String **arr, size_t *n, const char *v, size_t line, char *err,
                           size_t errLen) {
    UA_String vals[GDS_MAX_ARRAY_FIELD];
    size_t k = 0;
    const char *p = v;
    for(;;) {
        while(*p == ' ' || *p == '\t')
            p++;
        if(*p == '\0')
            break;
        const char *e = p;
        while(*e && *e != ' ' && *e != '\t')
            e++;
        if(k >= GDS_MAX_ARRAY_FIELD) {
            set_err(err, errLen, "line %zu: more than %zu values in a list", line,
                    GDS_MAX_ARRAY_FIELD);
            return GDS_EINVAL;
        }
        vals[k].data = (UA_Byte *)(uintptr_t)p;
        vals[k++].length = (size_t)(e - p);
        p = e;
    }
    if(k == 0)
        return GDS_OK;
    return UA_Array_copy(vals, k, (void **)arr, &UA_TYPES[UA_TYPES_STRING]) == UA_STATUSCODE_GOOD
               ? (*n = k, GDS_OK)
               : GDS_ENOMEM;
}

static bool parse_type(const char *t, UA_ApplicationType *out) {
    static const struct {
        const char *name;
        UA_ApplicationType type;
    } types[] = {{"Server", UA_APPLICATIONTYPE_SERVER},
                 {"Client", UA_APPLICATIONTYPE_CLIENT},
                 {"ClientAndServer", UA_APPLICATIONTYPE_CLIENTANDSERVER}};
    for(size_t i = 0; i < GDS_ARRAY_SIZE(types); i++) {
        if(strcmp(t, types[i].name) == 0) {
            *out = types[i].type;
            return true;
        }
    }
    return false;
}

static gds_status csv_record(const csv *c, const int cols[COL_N], size_t line,
                             UA_ApplicationRecordDataType *rec, char *err, size_t errLen) {
    UA_ApplicationRecordDataType_init(rec);
    if(!parse_type(col(c, cols, COL_TYPE), &rec->applicationType)) {
        set_err(err, errLen, "line %zu: ApplicationType '%s' is not Server, Client or "
                             "ClientAndServer", line, col(c, cols, COL_TYPE));
        return GDS_EINVAL;
    }
    const char *locale = cols[COL_LOCALE] >= 0 ? col(c, cols, COL_LOCALE) : "en";
    gds_status s = set_string(&rec->applicationUri, col(c, cols, COL_URI));
    if(s == GDS_OK)
        s = set_string(&rec->productUri, col(c, cols, COL_PRODUCT));
    if(s == GDS_OK && col(c, cols, COL_NAME)[0] != '\0') {
        rec->applicationNames = UA_LocalizedText_new();
        if(!rec->applicationNames)
            return GDS_ENOMEM;
        rec->applicationNamesSize = 1;
        s = set_string(&rec->applicationNames[0].locale, locale);
        if(s == GDS_OK)
            s = set_string(&rec->applicationNames[0].text, col(c, cols, COL_NAME));
    }
    if(s == GDS_OK)
        s = set_list(&rec->discoveryUrls, &rec->discoveryUrlsSize, col(c, cols, COL_URLS), line,
                     err, errLen);
    if(s == GDS_OK)
        s = set_list(&rec->serverCapabilities, &rec->serverCapabilitiesSize,
                     col(c, cols, COL_CAPS), line, err, errLen);
    return s;
}

static gds_status parse_csv(const UA_Byte *p, size_t len, gdsadm_import *out, char *err,
                            size_t errLen) {
    csv *c = calloc(1, sizeof(*c));
    if(!c)
        return GDS_ENOMEM;
    c->p = p;
    c->len = len;
    c->line = 1;
    if(len >= 3 && p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF)
        c->pos = 3; /* UTF-8 byte order mark */
    int cols[COL_N];
    gds_status s = csv_header(c, cols, err, errLen);
    size_t cap = 0;
    while(s == GDS_OK) {
        bool got = false;
        size_t line = 0;
        s = csv_row(c, &got, &line, err, errLen);
        if(s != GDS_OK || !got)
            break;
        if(blank_row(c))
            continue;
        if((s = grow(out, &cap)) != GDS_OK) {
            if(s == GDS_ETOOBIG)
                set_err(err, errLen, "line %zu: more than %zu records", line,
                        GDSADM_IMPORT_MAX_ROWS);
            break;
        }
        s = csv_record(c, cols, line, &out->recs[out->n], err, errLen);
        if(s != GDS_OK) {
            UA_ApplicationRecordDataType_clear(&out->recs[out->n]);
            break;
        }
        out->lines[out->n++] = line;
    }
    free(c);
    return s;
}

/* ---- JSON: {"Applications": [ApplicationRecordDataType...]} ---- */

typedef struct {
    size_t n;
    UA_ApplicationRecordDataType *recs;
} json_file;

static gds_status parse_json(const gds_buf *file, gdsadm_import *out, char *err, size_t errLen) {
    /* A one-member structure type: open62541's JSON decoder then reads the
     * whole file, with its own limits, and the records with the standard
     * encoding of ApplicationRecordDataType. */
    UA_DataTypeMember member;
    memset(&member, 0, sizeof(member));
    member.memberName = "Applications";
    member.memberType = &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE];
    member.isArray = true;
    UA_DataType t;
    memset(&t, 0, sizeof(t));
    t.typeName = "OpenGDSImport";
    t.typeId = UA_NODEID_NUMERIC(1, 1);
    t.memSize = (UA_UInt32)sizeof(json_file);
    t.typeKind = UA_DATATYPEKIND_STRUCTURE;
    t.membersSize = 1;
    t.members = &member;
    json_file jf;
    memset(&jf, 0, sizeof(jf));
    UA_ByteString src = {file->len, file->data};
    UA_StatusCode r = UA_decodeJson(&src, &jf, &t, NULL);
    if(r != UA_STATUSCODE_GOOD) {
        set_err(err, errLen, "not a JSON object {\"Applications\": [...]} of "
                             "ApplicationRecordDataType: %s", UA_StatusCode_name(r));
        return GDS_EINVAL;
    }
    gds_status s = GDS_OK;
    if(jf.n > GDSADM_IMPORT_MAX_ROWS) {
        set_err(err, errLen, "more than %zu records", GDSADM_IMPORT_MAX_ROWS);
        s = GDS_EINVAL;
    } else if(jf.n > 0) {
        out->lines = calloc(jf.n, sizeof(*out->lines));
        if(!out->lines)
            s = GDS_ENOMEM;
    }
    if(s != GDS_OK) {
        UA_Array_delete(jf.recs, jf.n, member.memberType);
        return s;
    }
    for(size_t i = 0; i < jf.n; i++) {
        UA_NodeId_clear(&jf.recs[i].applicationId); /* the GDS assigns it */
        out->lines[i] = i + 1;
    }
    out->recs = jf.n > 0 ? jf.recs : NULL;
    if(jf.n == 0)
        UA_Array_delete(jf.recs, 0, member.memberType);
    out->n = jf.n;
    return GDS_OK;
}

gds_status gdsadm_import_parse(const gds_buf *file, gdsadm_import *out, char *err,
                               size_t errLen) {
    if(err && errLen)
        err[0] = '\0';
    if(!file || !out || (!file->data && file->len > 0))
        return GDS_EINVAL;
    memset(out, 0, sizeof(*out));
    if(file->len > GDSADM_IMPORT_MAX_FILE) {
        set_err(err, errLen, "file larger than %zu bytes", GDSADM_IMPORT_MAX_FILE);
        return GDS_ETOOBIG;
    }
    size_t i = 0;
    while(i < file->len && (file->data[i] == ' ' || file->data[i] == '\t' ||
                            file->data[i] == '\r' || file->data[i] == '\n'))
        i++;
    gds_status s = i < file->len && file->data[i] == '{'
                       ? parse_json(file, out, err, errLen)
                       : parse_csv(file->data, file->len, out, err, errLen);
    if(s != GDS_OK)
        gdsadm_import_clear(out);
    return s;
}
