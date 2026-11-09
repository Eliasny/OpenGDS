/* gdsadm watch: live audit events and alarms of a GDS, as any standard
 * OPC UA client sees them (OpenGDS plan W5, tools "cmd_watch.c").
 *
 *   gdsadm watch --url URL --user NAME --password-file F --trust CA.der
 *                [--trust DER]... [--crl DER]... [--json] [--count N] [--seconds N]
 *
 * One Subscription with one event MonitoredItem on the Server object, whose
 * EventNotifier reports every event of the server (OPC 10000-3 §9.21,
 * OPC 10000-4 §5.12.1.4): the GDS's audit events (AuditEventType and its
 * subtypes, OPC 10000-5 §6.4.3), its alarms and the DialogConditions of
 * requests that wait for approval (OPC 10000-9). Right after it, a
 * ConditionRefresh (OPC 10000-9 §5.5.7) brings the current state of every
 * Condition, so an alarm that was raised before the watch started shows
 * too; those lines say "refresh". What a user sees is what the GDS lets
 * that user receive: the Roles of `--user` decide (docs/opengdsd.md).
 *
 * Output: one line per event, as text (UTC time, severity, EventType,
 * SourceName, Message, then the Condition and audit fields the event has)
 * or with --json one JSON object per line (JSON Lines). Text is printed
 * with control characters escaped, so a GDS cannot drive the terminal.
 * Stops after --count events, after --seconds, or on SIGINT/SIGTERM
 * (exit 0); a lost connection exits 1.
 * SPDX-License-Identifier: MPL-2.0 */
#include "gdsadm_watch.h"

#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>

#include <signal.h>
#include <string.h>

#include "client/gdsc_connect.h"
#include "common/buf.h"
#include "common/limits.h"
#include "common/safeint.h"
#include "common/banned.h"

#define MAX_FILES 8
#define QUEUE_MAX 256
#define TYPE_CACHE 32
#define PUBLISH_MS 250.0
#define ITERATE_MS 100

/* ---- printing ---- */

/* One UTF-8 sequence at p (n bytes left): its length, 0 if malformed. */
static size_t utf8_len(const unsigned char *p, size_t n) {
    unsigned char c = p[0];
    size_t len = c < 0x80 ? 1 : (c & 0xe0) == 0xc0 && c >= 0xc2 ? 2 : (c & 0xf0) == 0xe0 ? 3
                            : (c & 0xf8) == 0xf0 && c <= 0xf4   ? 4 : 0;
    if(len == 0 || len > n)
        return 0;
    for(size_t i = 1; i < len; i++)
        if((p[i] & 0xc0) != 0x80)
            return 0;
    return len;
}

/* A JSON string; malformed UTF-8 becomes U+FFFD. */
static void put_json_str(FILE *o, const UA_Byte *d, size_t n) {
    fputc('"', o);
    for(size_t i = 0; i < n;) {
        unsigned char c = d[i];
        size_t len = utf8_len(d + i, n - i);
        if(len == 0) {
            fputs("\\ufffd", o);
            i++;
            continue;
        }
        if(len > 1) {
            (void)fwrite(d + i, 1, len, o);
        } else if(c == '"' || c == '\\') {
            fputc('\\', o);
            fputc(c, o);
        } else if(c == '\n') {
            fputs("\\n", o);
        } else if(c == '\t') {
            fputs("\\t", o);
        } else if(c < 0x20 || c == 0x7f) {
            fprintf(o, "\\u%04x", (unsigned)c);
        } else {
            fputc(c, o);
        }
        i += len;
    }
    fputc('"', o);
}

/* Text: printable UTF-8 as is, anything else as \xNN. */
static void put_text(FILE *o, const UA_Byte *d, size_t n) {
    for(size_t i = 0; i < n;) {
        size_t len = utf8_len(d + i, n - i);
        if(len > 1) {
            (void)fwrite(d + i, 1, len, o);
            i += len;
            continue;
        }
        unsigned char c = d[i++];
        if(len == 1 && c >= 0x20 && c != 0x7f && c != '\\')
            fputc(c, o);
        else
            fprintf(o, "\\x%02x", (unsigned)c);
    }
}

static const UA_String *as_string(const UA_Variant *v) {
    if(UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_STRING]))
        return v->data;
    if(UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]))
        return &((const UA_LocalizedText *)v->data)->text;
    if(UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_QUALIFIEDNAME]))
        return &((const UA_QualifiedName *)v->data)->name;
    return NULL;
}

static bool as_bool(const UA_Variant *v, bool *out) {
    if(!UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_BOOLEAN]))
        return false;
    *out = *(const UA_Boolean *)v->data;
    return true;
}

/* NodeId in its standard string form (OPC 10000-6 §5.3.1.10). */
static bool node_text(const UA_Variant *v, UA_String *out) {
    UA_String_init(out);
    if(!UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_NODEID]))
        return false;
    return UA_NodeId_print(v->data, out) == UA_STATUSCODE_GOOD;
}

/* 2026-11-09T06:30:00.123Z */
static bool time_text(const UA_Variant *v, char *buf, size_t len) {
    if(!UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_DATETIME]))
        return false;
    UA_DateTimeStruct t = UA_DateTime_toStruct(*(const UA_DateTime *)v->data);
    int n = snprintf(buf, len, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", (unsigned)t.year,
                     (unsigned)t.month, (unsigned)t.day, (unsigned)t.hour, (unsigned)t.min,
                     (unsigned)t.sec, (unsigned)t.milliSec);
    return n > 0 && (size_t)n < len;
}

typedef struct {
    FILE *o;
    bool first;
} json_obj;

static void key(json_obj *j, const char *k) {
    fprintf(j->o, "%s\"%s\":", j->first ? "" : ",", k);
    j->first = false;
}

static void json_string_field(json_obj *j, const char *k, const UA_String *s) {
    if(!s)
        return;
    key(j, k);
    put_json_str(j->o, s->data, s->length);
}

static void json_cstr_field(json_obj *j, const char *k, const char *s) {
    if(!s)
        return;
    key(j, k);
    put_json_str(j->o, (const UA_Byte *)s, strlen(s));
}

static void json_bool_field(json_obj *j, const char *k, const UA_Variant *v) {
    bool b;
    if(!as_bool(v, &b))
        return;
    key(j, k);
    fputs(b ? "true" : "false", j->o);
}

static void json_node_field(json_obj *j, const char *k, const UA_Variant *v) {
    UA_String s;
    if(!node_text(v, &s))
        return;
    json_string_field(j, k, &s);
    UA_String_clear(&s);
}

static void print_json(FILE *o, const UA_Variant *f, const char *typeName, bool refresh) {
    json_obj j = {o, true};
    fputc('{', o);
    char tb[40];
    if(time_text(&f[GW_TIME], tb, sizeof(tb)))
        json_cstr_field(&j, "time", tb);
    json_cstr_field(&j, "eventType", typeName);
    json_node_field(&j, "eventTypeId", &f[GW_EVENT_TYPE]);
    if(UA_Variant_hasScalarType(&f[GW_SEVERITY], &UA_TYPES[UA_TYPES_UINT16])) {
        key(&j, "severity");
        fprintf(o, "%u", (unsigned)*(const UA_UInt16 *)f[GW_SEVERITY].data);
    }
    json_string_field(&j, "sourceName", as_string(&f[GW_SOURCE_NAME]));
    json_node_field(&j, "sourceNode", &f[GW_SOURCE_NODE]);
    json_string_field(&j, "message", as_string(&f[GW_MESSAGE]));
    if(UA_Variant_hasScalarType(&f[GW_EVENT_ID], &UA_TYPES[UA_TYPES_BYTESTRING])) {
        const UA_ByteString *id = f[GW_EVENT_ID].data;
        key(&j, "eventId");
        fputc('"', o);
        for(size_t i = 0; i < id->length; i++)
            fprintf(o, "%02x", (unsigned)id->data[i]);
        fputc('"', o);
    }
    json_node_field(&j, "conditionId", &f[GW_CONDITION_ID]);
    json_string_field(&j, "conditionName", as_string(&f[GW_CONDITION_NAME]));
    json_bool_field(&j, "retain", &f[GW_RETAIN]);
    json_bool_field(&j, "enabled", &f[GW_ENABLED]);
    json_bool_field(&j, "active", &f[GW_ACTIVE]);
    json_bool_field(&j, "acked", &f[GW_ACKED]);
    const UA_String *user = as_string(&f[GW_CLIENT_USER]);
    if(user && user->length) /* open62541 gives "" to events without the field */
        json_string_field(&j, "clientUserId", user);
    json_bool_field(&j, "status", &f[GW_STATUS]);
    key(&j, "refresh");
    fputs(refresh ? "true" : "false", o);
    fputs("}\n", o);
}

static void text_flag(FILE *o, const char *name, const UA_Variant *v, const char *no) {
    bool b;
    if(as_bool(v, &b))
        fprintf(o, " %s", b ? name : no);
}

static void print_text(FILE *o, const UA_Variant *f, const char *typeName, bool refresh) {
    char tb[40];
    fputs(time_text(&f[GW_TIME], tb, sizeof(tb)) ? tb : "-", o);
    if(UA_Variant_hasScalarType(&f[GW_SEVERITY], &UA_TYPES[UA_TYPES_UINT16]))
        fprintf(o, "  %4u", (unsigned)*(const UA_UInt16 *)f[GW_SEVERITY].data);
    else
        fputs("     -", o);
    fputs("  ", o);
    UA_String id = UA_STRING_NULL;
    if(typeName)
        put_text(o, (const UA_Byte *)typeName, strlen(typeName));
    else if(node_text(&f[GW_EVENT_TYPE], &id))
        put_text(o, id.data, id.length);
    else
        fputc('-', o);
    UA_String_clear(&id);
    const UA_String *src = as_string(&f[GW_SOURCE_NAME]);
    fputs("  ", o);
    if(src && src->length)
        put_text(o, src->data, src->length);
    else
        fputc('-', o);
    const UA_String *msg = as_string(&f[GW_MESSAGE]);
    if(msg && msg->length) {
        fputs(": ", o);
        put_text(o, msg->data, msg->length);
    }
    const UA_String *cn = as_string(&f[GW_CONDITION_NAME]);
    if(cn && cn->length) {
        fputs("  [condition ", o);
        put_text(o, cn->data, cn->length);
        text_flag(o, "enabled", &f[GW_ENABLED], "disabled");
        text_flag(o, "active", &f[GW_ACTIVE], "inactive");
        text_flag(o, "acked", &f[GW_ACKED], "unacked");
        text_flag(o, "retained", &f[GW_RETAIN], "not-retained");
        fputc(']', o);
    }
    const UA_String *user = as_string(&f[GW_CLIENT_USER]);
    if(user && user->length) {
        fputs("  user=", o);
        put_text(o, user->data, user->length);
    }
    bool ok;
    if(as_bool(&f[GW_STATUS], &ok))
        fprintf(o, "  status=%s", ok ? "ok" : "failed");
    if(refresh)
        fputs("  (refresh)", o);
    fputc('\n', o);
}

void gdsadm_watch_print(FILE *out, bool json, const UA_Variant *fields, const char *typeName,
                        bool refresh) {
    if(json)
        print_json(out, fields, typeName, refresh);
    else
        print_text(out, fields, typeName, refresh);
    fflush(out);
}

/* ---- the subscription ---- */

typedef struct {
    UA_Variant f[GW_NFIELDS];
} queued_event;

typedef struct {
    queued_event q[QUEUE_MAX];
    size_t head, n;
    size_t dropped;
} event_queue;

/* Runs inside UA_Client_run_iterate: only copies (no service calls here). */
static void on_event(UA_Client *c, UA_UInt32 subId, void *subCtx, UA_UInt32 monId, void *monCtx,
                     const UA_KeyValueMap fields) {
    (void)c, (void)subId, (void)subCtx, (void)monId;
    event_queue *eq = monCtx;
    if(eq->n == QUEUE_MAX || fields.mapSize != GW_NFIELDS) {
        eq->dropped++;
        return;
    }
    queued_event *e = &eq->q[(eq->head + eq->n) % QUEUE_MAX];
    for(size_t i = 0; i < GW_NFIELDS; i++)
        if(UA_Variant_copy(&fields.map[i].value, &e->f[i]) != UA_STATUSCODE_GOOD)
            UA_Variant_init(&e->f[i]); /* out of memory: left out */
    eq->n++;
}

/* Browse paths with one or two names; an empty path is the Condition's NodeId. */
static UA_StatusCode add_select(UA_SimpleAttributeOperand *s, UA_QualifiedName *path,
                                UA_UInt32 type, const char *a, const char *b, UA_UInt32 attr) {
    UA_SimpleAttributeOperand_init(s);
    s->typeDefinitionId = UA_NODEID_NUMERIC(0, type);
    s->attributeId = attr;
    s->browsePath = path;
    s->browsePathSize = 0;
    if(a)
        path[s->browsePathSize++] = UA_QUALIFIEDNAME(0, (char *)(uintptr_t)a);
    if(b)
        path[s->browsePathSize++] = UA_QUALIFIEDNAME(0, (char *)(uintptr_t)b);
    if(s->browsePathSize == 0)
        s->browsePath = NULL;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode subscribe(UA_Client *c, event_queue *eq, UA_UInt32 *subId) {
    UA_CreateSubscriptionRequest sreq = UA_CreateSubscriptionRequest_default();
    sreq.requestedPublishingInterval = PUBLISH_MS;
    UA_CreateSubscriptionResponse sres = UA_Client_Subscriptions_create(c, sreq, NULL, NULL, NULL);
    UA_StatusCode r = sres.responseHeader.serviceResult;
    *subId = sres.subscriptionId;
    UA_CreateSubscriptionResponse_clear(&sres);
    if(r != UA_STATUSCODE_GOOD)
        return r;

    static const struct {
        const char *a, *b;
        UA_UInt32 type;
        UA_UInt32 attr;
    } defs[GW_NFIELDS] = {
        [GW_EVENT_ID] = {"EventId", NULL, UA_NS0ID_BASEEVENTTYPE, UA_ATTRIBUTEID_VALUE},
        [GW_EVENT_TYPE] = {"EventType", NULL, UA_NS0ID_BASEEVENTTYPE, UA_ATTRIBUTEID_VALUE},
        [GW_SOURCE_NODE] = {"SourceNode", NULL, UA_NS0ID_BASEEVENTTYPE, UA_ATTRIBUTEID_VALUE},
        [GW_SOURCE_NAME] = {"SourceName", NULL, UA_NS0ID_BASEEVENTTYPE, UA_ATTRIBUTEID_VALUE},
        [GW_TIME] = {"Time", NULL, UA_NS0ID_BASEEVENTTYPE, UA_ATTRIBUTEID_VALUE},
        [GW_MESSAGE] = {"Message", NULL, UA_NS0ID_BASEEVENTTYPE, UA_ATTRIBUTEID_VALUE},
        [GW_SEVERITY] = {"Severity", NULL, UA_NS0ID_BASEEVENTTYPE, UA_ATTRIBUTEID_VALUE},
        [GW_CONDITION_ID] = {NULL, NULL, UA_NS0ID_CONDITIONTYPE, UA_ATTRIBUTEID_NODEID},
        [GW_CONDITION_NAME] = {"ConditionName", NULL, UA_NS0ID_CONDITIONTYPE, UA_ATTRIBUTEID_VALUE},
        [GW_RETAIN] = {"Retain", NULL, UA_NS0ID_CONDITIONTYPE, UA_ATTRIBUTEID_VALUE},
        [GW_ENABLED] = {"EnabledState", "Id", UA_NS0ID_CONDITIONTYPE, UA_ATTRIBUTEID_VALUE},
        [GW_ACKED] = {"AckedState", "Id", UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE, UA_ATTRIBUTEID_VALUE},
        [GW_ACTIVE] = {"ActiveState", "Id", UA_NS0ID_ALARMCONDITIONTYPE, UA_ATTRIBUTEID_VALUE},
        [GW_CLIENT_USER] = {"ClientUserId", NULL, UA_NS0ID_AUDITEVENTTYPE, UA_ATTRIBUTEID_VALUE},
        [GW_STATUS] = {"Status", NULL, UA_NS0ID_AUDITEVENTTYPE, UA_ATTRIBUTEID_VALUE},
    };
    UA_SimpleAttributeOperand sel[GW_NFIELDS];
    UA_QualifiedName paths[GW_NFIELDS][2];
    for(size_t i = 0; i < GW_NFIELDS; i++)
        (void)add_select(&sel[i], paths[i], defs[i].type, defs[i].a, defs[i].b, defs[i].attr);
    UA_EventFilter filter;
    UA_EventFilter_init(&filter);
    filter.selectClauses = sel;
    filter.selectClausesSize = GW_NFIELDS;

    UA_MonitoredItemCreateRequest item;
    UA_MonitoredItemCreateRequest_init(&item);
    item.itemToMonitor.nodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER);
    item.itemToMonitor.attributeId = UA_ATTRIBUTEID_EVENTNOTIFIER;
    item.monitoringMode = UA_MONITORINGMODE_REPORTING;
    UA_ExtensionObject_setValue(&item.requestedParameters.filter, &filter,
                                &UA_TYPES[UA_TYPES_EVENTFILTER]);
    item.requestedParameters.queueSize = 100;
    item.requestedParameters.discardOldest = true;
    UA_MonitoredItemCreateResult mr = UA_Client_MonitoredItems_createEvent(
        c, *subId, UA_TIMESTAMPSTORETURN_NEITHER, item, eq, on_event, NULL);
    r = mr.statusCode;
    UA_MonitoredItemCreateResult_clear(&mr);
    return r;
}

/* ConditionRefresh on ConditionType (OPC 10000-9 §5.5.7). */
static UA_StatusCode refresh(UA_Client *c, UA_UInt32 subId) {
    UA_Variant in;
    UA_Variant_setScalar(&in, &subId, &UA_TYPES[UA_TYPES_UINT32]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = UA_Client_call(c, UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE),
                                     UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE_CONDITIONREFRESH),
                                     1, &in, &outN, &out);
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

/* BrowseName of an EventType, read once per type. */
typedef struct {
    UA_NodeId id[TYPE_CACHE];
    char name[TYPE_CACHE][128];
    size_t n;
} type_cache;

static const char *type_name(UA_Client *c, type_cache *tc, const UA_Variant *v) {
    if(!UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_NODEID]))
        return NULL;
    const UA_NodeId *id = v->data;
    for(size_t i = 0; i < tc->n; i++)
        if(UA_NodeId_equal(&tc->id[i], id))
            return tc->name[i][0] ? tc->name[i] : NULL;
    if(tc->n == TYPE_CACHE)
        return NULL;
    size_t k = tc->n;
    tc->name[k][0] = '\0';
    UA_QualifiedName qn;
    UA_QualifiedName_init(&qn);
    if(UA_Client_readBrowseNameAttribute(c, *id, &qn) == UA_STATUSCODE_GOOD &&
       qn.name.length < sizeof(tc->name[k])) {
        memcpy(tc->name[k], qn.name.data, qn.name.length);
        tc->name[k][qn.name.length] = '\0';
    }
    UA_QualifiedName_clear(&qn);
    if(UA_NodeId_copy(id, &tc->id[k]) != UA_STATUSCODE_GOOD)
        return NULL;
    tc->n++;
    return tc->name[k][0] ? tc->name[k] : NULL;
}

static void type_cache_clear(type_cache *tc) {
    for(size_t i = 0; i < tc->n; i++)
        UA_NodeId_clear(&tc->id[i]);
    tc->n = 0;
}

static bool is_type(const UA_Variant *v, UA_UInt32 ns0) {
    UA_NodeId want = UA_NODEID_NUMERIC(0, ns0);
    return UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_NODEID]) &&
           UA_NodeId_equal(v->data, &want);
}

/* ---- the command ---- */

static volatile sig_atomic_t stopRequested;

static void on_stop(int sig) {
    (void)sig;
    stopRequested = 1;
}

typedef struct {
    const char *url, *user, *passwordFile;
    const char *trust[MAX_FILES], *crl[MAX_FILES];
    size_t trustN, crlN;
    bool json;
    long count, seconds;
} watch_args;

static int usage(void) {
    fprintf(stderr, "usage: gdsadm watch --url URL --user NAME --password-file FILE "
                    "--trust CA.der [--trust DER]... [--crl DER]...\n"
                    "                    [--json] [--count N] [--seconds N]\n");
    return 2;
}

/* One option with a value; false: unknown, repeated or malformed. */
static bool parse_opt(watch_args *a, const char *k, const char *v) {
    if(strcmp(k, "--trust") == 0 && a->trustN < MAX_FILES) {
        a->trust[a->trustN++] = v;
        return true;
    }
    if(strcmp(k, "--crl") == 0 && a->crlN < MAX_FILES) {
        a->crl[a->crlN++] = v;
        return true;
    }
    if(strcmp(k, "--count") == 0 && !a->count)
        return gds_parse_long(v, 1, 1000000000L, &a->count);
    if(strcmp(k, "--seconds") == 0 && !a->seconds)
        return gds_parse_long(v, 1, 31L * 24 * 3600, &a->seconds);
    const struct {
        const char *name;
        const char **field;
    } single[] = {{"--url", &a->url}, {"--user", &a->user}, {"--password-file", &a->passwordFile}};
    for(size_t i = 0; i < sizeof(single) / sizeof(single[0]); i++) {
        if(strcmp(k, single[i].name) == 0 && !*single[i].field) {
            *single[i].field = v;
            return true;
        }
    }
    return false;
}

static bool parse(int argc, char **argv, watch_args *a) {
    memset(a, 0, sizeof(*a));
    for(int i = 2; i < argc; i++) {
        if(strcmp(argv[i], "--json") == 0 && !a->json) {
            a->json = true;
            continue;
        }
        if(i + 1 >= argc || !parse_opt(a, argv[i], argv[i + 1]))
            return false;
        i++;
    }
    return a->url && a->user && a->passwordFile && a->trustN > 0;
}

typedef struct {
    gds_buf password;
    gds_buf trust[MAX_FILES], crl[MAX_FILES];
    size_t trustN, crlN;
} watch_files;

static void files_clear(watch_files *f) {
    gds_buf_free_secret(&f->password);
    for(size_t i = 0; i < f->trustN; i++)
        gds_buf_free(&f->trust[i]);
    for(size_t i = 0; i < f->crlN; i++)
        gds_buf_free(&f->crl[i]);
}

static gds_status load_files(const watch_args *a, watch_files *f) {
    gds_status r = gds_file_read(a->passwordFile, 1024, &f->password);
    while(r == GDS_OK && f->password.len > 0 &&
          (f->password.data[f->password.len - 1] == '\n' ||
           f->password.data[f->password.len - 1] == '\r'))
        f->password.len--;
    if(r == GDS_OK && f->password.len == 0)
        r = GDS_EINVAL;
    for(size_t i = 0; r == GDS_OK && i < a->trustN; i++, f->trustN++)
        r = gds_file_read(a->trust[i], GDS_MAX_CERT_SIZE, &f->trust[i]);
    for(size_t i = 0; r == GDS_OK && i < a->crlN; i++, f->crlN++)
        r = gds_file_read(a->crl[i], GDS_MAX_CRL_SIZE, &f->crl[i]);
    return r;
}

static void install_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_stop;
    sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGINT, &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);
}

/* Prints the queued events; false once --count is reached. */
static bool drain(UA_Client *c, event_queue *eq, type_cache *tc, const watch_args *a,
                  bool *inRefresh, long *printed) {
    bool more = !(a->count && *printed >= a->count);
    while(eq->n > 0) {
        queued_event *e = &eq->q[eq->head];
        if(is_type(&e->f[GW_EVENT_TYPE], UA_NS0ID_REFRESHSTARTEVENTTYPE)) {
            *inRefresh = true;
        } else if(is_type(&e->f[GW_EVENT_TYPE], UA_NS0ID_REFRESHENDEVENTTYPE)) {
            *inRefresh = false;
        } else if(more) {
            gdsadm_watch_print(stdout, a->json, e->f, type_name(c, tc, &e->f[GW_EVENT_TYPE]),
                               *inRefresh);
            if(a->count && ++*printed >= a->count)
                more = false;
        }
        for(size_t i = 0; i < GW_NFIELDS; i++)
            UA_Variant_clear(&e->f[i]);
        eq->head = (eq->head + 1) % QUEUE_MAX;
        eq->n--;
    }
    if(eq->dropped) {
        fprintf(stderr, "gdsadm: %zu events dropped (too many at once)\n", eq->dropped);
        eq->dropped = 0;
    }
    return more;
}

int gdsadm_watch(int argc, char **argv) {
    watch_args a;
    if(!parse(argc, argv, &a))
        return usage();
    watch_files f;
    memset(&f, 0, sizeof(f));
    gds_status st = load_files(&a, &f);
    if(st != GDS_OK) {
        fprintf(stderr, "gdsadm: reading the password, --trust or --crl: %s\n",
                gds_status_name(st));
        files_clear(&f);
        return 1;
    }
    gdsc_admin_cfg cfg = {a.url, a.user, &f.password, f.trust, f.trustN,
                          f.crlN ? f.crl : NULL, f.crlN, 0};
    UA_Client *c = NULL;
    UA_StatusCode r = gdsc_admin_connect(&cfg, &c);
    files_clear(&f);
    if(r != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "gdsadm: connecting to %s: %s\n", a.url, UA_StatusCode_name(r));
        return 1;
    }
    static event_queue eq;
    static type_cache tc;
    UA_UInt32 subId = 0;
    r = subscribe(c, &eq, &subId);
    if(r != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "gdsadm: event subscription: %s\n", UA_StatusCode_name(r));
        gdsc_admin_close(c);
        return 1;
    }
    UA_StatusCode rr = refresh(c, subId);
    if(rr != UA_STATUSCODE_GOOD)
        fprintf(stderr, "gdsadm: ConditionRefresh: %s (only new events are shown)\n",
                UA_StatusCode_name(rr));
    install_signals();
    UA_DateTime end = a.seconds ? UA_DateTime_nowMonotonic() + a.seconds * UA_DATETIME_SEC : 0;
    bool inRefresh = false;
    long printed = 0;
    int rc = 0;
    while(!stopRequested && (!end || UA_DateTime_nowMonotonic() < end)) {
        r = UA_Client_run_iterate(c, ITERATE_MS);
        if(!drain(c, &eq, &tc, &a, &inRefresh, &printed))
            break;
        if(r != UA_STATUSCODE_GOOD) {
            fprintf(stderr, "gdsadm: connection to %s lost: %s\n", a.url, UA_StatusCode_name(r));
            rc = 1;
            break;
        }
    }
    (void)drain(c, &eq, &tc, &a, &inRefresh, &printed); /* frees what is left */
    type_cache_clear(&tc);
    gdsc_admin_close(c);
    return rc;
}
