/* OpenGDS unit test: plugin alarms (UASM ask A16, gds_alarms.c).
 *
 * A plugin adds OffNormalAlarmType instances under its own object and
 * raises and clears them (OPC 10000-9 §5.8): ActiveState, Severity,
 * LastSeverity, Message and Retain follow, and each change fires the
 * alarm's event. An alarm with ackRoles turns Unacknowledged on activation
 * and stays retained until a session with one of the Roles acknowledges it
 * with its last EventId (§5.7.3); refused and accepted acknowledgements are
 * audited. Over a real client, the events reach a subscription on the
 * Server object, set from another thread, and ConditionRefresh (§5.5.7)
 * replays the retained alarm between RefreshStart and RefreshEnd.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>
#include <open62541/nodeids.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ca.h"
#include "check.h"
#include "common/buf.h"
#include "gds_internal.h"
#include "gds_plugin.h"
#include "gds_server.h"
#include "store.h"
#include "common/banned.h"

#define TEST_URI "urn:opengds:test:alarms"
#define CLIENT_URI "urn:opengds:test:alarms:client"
#define PLUGIN_NS "urn:opengds:test:alarms:plugin"
#define ACK_METHOD UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE_ACKNOWLEDGE

static UA_UInt16 ns;
static gds_session admin, outsider;

/* ---- reading condition fields ---- */

static bool read_path(gds_server *s, const UA_NodeId *c, const char *a, const char *b,
                      const UA_DataType *t, void *out) {
    UA_QualifiedName path[2] = {UA_QUALIFIEDNAME(0, (char *)(uintptr_t)a),
                                UA_QUALIFIEDNAME(0, (char *)(uintptr_t)(b ? b : ""))};
    UA_BrowsePathResult bp =
        UA_Server_browseSimplifiedBrowsePath(gds_server_ua(s), *c, b ? 2 : 1, path);
    bool ok = false;
    if(bp.statusCode == UA_STATUSCODE_GOOD && bp.targetsSize == 1) {
        UA_Variant v;
        if(UA_Server_readValue(gds_server_ua(s), bp.targets[0].targetId.nodeId, &v) ==
               UA_STATUSCODE_GOOD &&
           UA_Variant_hasScalarType(&v, t)) {
            ok = UA_copy(v.data, out, t) == UA_STATUSCODE_GOOD;
        }
        UA_Variant_clear(&v);
    }
    UA_BrowsePathResult_clear(&bp);
    return ok;
}

static bool flag(gds_server *s, const UA_NodeId *c, const char *a, const char *b) {
    UA_Boolean v = false;
    return read_path(s, c, a, b, &UA_TYPES[UA_TYPES_BOOLEAN], &v) && v;
}

static int u16(gds_server *s, const UA_NodeId *c, const char *a) {
    UA_UInt16 v = 0;
    return read_path(s, c, a, NULL, &UA_TYPES[UA_TYPES_UINT16], &v) ? v : -1;
}

static bool message_is(gds_server *s, const UA_NodeId *c, const char *text) {
    UA_LocalizedText lt;
    UA_LocalizedText_init(&lt);
    bool ok = read_path(s, c, "Message", NULL, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT], &lt) &&
              lt.text.length == strlen(text) && memcmp(lt.text.data, text, lt.text.length) == 0;
    UA_LocalizedText_clear(&lt);
    return ok;
}

static void iterate(gds_server *s) {
    for(int i = 0; i < 20; i++)
        (void)UA_Server_run_iterate(gds_server_ua(s), false);
}

static int64_t audit_rows(gds_server *s) {
    int64_t rows = 0, bad = 0;
    gds_lock(s);
    CHECK(gds_store_audit_verify(s->store, &rows, &bad) == GDS_OK && bad == 0);
    gds_unlock(s);
    return rows;
}

static UA_StatusCode ack(gds_server *s, gds_session *as, const UA_NodeId *c,
                         const UA_ByteString *eventId) {
    UA_Variant in[2];
    UA_LocalizedText comment = UA_LOCALIZEDTEXT("en", "seen");
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)eventId, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&in[1], &comment, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = *c;
    req.methodId = UA_NODEID_NUMERIC(0, ACK_METHOD);
    req.inputArguments = in;
    req.inputArgumentsSize = 2;
    UA_Server_setAdminSessionContext(gds_server_ua(s), as);
    UA_CallMethodResult res = UA_Server_call(gds_server_ua(s), &req);
    UA_Server_setAdminSessionContext(gds_server_ua(s), &admin);
    UA_StatusCode r = res.statusCode;
    UA_CallMethodResult_clear(&res);
    return r;
}

/* ---- setup ---- */

static UA_NodeId source(void) {
    return UA_NODEID_STRING(ns, "KeyService");
}

static gds_alarm_def def_of(const char *name, const UA_NodeId *ackRoles, size_t n) {
    gds_alarm_def d;
    memset(&d, 0, sizeof(d));
    d.abi_major = GDS_PLUGIN_ABI_MAJOR;
    d.abi_minor = GDS_PLUGIN_ABI_MINOR;
    d.struct_size = sizeof(d);
    d.sourceNode = source();
    d.name = name;
    d.ackRoles = ackRoles;
    d.ackRolesSize = n;
    return d;
}

static void setup(gds_server *s, gds_alarm **plain, gds_alarm **acked) {
    CHECK(gds_server_add_namespace(s, PLUGIN_NS, &ns) == GDS_OK);
    UA_NodeId src = source(), objects = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    CHECK(gds_server_add_object(s, &src, &objects, "KeyService", NULL) == GDS_OK);

    static const UA_NodeId secAdmin = {0, UA_NODEIDTYPE_NUMERIC,
                                       {UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN}};
    gds_alarm_def d = def_of("KeysExhausted", NULL, 0);
    CHECK(gds_server_add_alarm(s, &d, plain) == GDS_OK && *plain);
    d = def_of("MajorityLost", &secAdmin, 1);
    d.alarmId = UA_NODEID_STRING(ns, "MajorityLost");
    CHECK(gds_server_add_alarm(s, &d, acked) == GDS_OK && *acked);

    /* refused definitions */
    gds_alarm *x = NULL;
    CHECK(gds_server_add_alarm(s, &d, &x) == GDS_EEXISTS && !x); /* NodeId taken */
    d = def_of("", NULL, 0);
    CHECK(gds_server_add_alarm(s, &d, &x) == GDS_EINVAL);
    d = def_of("Nowhere", NULL, 0);
    d.sourceNode = UA_NODEID_STRING(ns, "NoSuchObject");
    CHECK(gds_server_add_alarm(s, &d, &x) == GDS_ENOTFOUND);
    d.sourceNode = UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY);
    CHECK(gds_server_add_alarm(s, &d, &x) == GDS_EDENIED);
    d = def_of("NotAnAlarm", NULL, 0);
    d.alarmType = UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE); /* no ActiveState */
    CHECK(gds_server_add_alarm(s, &d, &x) == GDS_EINVAL);
    d = def_of("BadRole", NULL, 0);
    UA_NodeId noRole = UA_NODEID_STRING(ns, "NoRole");
    d.ackRoles = &noRole;
    d.ackRolesSize = 1;
    CHECK(gds_server_add_alarm(s, &d, &x) == GDS_EINVAL);
    d = def_of("Old", NULL, 0);
    d.abi_major = GDS_PLUGIN_ABI_MAJOR + 1;
    CHECK(gds_server_add_alarm(s, &d, &x) == GDS_EINVAL);
    CHECK(gds_server_set_alarm(*plain, true, 0, NULL) == GDS_EINVAL);
    CHECK(gds_server_set_alarm(*plain, true, 1001, NULL) == GDS_EINVAL);
}

/* ---- in-process cases ---- */

/* The alarm's NodeId, found under its source by BrowseName. */
static UA_NodeId child(gds_server *s, const char *name) {
    UA_QualifiedName qn = UA_QUALIFIEDNAME(ns, (char *)(uintptr_t)name);
    UA_BrowsePathResult bp = UA_Server_browseSimplifiedBrowsePath(gds_server_ua(s), source(), 1, &qn);
    UA_NodeId id = UA_NODEID_NULL;
    if(bp.statusCode == UA_STATUSCODE_GOOD && bp.targetsSize == 1)
        (void)UA_NodeId_copy(&bp.targets[0].targetId.nodeId, &id);
    UA_BrowsePathResult_clear(&bp);
    return id;
}

static void test_plain(gds_server *s, gds_alarm *a) {
    UA_NodeId c = child(s, "KeysExhausted");
    if(!CHECK(!UA_NodeId_isNull(&c)))
        return;
    /* the initial state */
    CHECK(flag(s, &c, "EnabledState", "Id"));
    CHECK(!flag(s, &c, "ActiveState", "Id"));
    CHECK(flag(s, &c, "AckedState", "Id"));
    CHECK(!flag(s, &c, "Retain", NULL));

    CHECK(gds_server_set_alarm(a, true, 900, "No pre-generated keys left") == GDS_OK);
    iterate(s);
    CHECK(flag(s, &c, "ActiveState", "Id"));
    CHECK(flag(s, &c, "Retain", NULL));
    CHECK(flag(s, &c, "AckedState", "Id")); /* no acknowledgement needed */
    CHECK_EQ_INT(u16(s, &c, "Severity"), 900);
    CHECK(message_is(s, &c, "No pre-generated keys left"));

    /* queued calls apply in order */
    CHECK(gds_server_set_alarm(a, true, 950, "Still none") == GDS_OK);
    CHECK(gds_server_set_alarm(a, false, 100, "Keys available again") == GDS_OK);
    iterate(s);
    CHECK(!flag(s, &c, "ActiveState", "Id"));
    CHECK(!flag(s, &c, "Retain", NULL));
    CHECK_EQ_INT(u16(s, &c, "Severity"), 100);
    CHECK_EQ_INT(u16(s, &c, "LastSeverity"), 950);
    CHECK(message_is(s, &c, "Keys available again"));

    /* nobody acknowledges an alarm without ackRoles */
    UA_ByteString none = UA_BYTESTRING_NULL;
    CHECK_EQ_INT(ack(s, &admin, &c, &none), UA_STATUSCODE_BADUSERACCESSDENIED);
    UA_NodeId_clear(&c);
}

static void test_acked(gds_server *s, gds_alarm *a) {
    UA_NodeId c = UA_NODEID_STRING(ns, "MajorityLost");
    CHECK(gds_server_set_alarm(a, true, 1000, "Majority lost") == GDS_OK);
    iterate(s);
    CHECK(flag(s, &c, "ActiveState", "Id"));
    CHECK(!flag(s, &c, "AckedState", "Id"));
    CHECK(flag(s, &c, "Retain", NULL));
    CHECK(gds_server_set_alarm(a, false, 500, "Majority back") == GDS_OK);
    iterate(s);
    CHECK(!flag(s, &c, "ActiveState", "Id"));
    CHECK(flag(s, &c, "Retain", NULL)); /* still unacknowledged */

    UA_ByteString eventId = UA_BYTESTRING_NULL;
    CHECK(gds_alarm_last_event_id(a, &eventId) == UA_STATUSCODE_GOOD && eventId.length > 0);
    UA_ByteString wrong = UA_BYTESTRING("not-an-event");
    int64_t rows = audit_rows(s);
    CHECK_EQ_INT(ack(s, &outsider, &c, &eventId), UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(ack(s, &admin, &c, &wrong), UA_STATUSCODE_BADEVENTIDUNKNOWN);
    CHECK_EQ_INT(ack(s, &admin, &c, &eventId), UA_STATUSCODE_GOOD);
    CHECK(flag(s, &c, "AckedState", "Id"));
    CHECK(!flag(s, &c, "Retain", NULL));
    /* the refused and the accepted acknowledgement, not the denied call */
    CHECK_EQ_INT(audit_rows(s), rows + 2);
    UA_ByteString_clear(&eventId);
    CHECK(gds_alarm_last_event_id(a, &eventId) == UA_STATUSCODE_GOOD && eventId.length > 0);
    CHECK_EQ_INT(ack(s, &admin, &c, &eventId), UA_STATUSCODE_BADCONDITIONDISABLED);

    /* active and acknowledged: retained until it clears */
    CHECK(gds_server_set_alarm(a, true, 1000, "Majority lost") == GDS_OK);
    iterate(s);
    UA_ByteString_clear(&eventId);
    CHECK(gds_alarm_last_event_id(a, &eventId) == UA_STATUSCODE_GOOD && eventId.length > 0);
    CHECK_EQ_INT(ack(s, &admin, &c, &eventId), UA_STATUSCODE_GOOD);
    CHECK(flag(s, &c, "Retain", NULL));
    UA_ByteString_clear(&eventId);
    CHECK(gds_alarm_last_event_id(a, &eventId) == UA_STATUSCODE_GOOD && eventId.length > 0);
    CHECK_EQ_INT(ack(s, &admin, &c, &eventId), UA_STATUSCODE_BADCONDITIONBRANCHALREADYACKED);
    CHECK(gds_server_set_alarm(a, false, 500, "Majority back") == GDS_OK);
    iterate(s);
    CHECK(!flag(s, &c, "Retain", NULL));
    UA_ByteString_clear(&eventId);
}

/* ---- over a client ---- */

typedef struct {
    UA_UInt32 type;
    UA_UInt16 severity;
    bool retain;
    bool active;
} seen_event;

static pthread_mutex_t seenLock = PTHREAD_MUTEX_INITIALIZER;
static seen_event seen[64];
static size_t nSeen;

/* The fields come in the order of the select clauses. */
static void on_event(UA_Client *c, UA_UInt32 subId, void *subCtx, UA_UInt32 monId, void *monCtx,
                     const UA_KeyValueMap fields) {
    (void)c, (void)subId, (void)subCtx, (void)monId, (void)monCtx;
    size_t n = fields.mapSize;
    UA_Variant f[4];
    for(size_t i = 0; i < 4; i++)
        f[i] = i < n ? fields.map[i].value : (UA_Variant){0};
    seen_event e = {0, 0, false, false};
    if(n == 4 && UA_Variant_hasScalarType(&f[0], &UA_TYPES[UA_TYPES_NODEID])) {
        const UA_NodeId *t = f[0].data;
        if(t->namespaceIndex == 0 && t->identifierType == UA_NODEIDTYPE_NUMERIC)
            e.type = t->identifier.numeric;
    }
    if(n == 4 && UA_Variant_hasScalarType(&f[1], &UA_TYPES[UA_TYPES_UINT16]))
        e.severity = *(UA_UInt16 *)f[1].data;
    if(n == 4 && UA_Variant_hasScalarType(&f[2], &UA_TYPES[UA_TYPES_BOOLEAN]))
        e.retain = *(UA_Boolean *)f[2].data;
    if(n == 4 && UA_Variant_hasScalarType(&f[3], &UA_TYPES[UA_TYPES_BOOLEAN]))
        e.active = *(UA_Boolean *)f[3].data;
    pthread_mutex_lock(&seenLock);
    if(nSeen < sizeof(seen) / sizeof(seen[0]))
        seen[nSeen++] = e;
    pthread_mutex_unlock(&seenLock);
}

static size_t seen_count(void) {
    pthread_mutex_lock(&seenLock);
    size_t n = nSeen;
    pthread_mutex_unlock(&seenLock);
    return n;
}

static void seen_reset(void) {
    pthread_mutex_lock(&seenLock);
    nSeen = 0;
    pthread_mutex_unlock(&seenLock);
}

/* Runs the client until n events arrived or 10 s passed. */
static bool wait_events(UA_Client *c, size_t n) {
    for(int i = 0; i < 200 && seen_count() < n; i++)
        (void)UA_Client_run_iterate(c, 50);
    for(int i = 0; i < 4; i++) /* and a little more: nothing extra may come */
        (void)UA_Client_run_iterate(c, 50);
    if(seen_count() != n) {
        pthread_mutex_lock(&seenLock);
        for(size_t i = 0; i < nSeen; i++)
            fprintf(stderr, "event %zu: type %u severity %u retain %d active %d\n", i,
                    seen[i].type, seen[i].severity, seen[i].retain, seen[i].active);
        pthread_mutex_unlock(&seenLock);
    }
    return seen_count() == n;
}

static UA_SimpleAttributeOperand select_of(UA_UInt32 type, UA_QualifiedName *path, size_t n) {
    UA_SimpleAttributeOperand o;
    UA_SimpleAttributeOperand_init(&o);
    o.typeDefinitionId = UA_NODEID_NUMERIC(0, type);
    o.browsePath = path;
    o.browsePathSize = n;
    o.attributeId = UA_ATTRIBUTEID_VALUE;
    return o;
}

static UA_StatusCode subscribe(UA_Client *c, UA_UInt32 *subId) {
    UA_CreateSubscriptionResponse sr = UA_Client_Subscriptions_create(
        c, UA_CreateSubscriptionRequest_default(), NULL, NULL, NULL);
    UA_StatusCode r = sr.responseHeader.serviceResult;
    *subId = sr.subscriptionId;
    UA_CreateSubscriptionResponse_clear(&sr);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    static UA_QualifiedName type = {0, UA_STRING_STATIC("EventType")};
    static UA_QualifiedName sev = {0, UA_STRING_STATIC("Severity")};
    static UA_QualifiedName retain = {0, UA_STRING_STATIC("Retain")};
    static UA_QualifiedName active[2] = {{0, UA_STRING_STATIC("ActiveState")},
                                         {0, UA_STRING_STATIC("Id")}};
    UA_SimpleAttributeOperand sel[4] = {
        select_of(UA_NS0ID_BASEEVENTTYPE, &type, 1), select_of(UA_NS0ID_BASEEVENTTYPE, &sev, 1),
        select_of(UA_NS0ID_CONDITIONTYPE, &retain, 1),
        select_of(UA_NS0ID_ALARMCONDITIONTYPE, active, 2)};
    UA_EventFilter filter;
    UA_EventFilter_init(&filter);
    filter.selectClauses = sel;
    filter.selectClausesSize = 4;
    UA_MonitoredItemCreateRequest item =
        UA_MonitoredItemCreateRequest_default(UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER));
    item.itemToMonitor.attributeId = UA_ATTRIBUTEID_EVENTNOTIFIER;
    item.monitoringMode = UA_MONITORINGMODE_REPORTING;
    item.requestedParameters.queueSize = 64;
    UA_ExtensionObject_setValue(&item.requestedParameters.filter, &filter,
                                &UA_TYPES[UA_TYPES_EVENTFILTER]);
    UA_MonitoredItemCreateResult mr = UA_Client_MonitoredItems_createEvent(
        c, *subId, UA_TIMESTAMPSTORETURN_BOTH, item, NULL, on_event, NULL);
    r = mr.statusCode;
    UA_MonitoredItemCreateResult_clear(&mr);
    return r;
}

static UA_StatusCode refresh(UA_Client *c, UA_UInt32 subId) {
    UA_Variant in;
    UA_Variant_setScalar(&in, &subId, &UA_TYPES[UA_TYPES_UINT32]);
    size_t nOut = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = UA_Client_call(c, UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE),
                                     UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE_CONDITIONREFRESH),
                                     1, &in, &nOut, &out);
    UA_Array_delete(out, nOut, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

static bool seen_is(size_t i, UA_UInt32 type, int severity, bool retain, bool active) {
    pthread_mutex_lock(&seenLock);
    bool ok = i < nSeen && seen[i].type == type &&
              (severity < 0 || seen[i].severity == severity) &&
              (type != UA_NS0ID_OFFNORMALALARMTYPE ||
               (seen[i].retain == retain && seen[i].active == active));
    pthread_mutex_unlock(&seenLock);
    return ok;
}

static void client_events(UA_Client *c, gds_alarm *a, UA_NodeId child_id) {
    UA_UInt32 subId = 0;
    if(!CHECK_EQ_INT(subscribe(c, &subId), UA_STATUSCODE_GOOD))
        return;
    (void)wait_events(c, 0);
    seen_reset();
    /* set from this thread while the server thread runs */
    CHECK(gds_server_set_alarm(a, true, 800, "No pre-generated keys left") == GDS_OK);
    CHECK(wait_events(c, 1));
    CHECK(seen_is(0, UA_NS0ID_OFFNORMALALARMTYPE, 800, true, true));

    seen_reset();
    CHECK_EQ_INT(refresh(c, subId), UA_STATUSCODE_GOOD);
    CHECK(wait_events(c, 3));
    CHECK(seen_is(0, UA_NS0ID_REFRESHSTARTEVENTTYPE, -1, false, false));
    CHECK(seen_is(1, UA_NS0ID_OFFNORMALALARMTYPE, 800, true, true));
    CHECK(seen_is(2, UA_NS0ID_REFRESHENDEVENTTYPE, -1, false, false));

    /* access control: an anonymous session may not Acknowledge */
    UA_ByteString eventId = UA_BYTESTRING("x");
    UA_LocalizedText comment = UA_LOCALIZEDTEXT("en", "seen");
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &eventId, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&in[1], &comment, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    size_t nOut = 0;
    UA_Variant *out = NULL;
    UA_NodeId plain = child_id;
    CHECK_EQ_INT(UA_Client_call(c, plain, UA_NODEID_NUMERIC(0, ACK_METHOD), 2, in, &nOut, &out),
                 UA_STATUSCODE_BADUSERACCESSDENIED);
    UA_Array_delete(out, nOut, &UA_TYPES[UA_TYPES_VARIANT]);

    seen_reset();
    CHECK(gds_server_set_alarm(a, false, 200, "Keys available again") == GDS_OK);
    CHECK(wait_events(c, 1));
    CHECK(seen_is(0, UA_NS0ID_OFFNORMALALARMTYPE, 200, false, false));

    /* cleared and needing no acknowledgement: not retained, not replayed */
    seen_reset();
    CHECK_EQ_INT(refresh(c, subId), UA_STATUSCODE_GOOD);
    CHECK(wait_events(c, 2));
    CHECK(seen_is(0, UA_NS0ID_REFRESHSTARTEVENTTYPE, -1, false, false));
    CHECK(seen_is(1, UA_NS0ID_REFRESHENDEVENTTYPE, -1, false, false));
}

/* ---- the server thread ---- */

static UA_Boolean running = true;
static gds_status runResult = GDS_EIO;

static void *loop_main(void *arg) {
    runResult = gds_server_run(arg, &running);
    return NULL;
}

static void stop_cb(UA_Server *ua, void *data) {
    (void)ua;
    *(UA_Boolean *)data = false;
}

static UA_Client *new_client(UA_ByteString *serverCert) {
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    UA_String subject[] = {UA_STRING_STATIC("CN=alarms client"), UA_STRING_STATIC("O=OpenGDS")};
    UA_String san[] = {UA_STRING_STATIC("URI:" CLIENT_URI), UA_STRING_STATIC("DNS:localhost")};
    UA_ClientConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.logging = UA_Log_Stdout_new(UA_LOGLEVEL_WARNING);
    UA_Client *c = NULL;
    if(UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER, NULL,
                            &key, &cert) == UA_STATUSCODE_GOOD &&
       UA_ClientConfig_setDefault(&cfg) == UA_STATUSCODE_GOOD &&
       UA_ClientConfig_setDefaultEncryption(&cfg, cert, key, serverCert, 1, NULL, 0) ==
           UA_STATUSCODE_GOOD) {
        cfg.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
        UA_String_clear(&cfg.securityPolicyUri);
        cfg.securityPolicyUri =
            UA_STRING_ALLOC("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
        UA_String_clear(&cfg.clientDescription.applicationUri);
        cfg.clientDescription.applicationUri = UA_STRING_ALLOC(CLIENT_URI);
        c = UA_Client_newWithConfig(&cfg);
    }
    if(!c)
        UA_ClientConfig_clear(&cfg);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    return c;
}

static void test_served(gds_server *s, gds_alarm *a, UA_ByteString *serverCert, UA_UInt16 port) {
    UA_NodeId cid = child(s, "KeysExhausted");
    pthread_t loop;
    if(!CHECK(pthread_create(&loop, NULL, loop_main, s) == 0))
        return;
    char url[64];
    (void)snprintf(url, sizeof(url), "opc.tcp://127.0.0.1:%u", (unsigned)port);
    UA_Client *c = new_client(serverCert);
    UA_StatusCode r = UA_STATUSCODE_BADINTERNALERROR;
    for(int i = 0; c && i < 50 && r != UA_STATUSCODE_GOOD; i++) { /* the server is starting */
        r = UA_Client_connect(c, url);
        if(r != UA_STATUSCODE_GOOD)
            usleep(100000);
    }
    if(CHECK_EQ_INT(r, UA_STATUSCODE_GOOD))
        client_events(c, a, cid);
    if(c) {
        (void)UA_Client_disconnect(c);
        UA_Client_delete(c);
    }
    (void)UA_Server_addTimedCallback(gds_server_ua(s), stop_cb, &running,
                                     UA_DateTime_nowMonotonic(), NULL);
    (void)pthread_join(loop, NULL);
    CHECK_EQ_INT(runResult, GDS_OK);
    UA_NodeId_clear(&cid);
}

int main(int argc, char **argv) {
    if(argc != 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    /* clients and server share this process (see test_audit.c) */
    CHECK(setenv("TZ", "UTC", 1) == 0);
    tzset();
    char db[1024], caDir[1024];
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/store.db", argv[1]) == GDS_OK);
    CHECK(gds_path(caDir, sizeof(caDir), "%s/ca", argv[1]) == GDS_OK);
    (void)unlink(db);

    static uint8_t pw[] = "alarms-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    gds_store *st = NULL;
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    UA_String subject[] = {UA_STRING_STATIC("CN=OpenGDS alarms test")};
    UA_String san[] = {UA_STRING_STATIC("URI:" TEST_URI), UA_STRING_STATIC("DNS:localhost")};
    if(!CHECK(gds_ca_openssl_open(&cc, &ca) == GDS_OK) || !CHECK(gds_store_open(db, &st) == GDS_OK) ||
       !CHECK(UA_CreateCertificate(UA_Log_Stdout, subject, 1, san, 2, UA_CERTIFICATEFORMAT_DER,
                                   NULL, &key, &cert) == UA_STATUSCODE_GOOD))
        return CHECK_DONE();

    admin.roles = GDS_ROLE_SECURITY_ADMIN;
    admin.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    memcpy(admin.user, "operator", sizeof("operator"));
    outsider.anonymous = true;
    outsider.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;

    static gds_users users;
    UA_UInt16 port = (UA_UInt16)(47000 + getpid() % 1000);
    gds_server_config cfg = {0};
    cfg.port = port;
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS alarms test";
    cfg.ownCert = (gds_buf){cert.data, cert.length};
    cfg.ownKey = (gds_buf){key.data, key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_ALL;

    gds_server *s = NULL;
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s) {
        gds_alarm *plain = NULL, *acked = NULL;
        UA_Server_setAdminSessionContext(gds_server_ua(s), &admin);
        setup(s, &plain, &acked);
        if(plain && acked) {
            test_plain(s, plain);
            test_acked(s, acked);
        }
        UA_Server_setAdminSessionContext(gds_server_ua(s), NULL);
        if(plain)
            test_served(s, plain, &cert, port);
    }
    gds_server_delete(s);

    gds_store_close(st);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    gds_ca_close(ca);
    return CHECK_DONE();
}
