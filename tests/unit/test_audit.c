/* OpenGDS unit test: audit events of other parts (UASM ask A7, issue #18).
 * gds_server_raise_audit_event writes the event to the store's hash-chained
 * audit log first and raises it only after the commit, and only to the
 * sessions of the Roles it names (OPC 10000-21 §9.2.13 limits audit events
 * to SecurityAdmin). Two real clients over SignAndEncrypt, one SecurityAdmin
 * user and one anonymous, each subscribe to the Server object's events.
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
#include "gds_access.h"
#include "gds_plugin.h"
#include "gds_server.h"
#include "store.h"
#include "store_backend.h"
#include "common/banned.h"

#define TEST_URI "urn:opengds:test:audit"
#define CLIENT_URI "urn:opengds:test:audit:client"
#define AUDIT_NS "urn:opengds:test:auditor"
#define TYPE_ID 100
#define DETAIL_ID 101
#define PASSWORD "audit-pw-for-the-test"
#define WAIT_ITER 40

/* ---- a store backend that can refuse the audit append ---- */

static gds_store_backend refusing;
static int refuseAudit;

static gds_status audit_maybe(void *ctx, int64_t time, const gds_buf *body, int64_t *seq) {
    if(__atomic_load_n(&refuseAudit, __ATOMIC_SEQ_CST))
        return GDS_ENOTLEADER;
    return gds_store_sqlite_backend.audit_append(ctx, time, body, seq);
}

static gds_status open_store(const char *path, gds_store **out) {
    refusing = gds_store_sqlite_backend;
    refusing.audit_append = audit_maybe;
    void *ctx = NULL;
    gds_status st = gds_store_sqlite_open(path, false, &ctx);
    return st == GDS_OK ? gds_store_open_backend(&refusing, ctx, out) : st;
}

/* ---- the server loop thread ---- */

static volatile int running = 1;

static void *loop_main(void *arg) {
    UA_Server *ua = arg;
    while(__atomic_load_n(&running, __ATOMIC_SEQ_CST))
        (void)UA_Server_run_iterate(ua, true);
    return NULL;
}

/* ---- clients ---- */

typedef struct {
    int events;
    UA_String clientUserId;
    UA_String detail;
} received;

static bool make_cert(const char *cn, const char *uri, UA_ByteString *cert, UA_ByteString *key) {
    UA_String subject[] = {UA_STRING((char *)(uintptr_t)cn), UA_STRING_STATIC("O=OpenGDS")};
    UA_String san[] = {UA_STRING((char *)(uintptr_t)uri), UA_STRING_STATIC("DNS:localhost")};
    return UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER,
                                NULL, key, cert) == UA_STATUSCODE_GOOD;
}

static UA_Client *new_client(const UA_ByteString *cert, const UA_ByteString *key,
                             UA_ByteString *serverCert) {
    UA_ClientConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.logging = UA_Log_Stdout_new(UA_LOGLEVEL_WARNING);
    if(UA_ClientConfig_setDefault(&cfg) != UA_STATUSCODE_GOOD ||
       UA_ClientConfig_setDefaultEncryption(&cfg, *cert, *key, serverCert, 1, NULL, 0) !=
           UA_STATUSCODE_GOOD) {
        UA_ClientConfig_clear(&cfg);
        return NULL;
    }
    cfg.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    UA_String_clear(&cfg.securityPolicyUri);
    cfg.securityPolicyUri =
        UA_STRING_ALLOC("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
    UA_String_clear(&cfg.clientDescription.applicationUri);
    cfg.clientDescription.applicationUri = UA_STRING_ALLOC(CLIENT_URI);
    UA_Client *c = UA_Client_newWithConfig(&cfg);
    if(!c)
        UA_ClientConfig_clear(&cfg);
    return c;
}

/* The fields come in select-clause order. */
static void on_event(UA_Client *c, UA_UInt32 subId, void *subCtx, UA_UInt32 monId, void *monCtx,
                     const UA_KeyValueMap fields) {
    (void)c, (void)subId, (void)subCtx, (void)monId;
    received *r = monCtx;
    r->events++;
    UA_String_clear(&r->clientUserId);
    UA_String_clear(&r->detail);
    if(fields.mapSize != 3)
        return;
    const UA_Variant *user = &fields.map[1].value, *detail = &fields.map[2].value;
    if(UA_Variant_hasScalarType(user, &UA_TYPES[UA_TYPES_STRING]))
        (void)UA_String_copy(user->data, &r->clientUserId);
    if(UA_Variant_hasScalarType(detail, &UA_TYPES[UA_TYPES_STRING]))
        (void)UA_String_copy(detail->data, &r->detail);
}

/* EventType, AuditEventType.ClientUserId and the test type's Detail. */
static UA_StatusCode subscribe(UA_Client *c, UA_UInt16 ns, received *r) {
    UA_CreateSubscriptionRequest sreq = UA_CreateSubscriptionRequest_default();
    sreq.requestedPublishingInterval = 20.0;
    UA_CreateSubscriptionResponse sres =
        UA_Client_Subscriptions_create(c, sreq, NULL, NULL, NULL);
    UA_StatusCode res = sres.responseHeader.serviceResult;
    UA_UInt32 subId = sres.subscriptionId;
    UA_CreateSubscriptionResponse_clear(&sres);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_QualifiedName names[3] = {UA_QUALIFIEDNAME(0, "EventType"),
                                 UA_QUALIFIEDNAME(0, "ClientUserId"),
                                 UA_QUALIFIEDNAME(ns, "Detail")};
    UA_NodeId types[3] = {UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE),
                          UA_NODEID_NUMERIC(0, UA_NS0ID_AUDITEVENTTYPE),
                          UA_NODEID_NUMERIC(ns, TYPE_ID)};
    UA_SimpleAttributeOperand sel[3];
    for(size_t i = 0; i < 3; i++) {
        UA_SimpleAttributeOperand_init(&sel[i]);
        sel[i].typeDefinitionId = types[i];
        sel[i].browsePathSize = 1;
        sel[i].browsePath = &names[i];
        sel[i].attributeId = UA_ATTRIBUTEID_VALUE;
    }
    UA_EventFilter filter;
    UA_EventFilter_init(&filter);
    filter.selectClauses = sel;
    filter.selectClausesSize = 3;

    UA_MonitoredItemCreateRequest item;
    UA_MonitoredItemCreateRequest_init(&item);
    item.itemToMonitor.nodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER);
    item.itemToMonitor.attributeId = UA_ATTRIBUTEID_EVENTNOTIFIER;
    item.monitoringMode = UA_MONITORINGMODE_REPORTING;
    UA_ExtensionObject_setValue(&item.requestedParameters.filter, &filter,
                                &UA_TYPES[UA_TYPES_EVENTFILTER]);
    item.requestedParameters.queueSize = 16;
    UA_MonitoredItemCreateResult mr = UA_Client_MonitoredItems_createEvent(
        c, subId, UA_TIMESTAMPSTORETURN_NEITHER, item, r, on_event, NULL);
    res = mr.statusCode;
    UA_MonitoredItemCreateResult_clear(&mr);
    return res;
}

/* Lets both clients publish until `want` events have reached `a` (the
 * other client gets the same time to receive anything it should not). */
static void pump(UA_Client *a, UA_Client *b, const received *ra, int want) {
    for(int i = 0; i < WAIT_ITER; i++) {
        (void)UA_Client_run_iterate(a, 25);
        (void)UA_Client_run_iterate(b, 25);
        if(ra->events >= want && i >= WAIT_ITER / 2)
            break;
    }
}

/* ---- setup ---- */

static UA_UInt16 add_types(gds_server *s) {
    UA_UInt16 ns = 0;
    CHECK(gds_server_add_namespace(s, AUDIT_NS, &ns) == GDS_OK);
    UA_Server *ua = gds_server_ua(s);
    UA_ObjectTypeAttributes ta = UA_ObjectTypeAttributes_default;
    ta.displayName = UA_LOCALIZEDTEXT("", "TestAuditEventType");
    ta.isAbstract = true;
    CHECK(UA_Server_addObjectTypeNode(ua, UA_NODEID_NUMERIC(ns, TYPE_ID),
                                      UA_NODEID_NUMERIC(0, UA_NS0ID_AUDITUPDATEMETHODEVENTTYPE),
                                      UA_NODEID_NUMERIC(0, UA_NS0ID_HASSUBTYPE),
                                      UA_QUALIFIEDNAME(ns, "TestAuditEventType"), ta, NULL,
                                      NULL) == UA_STATUSCODE_GOOD);
    UA_VariableAttributes va = UA_VariableAttributes_default;
    va.displayName = UA_LOCALIZEDTEXT("", "Detail");
    va.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
    CHECK(UA_Server_addVariableNode(ua, UA_NODEID_NUMERIC(ns, DETAIL_ID),
                                    UA_NODEID_NUMERIC(ns, TYPE_ID),
                                    UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY),
                                    UA_QUALIFIEDNAME(ns, "Detail"),
                                    UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE), va, NULL,
                                    NULL) == UA_STATUSCODE_GOOD);
    return ns;
}

static gds_audit_event event(UA_UInt16 ns, const gds_event_field *f, const UA_NodeId *roles,
                             size_t nRoles) {
    gds_audit_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.abi_major = GDS_PLUGIN_ABI_MAJOR;
    ev.abi_minor = GDS_PLUGIN_ABI_MINOR;
    ev.struct_size = sizeof(ev);
    ev.eventType = UA_NODEID_NUMERIC(ns, TYPE_ID);
    ev.severity = 500;
    ev.message = "role switch";
    ev.status = true;
    ev.fields = f;
    ev.fieldsSize = 1;
    ev.visibleTo = roles;
    ev.visibleToSize = nRoles;
    return ev;
}

static bool is(const UA_String *a, const char *b) {
    UA_String bs = UA_STRING((char *)(uintptr_t)b);
    return UA_String_equal(a, &bs);
}

/* ---- cases ---- */

static void test_refused(gds_server *s, UA_UInt16 ns, gds_event_field *f) {
    UA_NodeId sec = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN);
    gds_audit_event ev = event(ns, f, &sec, 1);
    int64_t seq = 0;
    ev.eventType = UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE); /* not an audit type */
    CHECK(gds_server_raise_audit_event(s, NULL, &ev, &seq) == GDS_EINVAL);
    ev.eventType = UA_NODEID_NUMERIC(ns, 999); /* no such node */
    CHECK(gds_server_raise_audit_event(s, NULL, &ev, &seq) == GDS_EINVAL);
    ev.eventType = UA_NODEID_NUMERIC(ns, TYPE_ID);
    ev.visibleToSize = 0;
    CHECK(gds_server_raise_audit_event(s, NULL, &ev, &seq) == GDS_EINVAL);
    UA_NodeId notRole = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER);
    ev.visibleTo = &notRole;
    ev.visibleToSize = 1;
    CHECK(gds_server_raise_audit_event(s, NULL, &ev, &seq) == GDS_EINVAL);
    ev.visibleTo = &sec;
    ev.severity = 0;
    CHECK(gds_server_raise_audit_event(s, NULL, &ev, &seq) == GDS_EINVAL);
    ev.severity = 500;
    f->name = "a/b";
    CHECK(gds_server_raise_audit_event(s, NULL, &ev, &seq) == GDS_EINVAL);
    f->name = "Detail";
    ev.abi_major = GDS_PLUGIN_ABI_MAJOR + 1;
    CHECK(gds_server_raise_audit_event(s, NULL, &ev, &seq) == GDS_EINVAL);
    CHECK_EQ_INT(seq, 0);
}

static void test_delivery(gds_server *s, gds_store *st, UA_UInt16 ns, UA_Client *admin,
                          UA_Client *anon, received *ra, received *rn) {
    UA_String detail = UA_STRING_STATIC("primary to standby");
    gds_event_field f = {ns, "Detail", {0}};
    UA_Variant_setScalar(&f.value, &detail, &UA_TYPES[UA_TYPES_STRING]);
    test_refused(s, ns, &f);

    /* SecurityAdmin only */
    UA_NodeId sec = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN);
    gds_audit_event ev = event(ns, &f, &sec, 1);
    gds_caller caller;
    memset(&caller, 0, sizeof(caller));
    caller.userName = "sec";
    int64_t seq = 0;
    CHECK(gds_server_raise_audit_event(s, &caller, &ev, &seq) == GDS_OK);
    CHECK_EQ_INT(seq, 1);
    pump(admin, anon, ra, 1);
    CHECK_EQ_INT(ra->events, 1);
    CHECK_EQ_INT(rn->events, 0);
    CHECK(is(&ra->clientUserId, "sec"));
    CHECK(is(&ra->detail, "primary to standby"));

    /* the log refuses the append (a standby): nothing is raised */
    __atomic_store_n(&refuseAudit, 1, __ATOMIC_SEQ_CST);
    CHECK(gds_server_raise_audit_event(s, &caller, &ev, &seq) == GDS_ENOTLEADER);
    __atomic_store_n(&refuseAudit, 0, __ATOMIC_SEQ_CST);
    pump(admin, anon, ra, 2);
    CHECK_EQ_INT(ra->events, 1);

    /* Anonymous: every session */
    UA_NodeId anyone = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS);
    ev.visibleTo = &anyone;
    CHECK(gds_server_raise_audit_event(s, NULL, &ev, &seq) == GDS_OK);
    CHECK_EQ_INT(seq, 2);
    pump(admin, anon, ra, 2);
    CHECK_EQ_INT(ra->events, 2);
    CHECK_EQ_INT(rn->events, 1);
    CHECK(rn->clientUserId.length == 0);

    int64_t rows = 0, bad = -1;
    CHECK(gds_store_audit_verify(st, &rows, &bad) == GDS_OK);
    CHECK_EQ_INT(rows, 2);
    CHECK_EQ_INT(bad, 0);
}

static void run_clients(gds_server *s, gds_store *st, UA_UInt16 ns, UA_ByteString *serverCert,
                        const char *url) {
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    if(!CHECK(make_cert("CN=OpenGDS audit client", "URI:" CLIENT_URI, &cert, &key)))
        return;
    UA_Client *admin = new_client(&cert, &key, serverCert);
    UA_Client *anon = new_client(&cert, &key, serverCert);
    received ra = {0}, rn = {0};
    if(CHECK(admin && anon) &&
       CHECK(UA_Client_connectUsername(admin, url, "sec", PASSWORD) == UA_STATUSCODE_GOOD) &&
       CHECK(UA_Client_connect(anon, url) == UA_STATUSCODE_GOOD) &&
       CHECK(subscribe(admin, ns, &ra) == UA_STATUSCODE_GOOD) &&
       CHECK(subscribe(anon, ns, &rn) == UA_STATUSCODE_GOOD)) {
        pump(admin, anon, &ra, 0);
        test_delivery(s, st, ns, admin, anon, &ra, &rn);
    }
    if(admin)
        (void)UA_Client_disconnect(admin);
    if(anon)
        (void)UA_Client_disconnect(anon);
    UA_Client_delete(admin);
    UA_Client_delete(anon);
    UA_String_clear(&ra.clientUserId);
    UA_String_clear(&ra.detail);
    UA_String_clear(&rn.clientUserId);
    UA_String_clear(&rn.detail);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
}

static bool load_users(const char *dir, gds_users *u) {
    char path[1024], cred[256], line[512];
    static const uint8_t pw[] = PASSWORD;
    if(!CHECK(gds_path(path, sizeof(path), "%s/users", dir) == GDS_OK) ||
       !CHECK(gds_password_hash(pw, sizeof(pw) - 1, 10000, cred, sizeof(cred)) == GDS_OK))
        return false;
    int n = snprintf(line, sizeof(line), "sec SecurityAdmin %s\n", cred);
    return CHECK(n > 0 && (size_t)n < sizeof(line)) &&
           CHECK(gds_file_write_atomic(path, line, (size_t)n, 0600) == GDS_OK) &&
           CHECK(gds_users_load(path, u) == GDS_OK);
}

static void serve(gds_server *s, gds_store *st, UA_ByteString *cert, UA_UInt16 port) {
    UA_UInt16 ns = add_types(s);
    UA_Server *ua = gds_server_ua(s);
    if(!CHECK(UA_Server_run_startup(ua) == UA_STATUSCODE_GOOD))
        return;
    pthread_t loop;
    if(CHECK(pthread_create(&loop, NULL, loop_main, ua) == 0)) {
        char url[64];
        (void)snprintf(url, sizeof(url), "opc.tcp://127.0.0.1:%u", (unsigned)port);
        run_clients(s, st, ns, cert, url);
        __atomic_store_n(&running, 0, __ATOMIC_SEQ_CST);
        (void)pthread_join(loop, NULL);
    }
    (void)UA_Server_run_shutdown(ua);
}

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    /* Client and server share this process: with TZ unset, glibc's mktime
     * (UA_DateTime_localTimeUtcOffset) frees and re-allocates its zone name
     * on every call, under a lock ThreadSanitizer cannot see. */
    CHECK(setenv("TZ", "UTC", 1) == 0);
    tzset();
    char db[1024], caDir[1024];
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/store.db", argv[1]) == GDS_OK);
    CHECK(gds_path(caDir, sizeof(caDir), "%s/ca", argv[1]) == GDS_OK);
    (void)unlink(db);

    static uint8_t pw[] = "audit-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    gds_store *st = NULL;
    static gds_users users;
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    if(!CHECK(gds_ca_openssl_open(&cc, &ca) == GDS_OK) || !CHECK(open_store(db, &st) == GDS_OK) ||
       !CHECK(make_cert("CN=OpenGDS audit test", "URI:" TEST_URI, &cert, &key)) ||
       !load_users(argv[1], &users))
        return CHECK_DONE();

    gds_server_config cfg = {0};
    cfg.port = (UA_UInt16)(44000 + getpid() % 2000);
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS audit test";
    cfg.ownCert = (gds_buf){cert.data, cert.length};
    cfg.ownKey = (gds_buf){key.data, key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.autoApprove = true;
    gds_server *s = NULL;
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s)
        serve(s, st, &cert, cfg.port);
    gds_server_delete(s);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    gds_store_close(st);
    gds_ca_close(ca);
    return CHECK_DONE();
}
