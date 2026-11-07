/* OpenGDS unit test: plugin dialogs and Role-filtered condition events
 * (UASM ask A19, gds_dialogs.c, open62541 patch 0006).
 *
 * A plugin opens DialogConditionType instances under its own object
 * (OPC 10000-9 §5.6). Over real clients: a dialog with visibleTo
 * SecurityAdmin reaches only the SecurityAdmin's subscription, live and in
 * ConditionRefresh (§5.5.7), while an open dialog reaches both; only the
 * respondRoles may Respond; the response index and the active state are
 * checked; the plugin's callback runs off the server thread and may refuse
 * a response; an accepted Respond2 closes the dialog (LastResponse,
 * Comment, DialogState Inactive, Retain false); removing an active dialog
 * closes it first.
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
#include <unistd.h>

#include "ca.h"
#include "check.h"
#include "common/buf.h"
#include "gds_internal.h"
#include "gds_plugin.h"
#include "gds_server.h"
#include "store.h"
#include "common/banned.h"

#define TEST_URI "urn:opengds:test:dialogs"
#define CLIENT_URI "urn:opengds:test:dialogs:client"
#define PLUGIN_NS "urn:opengds:test:dialogs:fleet"
#define PASSWORD "dialogs-pw-for-the-test"
#define DIALOG_TYPE UA_NS0ID_DIALOGCONDITIONTYPE

static UA_UInt16 ns;
static const UA_NodeId secAdmin = {0, UA_NODEIDTYPE_NUMERIC,
                                   {UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN}};
static pthread_t serverThread;

/* ---- the plugin's callback ---- */

static pthread_mutex_t cbLock = PTHREAD_MUTEX_INITIALIZER;
static int cbCalls;
static bool cbOffServerThread = true;
static char cbUser[64], cbComment[64];

static UA_StatusCode on_respond(void *ctx, const gds_caller *caller, const UA_NodeId *dialogId,
                                int32_t selected, const UA_LocalizedText *comment) {
    (void)ctx, (void)dialogId;
    pthread_mutex_lock(&cbLock);
    cbCalls++;
    if(pthread_equal(pthread_self(), serverThread))
        cbOffServerThread = false;
    (void)snprintf(cbUser, sizeof(cbUser), "%s", caller->userName ? caller->userName : "");
    cbComment[0] = '\0';
    if(comment)
        (void)snprintf(cbComment, sizeof(cbComment), "%.*s", (int)comment->text.length,
                       (const char *)comment->text.data);
    pthread_mutex_unlock(&cbLock);
    /* "Later" is refused by the plugin itself */
    return selected == 1 ? UA_STATUSCODE_BADDIALOGRESPONSEINVALID : UA_STATUSCODE_GOOD;
}

static int cb_calls(void) {
    pthread_mutex_lock(&cbLock);
    int n = cbCalls;
    pthread_mutex_unlock(&cbLock);
    return n;
}

/* ---- setup ---- */

static UA_NodeId source(void) {
    return UA_NODEID_STRING(ns, "FleetDiscovery");
}

static const char *const OPTIONS[] = {"Register", "Later", "Ignore"};

static gds_dialog_def def_of(const char *name, bool restricted) {
    gds_dialog_def d;
    memset(&d, 0, sizeof(d));
    d.abi_major = GDS_PLUGIN_ABI_MAJOR;
    d.abi_minor = GDS_PLUGIN_ABI_MINOR;
    d.struct_size = sizeof(d);
    d.sourceNode = source();
    d.name = name;
    d.message = "Found opc.tcp://plc-7:4840";
    d.prompt = "Register and manage this server?";
    d.responseOptions = OPTIONS;
    d.responseOptionsSize = 3;
    d.defaultResponse = 0;
    d.okResponse = 0;
    d.cancelResponse = 2;
    d.severity = 300;
    d.respondRoles = &secAdmin;
    d.respondRolesSize = 1;
    d.visibleTo = restricted ? &secAdmin : NULL;
    d.visibleToSize = restricted ? 1 : 0;
    d.respond = on_respond;
    return d;
}

static void setup(gds_server *s) {
    CHECK(gds_server_add_namespace(s, PLUGIN_NS, &ns) == GDS_OK);
    UA_NodeId src = source(), objects = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    CHECK(gds_server_add_object(s, &src, &objects, "FleetDiscovery", NULL) == GDS_OK);
    /* refused definitions */
    UA_NodeId id;
    gds_dialog_def d = def_of("Bad", false);
    d.responseOptionsSize = 0;
    CHECK(gds_server_add_dialog(s, &d, &id) == GDS_EINVAL);
    d = def_of("Bad", false);
    d.okResponse = 3;
    CHECK(gds_server_add_dialog(s, &d, &id) == GDS_EINVAL);
    d = def_of("Bad", false);
    d.respondRolesSize = 0;
    CHECK(gds_server_add_dialog(s, &d, &id) == GDS_EINVAL);
    d = def_of("Bad", false);
    d.respond = NULL;
    CHECK(gds_server_add_dialog(s, &d, &id) == GDS_EINVAL);
    d = def_of("Bad", false);
    d.sourceNode = UA_NODEID_STRING(ns, "NoSuchObject");
    CHECK(gds_server_add_dialog(s, &d, &id) == GDS_ENOTFOUND);
    d.sourceNode = UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY);
    CHECK(gds_server_add_dialog(s, &d, &id) == GDS_EDENIED);
    d = def_of("Bad", true);
    UA_NodeId noRole = UA_NODEID_STRING(ns, "NoRole");
    d.visibleTo = &noRole;
    CHECK(gds_server_add_dialog(s, &d, &id) == GDS_EINVAL);
    UA_NodeId missing = UA_NODEID_STRING(ns, "NoSuchDialog");
    CHECK(gds_server_remove_dialog(s, &missing) == GDS_ENOTFOUND);
}

/* ---- events, per client ---- */

typedef struct {
    UA_UInt32 type;
    bool retain, dialogActive;
} seen_event;

typedef struct {
    pthread_mutex_t lock;
    seen_event ev[64];
    size_t n;
} seen_list;

static seen_list seenAdmin = {PTHREAD_MUTEX_INITIALIZER, {{0}}, 0};
static seen_list seenPlain = {PTHREAD_MUTEX_INITIALIZER, {{0}}, 0};

static void on_event(UA_Client *c, UA_UInt32 subId, void *subCtx, UA_UInt32 monId, void *monCtx,
                     const UA_KeyValueMap fields) {
    (void)c, (void)subId, (void)subCtx, (void)monId;
    seen_list *l = monCtx;
    seen_event e = {0, false, false};
    const UA_Variant *f = fields.mapSize == 3 ? &fields.map[0].value : NULL;
    if(f && UA_Variant_hasScalarType(&f[0], &UA_TYPES[UA_TYPES_NODEID])) {
        const UA_NodeId *t = f[0].data;
        if(t->namespaceIndex == 0 && t->identifierType == UA_NODEIDTYPE_NUMERIC)
            e.type = t->identifier.numeric;
    }
    if(f && UA_Variant_hasScalarType(&fields.map[1].value, &UA_TYPES[UA_TYPES_BOOLEAN]))
        e.retain = *(UA_Boolean *)fields.map[1].value.data;
    if(f && UA_Variant_hasScalarType(&fields.map[2].value, &UA_TYPES[UA_TYPES_BOOLEAN]))
        e.dialogActive = *(UA_Boolean *)fields.map[2].value.data;
    if(e.type == UA_NS0ID_AUDITCONDITIONRESPONDEVENTTYPE)
        return; /* counted apart from the condition events */
    pthread_mutex_lock(&l->lock);
    if(l->n < 64)
        l->ev[l->n++] = e;
    pthread_mutex_unlock(&l->lock);
}

static size_t seen_n(seen_list *l) {
    pthread_mutex_lock(&l->lock);
    size_t n = l->n;
    pthread_mutex_unlock(&l->lock);
    return n;
}

static void seen_reset(void) {
    seen_list *ls[2] = {&seenAdmin, &seenPlain};
    for(size_t i = 0; i < 2; i++) {
        pthread_mutex_lock(&ls[i]->lock);
        ls[i]->n = 0;
        pthread_mutex_unlock(&ls[i]->lock);
    }
}

static bool seen_is(seen_list *l, size_t i, UA_UInt32 type, bool retain, bool active) {
    pthread_mutex_lock(&l->lock);
    bool ok = i < l->n && l->ev[i].type == type &&
              (type != DIALOG_TYPE || (l->ev[i].retain == retain && l->ev[i].dialogActive == active));
    pthread_mutex_unlock(&l->lock);
    return ok;
}

/* Runs both clients until each has its count, then a little more. */
static bool wait_both(UA_Client *a, size_t na, UA_Client *p, size_t np) {
    for(int i = 0; i < 200 && (seen_n(&seenAdmin) < na || seen_n(&seenPlain) < np); i++) {
        (void)UA_Client_run_iterate(a, 25);
        (void)UA_Client_run_iterate(p, 25);
    }
    for(int i = 0; i < 4; i++) {
        (void)UA_Client_run_iterate(a, 25);
        (void)UA_Client_run_iterate(p, 25);
    }
    bool ok = seen_n(&seenAdmin) == na && seen_n(&seenPlain) == np;
    if(!ok) {
        fprintf(stderr, "events: admin %zu (want %zu), plain %zu (want %zu)\n",
                seen_n(&seenAdmin), na, seen_n(&seenPlain), np);
        for(size_t i = 0; i < seen_n(&seenAdmin); i++)
            fprintf(stderr, "  admin %zu: type %u retain %d active %d\n", i, seenAdmin.ev[i].type,
                    seenAdmin.ev[i].retain, seenAdmin.ev[i].dialogActive);
    }
    return ok;
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

static UA_StatusCode subscribe(UA_Client *c, seen_list *l, UA_UInt32 *subId) {
    UA_CreateSubscriptionResponse sr = UA_Client_Subscriptions_create(
        c, UA_CreateSubscriptionRequest_default(), NULL, NULL, NULL);
    UA_StatusCode r = sr.responseHeader.serviceResult;
    *subId = sr.subscriptionId;
    UA_CreateSubscriptionResponse_clear(&sr);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    static UA_QualifiedName type = {0, UA_STRING_STATIC("EventType")};
    static UA_QualifiedName retain = {0, UA_STRING_STATIC("Retain")};
    static UA_QualifiedName state[2] = {{0, UA_STRING_STATIC("DialogState")},
                                        {0, UA_STRING_STATIC("Id")}};
    UA_SimpleAttributeOperand sel[3] = {select_of(UA_NS0ID_BASEEVENTTYPE, &type, 1),
                                        select_of(UA_NS0ID_CONDITIONTYPE, &retain, 1),
                                        select_of(DIALOG_TYPE, state, 2)};
    UA_EventFilter filter;
    UA_EventFilter_init(&filter);
    filter.selectClauses = sel;
    filter.selectClausesSize = 3;
    UA_MonitoredItemCreateRequest item =
        UA_MonitoredItemCreateRequest_default(UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER));
    item.itemToMonitor.attributeId = UA_ATTRIBUTEID_EVENTNOTIFIER;
    item.monitoringMode = UA_MONITORINGMODE_REPORTING;
    item.requestedParameters.queueSize = 64;
    UA_ExtensionObject_setValue(&item.requestedParameters.filter, &filter,
                                &UA_TYPES[UA_TYPES_EVENTFILTER]);
    UA_MonitoredItemCreateResult mr = UA_Client_MonitoredItems_createEvent(
        c, *subId, UA_TIMESTAMPSTORETURN_BOTH, item, l, on_event, NULL);
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

static UA_StatusCode respond(UA_Client *c, const UA_NodeId *d, UA_Int32 resp, const char *comment) {
    UA_Variant in[2];
    UA_LocalizedText lt = UA_LOCALIZEDTEXT("en", (char *)(uintptr_t)(comment ? comment : ""));
    UA_Variant_setScalar(&in[0], &resp, &UA_TYPES[UA_TYPES_INT32]);
    UA_Variant_setScalar(&in[1], &lt, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    UA_UInt32 m = comment ? UA_NS0ID_DIALOGCONDITIONTYPE_RESPOND2 : UA_NS0ID_DIALOGCONDITIONTYPE_RESPOND;
    size_t nOut = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = UA_Client_call(c, *d, UA_NODEID_NUMERIC(0, m), comment ? 2 : 1, in, &nOut, &out);
    UA_Array_delete(out, nOut, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

static bool read_bool(UA_Client *c, const UA_NodeId *d, const char *a, const char *b) {
    UA_BrowsePath bp;
    UA_BrowsePath_init(&bp);
    UA_RelativePathElement el[2];
    UA_RelativePathElement_init(&el[0]);
    UA_RelativePathElement_init(&el[1]);
    el[0].referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HIERARCHICALREFERENCES);
    el[0].includeSubtypes = true;
    el[0].targetName = UA_QUALIFIEDNAME(0, (char *)(uintptr_t)a);
    el[1] = el[0];
    el[1].targetName = UA_QUALIFIEDNAME(0, (char *)(uintptr_t)(b ? b : ""));
    bp.startingNode = *d;
    bp.relativePath.elements = el;
    bp.relativePath.elementsSize = b ? 2 : 1;
    UA_TranslateBrowsePathsToNodeIdsRequest req;
    UA_TranslateBrowsePathsToNodeIdsRequest_init(&req);
    req.browsePaths = &bp;
    req.browsePathsSize = 1;
    UA_TranslateBrowsePathsToNodeIdsResponse res =
        UA_Client_Service_translateBrowsePathsToNodeIds(c, req);
    bool v = false;
    if(res.resultsSize == 1 && res.results[0].targetsSize == 1) {
        UA_Variant val;
        UA_Variant_init(&val);
        if(UA_Client_readValueAttribute(c, res.results[0].targets[0].targetId.nodeId, &val) ==
               UA_STATUSCODE_GOOD &&
           val.data && UA_Variant_hasScalarType(&val, &UA_TYPES[UA_TYPES_BOOLEAN]))
            v = *(UA_Boolean *)val.data;
        UA_Variant_clear(&val);
    }
    UA_TranslateBrowsePathsToNodeIdsResponse_clear(&res);
    return v;
}

/* ---- clients ---- */

static UA_Client *connect_as(const char *user, const char *url, UA_ByteString *serverCert) {
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    UA_String subject[] = {UA_STRING_STATIC("CN=dialogs client"), UA_STRING_STATIC("O=OpenGDS")};
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
    UA_StatusCode r = UA_STATUSCODE_BADINTERNALERROR;
    for(int i = 0; c && i < 50 && r != UA_STATUSCODE_GOOD; i++) {
        r = UA_Client_connectUsername(c, url, user, PASSWORD);
        if(r != UA_STATUSCODE_GOOD)
            usleep(100000);
    }
    if(c && !CHECK_EQ_INT(r, UA_STATUSCODE_GOOD)) {
        UA_Client_delete(c);
        c = NULL;
    }
    return c;
}

static void disconnect(UA_Client *c) {
    if(c) {
        (void)UA_Client_disconnect(c);
        UA_Client_delete(c);
    }
}

/* Responds and keeps both clients running until the answer is in. */
static void test_respond(UA_Client *admin, UA_Client *plain, const UA_NodeId *hidden) {
    CHECK_EQ_INT(respond(plain, hidden, 0, NULL), UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(respond(admin, hidden, 3, NULL), UA_STATUSCODE_BADDIALOGRESPONSEINVALID);
    CHECK_EQ_INT(respond(admin, hidden, -1, "x"), UA_STATUSCODE_BADDIALOGRESPONSEINVALID);
    CHECK_EQ_INT(cb_calls(), 0);
    /* the plugin refuses "Later": the dialog stays */
    CHECK_EQ_INT(respond(admin, hidden, 1, NULL), UA_STATUSCODE_BADDIALOGRESPONSEINVALID);
    CHECK_EQ_INT(cb_calls(), 1);
    CHECK(read_bool(admin, hidden, "DialogState", "Id"));
    CHECK(wait_both(admin, 0, plain, 0));
    /* accepted */
    CHECK_EQ_INT(respond(admin, hidden, 0, "registering"), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(cb_calls(), 2);
    pthread_mutex_lock(&cbLock);
    CHECK(strcmp(cbUser, "admin") == 0 && strcmp(cbComment, "registering") == 0);
    CHECK(cbOffServerThread);
    pthread_mutex_unlock(&cbLock);
    CHECK(wait_both(admin, 1, plain, 0));
    CHECK(seen_is(&seenAdmin, 0, DIALOG_TYPE, false, false));
    CHECK(!read_bool(admin, hidden, "DialogState", "Id"));
    CHECK(!read_bool(admin, hidden, "Retain", NULL));
    CHECK_EQ_INT(respond(admin, hidden, 0, NULL), UA_STATUSCODE_BADDIALOGNOTACTIVE);
    CHECK_EQ_INT(cb_calls(), 2);
}

/* An alarm with visibleTo (gds_alarm_def since A19). */
static void test_alarm(gds_server *s, UA_Client *admin, UA_Client *plain) {
    gds_alarm_def ad;
    memset(&ad, 0, sizeof(ad));
    ad.abi_major = GDS_PLUGIN_ABI_MAJOR;
    ad.abi_minor = GDS_PLUGIN_ABI_MINOR;
    ad.struct_size = sizeof(ad);
    ad.sourceNode = source();
    ad.name = "UnmanagedServers";
    ad.visibleTo = &secAdmin;
    ad.visibleToSize = 1;
    gds_alarm *a = NULL;
    CHECK(gds_server_add_alarm(s, &ad, &a) == GDS_OK && a);
    seen_reset();
    CHECK(a && gds_server_set_alarm(a, true, 400, "3 servers unmanaged") == GDS_OK);
    CHECK(wait_both(admin, 1, plain, 0));
    CHECK(seen_is(&seenAdmin, 0, UA_NS0ID_OFFNORMALALARMTYPE, true, false));
}

/* ConditionRefresh replays what each session may see: the hidden dialog
 * to the SecurityAdmin only. */
static void test_refresh(UA_Client *admin, UA_Client *plain, UA_UInt32 subA, UA_UInt32 subP) {
    seen_reset();
    CHECK_EQ_INT(refresh(admin, subA), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(refresh(plain, subP), UA_STATUSCODE_GOOD);
    CHECK(wait_both(admin, 4, plain, 3));
    CHECK(seen_is(&seenAdmin, 0, UA_NS0ID_REFRESHSTARTEVENTTYPE, false, false));
    CHECK(seen_is(&seenAdmin, 3, UA_NS0ID_REFRESHENDEVENTTYPE, false, false));
    CHECK(seen_is(&seenPlain, 0, UA_NS0ID_REFRESHSTARTEVENTTYPE, false, false));
    CHECK(seen_is(&seenPlain, 1, DIALOG_TYPE, true, true));
    CHECK(seen_is(&seenPlain, 2, UA_NS0ID_REFRESHENDEVENTTYPE, false, false));

}

static void test_clients(gds_server *s, UA_Client *admin, UA_Client *plain) {
    UA_UInt32 subA = 0, subP = 0;
    if(!CHECK_EQ_INT(subscribe(admin, &seenAdmin, &subA), UA_STATUSCODE_GOOD) ||
       !CHECK_EQ_INT(subscribe(plain, &seenPlain, &subP), UA_STATUSCODE_GOOD))
        return;
    (void)wait_both(admin, 0, plain, 0);
    seen_reset();

    /* added from this thread while the server thread runs */
    UA_NodeId hidden = UA_NODEID_NULL, open = UA_NODEID_NULL;
    gds_dialog_def d = def_of("RegisterPlc7", true);
    CHECK(gds_server_add_dialog(s, &d, &hidden) == GDS_OK);
    CHECK(wait_both(admin, 1, plain, 0));
    CHECK(seen_is(&seenAdmin, 0, DIALOG_TYPE, true, true));
    seen_reset();
    d = def_of("RegisterPlc8", false);
    d.dialogId = UA_NODEID_STRING(ns, "RegisterPlc8");
    CHECK(gds_server_add_dialog(s, &d, &open) == GDS_OK);
    CHECK(UA_NodeId_equal(&open, &d.dialogId));
    UA_NodeId again = UA_NODEID_NULL;
    CHECK(gds_server_add_dialog(s, &d, &again) == GDS_EEXISTS);
    CHECK(wait_both(admin, 1, plain, 1));

    test_refresh(admin, plain, subA, subP);

    seen_reset();
    test_respond(admin, plain, &hidden);

    /* removing the open one closes it first: both see that */
    seen_reset();
    CHECK(gds_server_remove_dialog(s, &open) == GDS_OK);
    CHECK(wait_both(admin, 1, plain, 1));
    CHECK(seen_is(&seenPlain, 0, DIALOG_TYPE, false, false));
    CHECK(gds_server_remove_dialog(s, &open) == GDS_ENOTFOUND);
    CHECK(gds_server_remove_dialog(s, &hidden) == GDS_OK); /* closed already: no event */
    seen_reset();
    CHECK(wait_both(admin, 0, plain, 0));
    UA_NodeId_clear(&hidden);
    UA_NodeId_clear(&open);
    test_alarm(s, admin, plain);
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

static bool write_users(const char *dir, gds_users *u) {
    char path[1024], cred[256], text[1024];
    static const uint8_t pw[] = PASSWORD;
    if(!CHECK(gds_path(path, sizeof(path), "%s/users", dir) == GDS_OK) ||
       !CHECK(gds_password_hash(pw, sizeof(pw) - 1, 10000, cred, sizeof(cred)) == GDS_OK))
        return false;
    int n = snprintf(text, sizeof(text), "admin SecurityAdmin %s\nplain - %s\n", cred, cred);
    return CHECK(n > 0 && (size_t)n < sizeof(text)) &&
           CHECK(gds_file_write_atomic(path, text, (size_t)n, 0600) == GDS_OK) &&
           CHECK(gds_users_load(path, u) == GDS_OK);
}

static void served(gds_server *s, UA_ByteString *serverCert, UA_UInt16 port) {
    if(!CHECK(pthread_create(&serverThread, NULL, loop_main, s) == 0))
        return;
    char url[64];
    (void)snprintf(url, sizeof(url), "opc.tcp://127.0.0.1:%u", (unsigned)port);
    UA_Client *admin = connect_as("admin", url, serverCert);
    UA_Client *plain = connect_as("plain", url, serverCert);
    if(CHECK(admin && plain))
        test_clients(s, admin, plain);
    disconnect(admin);
    disconnect(plain);
    (void)UA_Server_addTimedCallback(gds_server_ua(s), stop_cb, &running,
                                     UA_DateTime_nowMonotonic(), NULL);
    (void)pthread_join(serverThread, NULL);
    CHECK_EQ_INT(runResult, GDS_OK);
}

int main(int argc, char **argv) {
    if(argc != 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    char db[1024], caDir[1024];
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/store.db", argv[1]) == GDS_OK);
    CHECK(gds_path(caDir, sizeof(caDir), "%s/ca", argv[1]) == GDS_OK);
    (void)unlink(db);

    static uint8_t pw[] = "dialogs-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    gds_store *st = NULL;
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    UA_String subject[] = {UA_STRING_STATIC("CN=OpenGDS dialogs test")};
    UA_String san[] = {UA_STRING_STATIC("URI:" TEST_URI), UA_STRING_STATIC("DNS:localhost")};
    static gds_users users;
    if(!CHECK(gds_ca_openssl_open(&cc, &ca) == GDS_OK) || !CHECK(gds_store_open(db, &st) == GDS_OK) ||
       !CHECK(UA_CreateCertificate(UA_Log_Stdout, subject, 1, san, 2, UA_CERTIFICATEFORMAT_DER,
                                   NULL, &key, &cert) == UA_STATUSCODE_GOOD) ||
       !write_users(argv[1], &users))
        return CHECK_DONE();

    UA_UInt16 port = (UA_UInt16)(48000 + getpid() % 1000);
    gds_server_config cfg = {0};
    cfg.port = port;
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS dialogs test";
    cfg.ownCert = (gds_buf){cert.data, cert.length};
    cfg.ownKey = (gds_buf){key.data, key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_ALL;

    gds_server *s = NULL;
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s) {
        setup(s);
        served(s, &cert, port);
    }
    gds_server_delete(s);

    gds_store_close(st);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    gds_ca_close(ca);
    return CHECK_DONE();
}
