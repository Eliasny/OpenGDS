/* OpenGDS unit test: a KeyCredential source (gds_server_set_keycred_source,
 * OPC 10000-12 §8.5). A device that the embedder's may_manage hook lets act
 * for itself asks over SignAndEncrypt; FinishRequest takes the CredentialId
 * and secret from the source on a plugin worker, the core stores only the
 * CredentialId, a new credential names the one it replaces, Revoke asks the
 * source first, and a source that refuses leaves the request approved for a
 * retry.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>

#include <pthread.h>
#include <stdio.h>
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

#define TEST_URI "urn:opengds:test:kcsource"
#define DEVICE_URI "urn:opengds:test:kcsource:device"
#define BROKER "urn:opengds:test:broker"

typedef struct {
    UA_ByteString cert, key;
} pair;

static pair device;
static UA_NodeId deviceApp, svcObj, startM, finishM, revokeM;
static UA_Boolean running = true;

/* ---- the source ---- */

static pthread_mutex_t srcLock = PTHREAD_MUTEX_INITIALIZER;
static int issued, revoked;
static bool refuseNext;
static char lastReplaces[GDS_KEYCRED_ID_MAX + 1], lastService[80], lastResource[80],
    lastApp[128], lastRevoked[GDS_KEYCRED_ID_MAX + 1];

static gds_status src_issue(void *ctx, const gds_keycred_issue_request *req,
                            char credentialId[GDS_KEYCRED_ID_MAX + 1], UA_ByteString *secret) {
    (void)ctx;
    pthread_mutex_lock(&srcLock);
    gds_status st = GDS_OK;
    if(refuseNext) {
        refuseNext = false;
        st = GDS_EDENIED;
    } else {
        issued++;
        (void)snprintf(credentialId, GDS_KEYCRED_ID_MAX + 1, "src-%d", issued);
        char sec[32];
        int n = snprintf(sec, sizeof(sec), "s3cret-%d", issued);
        st = UA_ByteString_allocBuffer(secret, (size_t)n) == UA_STATUSCODE_GOOD ? GDS_OK
                                                                                 : GDS_ENOMEM;
        if(st == GDS_OK)
            memcpy(secret->data, sec, (size_t)n);
        (void)snprintf(lastReplaces, sizeof(lastReplaces), "%s",
                       req->replaces ? req->replaces : "");
        (void)snprintf(lastService, sizeof(lastService), "%s", req->service);
        (void)snprintf(lastResource, sizeof(lastResource), "%s", req->resourceUri);
        (void)snprintf(lastApp, sizeof(lastApp), "%.*s", (int)req->applicationUri->length,
                       (const char *)req->applicationUri->data);
    }
    pthread_mutex_unlock(&srcLock);
    return st;
}

static gds_status src_revoke(void *ctx, const char *service, const char *id) {
    (void)ctx, (void)service;
    pthread_mutex_lock(&srcLock);
    revoked++;
    (void)snprintf(lastRevoked, sizeof(lastRevoked), "%s", id);
    pthread_mutex_unlock(&srcLock);
    return GDS_OK;
}

static bool may_manage(void *ctx, const gds_caller *c, const UA_NodeId *app) {
    (void)ctx;
    bool isDevice = c->clientCertificate && c->clientCertificateSize == device.cert.length &&
                    memcmp(c->clientCertificate, device.cert.data, device.cert.length) == 0;
    return isDevice && UA_NodeId_equal(app, &deviceApp);
}

static void *loop_main(void *arg) {
    CHECK(gds_server_run(arg, &running) == GDS_OK);
    return NULL;
}

static void stop_cb(UA_Server *ua, void *data) {
    (void)ua;
    *(UA_Boolean *)data = false;
}

/* ---- the client ---- */

static bool make_cert(const char *uri, pair *p) {
    char sanUri[128];
    (void)snprintf(sanUri, sizeof(sanUri), "URI:%s", uri);
    UA_String subject[] = {UA_STRING_STATIC("CN=device"), UA_STRING_STATIC("O=OpenGDS")};
    UA_String san[] = {UA_STRING(sanUri), UA_STRING_STATIC("DNS:localhost")};
    return UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER,
                                NULL, &p->key, &p->cert) == UA_STATUSCODE_GOOD;
}

static UA_Client *connect_as(const pair *p, const char *uri, const char *url) {
    UA_ClientConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.logging = UA_Log_Stdout_new(UA_LOGLEVEL_WARNING);
    if(UA_ClientConfig_setDefault(&cfg) != UA_STATUSCODE_GOOD ||
       UA_ClientConfig_setDefaultEncryption(&cfg, p->cert, p->key, NULL, 0, NULL, 0) !=
           UA_STATUSCODE_GOOD) {
        UA_ClientConfig_clear(&cfg);
        return NULL;
    }
    cfg.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    UA_String_clear(&cfg.securityPolicyUri);
    cfg.securityPolicyUri =
        UA_STRING_ALLOC("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
    UA_String_clear(&cfg.clientDescription.applicationUri);
    cfg.clientDescription.applicationUri = UA_STRING_ALLOC(uri);
    UA_Client *c = UA_Client_newWithConfig(&cfg);
    if(!c) {
        UA_ClientConfig_clear(&cfg);
        return NULL;
    }
    UA_StatusCode r = UA_STATUSCODE_BADCONNECTIONREJECTED;
    for(int i = 0; i < 100 && r != UA_STATUSCODE_GOOD; i++) {
        r = UA_Client_connect(c, url);
        if(r != UA_STATUSCODE_GOOD)
            usleep(50000);
    }
    if(r != UA_STATUSCODE_GOOD) {
        UA_Client_delete(c);
        return NULL;
    }
    return c;
}

static UA_StatusCode start(UA_Client *c, UA_NodeId *req) {
    UA_String u = UA_STRING(DEVICE_URI);
    UA_ByteString k = UA_BYTESTRING_NULL;
    UA_String p = UA_STRING_NULL;
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], &u, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &k, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&in[2], &p, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setArray(&in[3], UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant *out = NULL;
    size_t n = 0;
    UA_StatusCode r = UA_Client_call(c, svcObj, startM, 4, in, &n, &out);
    if(r == UA_STATUSCODE_GOOD &&
       !(n == 1 && UA_Variant_hasScalarType(&out[0], &UA_TYPES[UA_TYPES_NODEID]) &&
         UA_NodeId_copy(out[0].data, req) == UA_STATUSCODE_GOOD))
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    UA_Array_delete(out, n, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

/* FinishRequest; on Good the CredentialId and the secret (plain: no key). */
static UA_StatusCode finish(UA_Client *c, const UA_NodeId *req, char *id, size_t idLen,
                            char *secret, size_t secretLen) {
    UA_Boolean cancel = false;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)req, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &cancel, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Variant *out = NULL;
    size_t n = 0;
    UA_StatusCode r = UA_Client_call(c, svcObj, finishM, 2, in, &n, &out);
    id[0] = secret[0] = '\0';
    if(r == UA_STATUSCODE_GOOD) {
        const UA_String *i = n == 5 && UA_Variant_hasScalarType(&out[0], &UA_TYPES[UA_TYPES_STRING])
                                 ? out[0].data
                                 : NULL;
        const UA_ByteString *s =
            n == 5 && UA_Variant_hasScalarType(&out[1], &UA_TYPES[UA_TYPES_BYTESTRING])
                ? out[1].data
                : NULL;
        if(i && s && i->length < idLen && s->length < secretLen) {
            memcpy(id, i->data, i->length);
            id[i->length] = '\0';
            memcpy(secret, s->data, s->length);
            secret[s->length] = '\0';
        } else {
            r = UA_STATUSCODE_BADUNEXPECTEDERROR;
        }
    }
    UA_Array_delete(out, n, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

static UA_StatusCode revoke_cred(UA_Client *c, const char *id) {
    UA_String i = UA_STRING((char *)(uintptr_t)id);
    UA_Variant in;
    UA_Variant_setScalar(&in, &i, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant *out = NULL;
    size_t n = 0;
    UA_StatusCode r = UA_Client_call(c, svcObj, revokeM, 1, &in, &n, &out);
    UA_Array_delete(out, n, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

static gds_status cred_get(gds_server *s, const char *id, gds_kc_cred *c) {
    gds_lock(s);
    gds_status st = gds_store_kc_cred_get(s->store, id, c);
    gds_unlock(s);
    return st;
}

/* ---- the tests ---- */

/* The source refuses once (the request stays approved), then delivers. */
static void test_issue(gds_server *s, UA_Client *c) {
    UA_NodeId a = UA_NODEID_NULL;
    char id[200], secret[200];
    gds_kc_cred kc;
    if(!CHECK_EQ_INT(start(c, &a), UA_STATUSCODE_GOOD))
        return;
    refuseNext = true;
    CHECK_EQ_INT(finish(c, &a, id, sizeof(id), secret, sizeof(secret)),
                 UA_STATUSCODE_BADREQUESTNOTALLOWED);
    if(CHECK_EQ_INT(finish(c, &a, id, sizeof(id), secret, sizeof(secret)), UA_STATUSCODE_GOOD)) {
        CHECK(strcmp(id, "src-1") == 0 && strcmp(secret, "s3cret-1") == 0);
        CHECK(strcmp(lastService, "mqtt") == 0 && strcmp(lastResource, BROKER) == 0);
        CHECK(strcmp(lastApp, DEVICE_URI) == 0 && lastReplaces[0] == '\0');
        if(CHECK(cred_get(s, "src-1", &kc) == GDS_OK))
            CHECK(strcmp(kc.verifier, "!source") == 0); /* not the secret */
    }
    CHECK_EQ_INT(finish(c, &a, id, sizeof(id), secret, sizeof(secret)),
                 UA_STATUSCODE_BADINVALIDARGUMENT); /* once only */
    UA_NodeId_clear(&a);
}

/* A new credential replaces src-1; Revoke asks the source, then forgets it. */
static void test_replace_revoke(gds_server *s, UA_Client *c) {
    UA_NodeId b = UA_NODEID_NULL;
    char id[200], secret[200];
    gds_kc_cred kc;
    if(!CHECK_EQ_INT(start(c, &b), UA_STATUSCODE_GOOD) ||
       !CHECK_EQ_INT(finish(c, &b, id, sizeof(id), secret, sizeof(secret)), UA_STATUSCODE_GOOD)) {
        UA_NodeId_clear(&b);
        return;
    }
    CHECK(strcmp(id, "src-2") == 0 && strcmp(lastReplaces, "src-1") == 0);
    CHECK(cred_get(s, "src-1", &kc) == GDS_ENOTFOUND);
    CHECK_EQ_INT(revoke_cred(c, "src-2"), UA_STATUSCODE_GOOD);
    CHECK(revoked == 1 && strcmp(lastRevoked, "src-2") == 0);
    CHECK(cred_get(s, "src-2", &kc) == GDS_ENOTFOUND);
    CHECK_EQ_INT(revoke_cred(c, "src-2"), UA_STATUSCODE_BADINVALIDARGUMENT);
    CHECK_EQ_INT(revoked, 1); /* unknown: the core answers alone */
    UA_NodeId_clear(&b);
}

static void test_device(gds_server *s, const char *url) {
    UA_Client *c = connect_as(&device, DEVICE_URI, url);
    if(!CHECK(c != NULL))
        return;
    test_issue(s, c);
    test_replace_revoke(s, c);
    (void)UA_Client_disconnect(c);
    UA_Client_delete(c);
}

static bool register_app(gds_server *s) {
    UA_LocalizedText name = UA_LOCALIZEDTEXT("en", "Device");
    UA_String disc = UA_STRING("opc.tcp://device:4840");
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    rec.applicationUri = UA_STRING(DEVICE_URI);
    rec.applicationType = UA_APPLICATIONTYPE_SERVER;
    rec.productUri = UA_STRING("urn:opengds:test:product");
    rec.applicationNames = &name;
    rec.applicationNamesSize = 1;
    rec.discoveryUrls = &disc;
    rec.discoveryUrlsSize = 1;
    bool created = false;
    return CHECK(gds_server_register_application(s, "test", &rec, &deviceApp, &created) == GDS_OK);
}

static UA_NodeId child(gds_server *s, const char *name) {
    UA_QualifiedName qn = UA_QUALIFIEDNAME(s->ns, (char *)(uintptr_t)name);
    UA_BrowsePathResult b = UA_Server_browseSimplifiedBrowsePath(gds_server_ua(s), svcObj, 1, &qn);
    UA_NodeId id = UA_NODEID_NULL;
    if(b.statusCode == UA_STATUSCODE_GOOD && b.targetsSize >= 1)
        (void)UA_NodeId_copy(&b.targets[0].targetId.nodeId, &id);
    UA_BrowsePathResult_clear(&b);
    return id;
}

static void serve(gds_server *s, UA_UInt16 port) {
    gds_keycred_source bad = {GDS_PLUGIN_ABI_MAJOR + 1, 0, sizeof(bad), NULL, src_issue,
                              src_revoke};
    CHECK(gds_server_set_keycred_source(s, &bad) == GDS_EINVAL);
    gds_keycred_source src = {GDS_PLUGIN_ABI_MAJOR, GDS_PLUGIN_ABI_MINOR, sizeof(src), NULL,
                              src_issue, src_revoke};
    CHECK(gds_server_set_keycred_source(s, &src) == GDS_OK);
    CHECK(gds_server_set_application_rights_hook(s, may_manage, NULL) == GDS_OK);
    if(!register_app(s))
        return;
    svcObj = UA_NODEID_STRING(s->ns, "KeyCredentialManagement/mqtt");
    startM = child(s, "StartRequest");
    finishM = child(s, "FinishRequest");
    revokeM = child(s, "Revoke");
    pthread_t loop;
    if(!CHECK(pthread_create(&loop, NULL, loop_main, s) == 0))
        return;
    char url[64];
    (void)snprintf(url, sizeof(url), "opc.tcp://127.0.0.1:%u", (unsigned)port);
    test_device(s, url);
    CHECK(gds_server_set_keycred_source(s, NULL) == GDS_ESTATE); /* fixed once running */
    (void)UA_Server_addTimedCallback(gds_server_ua(s), stop_cb, &running,
                                     UA_DateTime_nowMonotonic(), NULL);
    (void)pthread_join(loop, NULL);
    UA_NodeId_clear(&startM);
    UA_NodeId_clear(&finishM);
    UA_NodeId_clear(&revokeM);
}

int main(int argc, char **argv) {
    if(argc != 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    CHECK(setenv("TZ", "UTC", 1) == 0); /* clients and server share this process */
    tzset();
    char db[1024], caDir[1024];
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/store.db", argv[1]) == GDS_OK);
    CHECK(gds_path(caDir, sizeof(caDir), "%s/ca", argv[1]) == GDS_OK);
    (void)unlink(db);

    static uint8_t pw[] = "kcsource-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    gds_store *st = NULL;
    pair own = {UA_BYTESTRING_NULL, UA_BYTESTRING_NULL};
    if(!CHECK(gds_ca_openssl_open(&cc, &ca) == GDS_OK) || !CHECK(gds_store_open(db, &st) == GDS_OK) ||
       !CHECK(make_cert(TEST_URI, &own)) || !CHECK(make_cert(DEVICE_URI, &device)))
        return CHECK_DONE();

    static gds_users users;
    static const char *const prof[] = {"http://opcfoundation.org/UA/Profile/Transport/pubsub-mqtt-uadp"};
    static const gds_keycred_service svc[] = {{"mqtt", BROKER, prof, 1}};
    UA_UInt16 port = (UA_UInt16)(46000 + getpid() % 1000);
    gds_server_config cfg = {0};
    cfg.port = port;
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS KeyCredential source test";
    cfg.ownCert = (gds_buf){own.cert.data, own.cert.length};
    cfg.ownKey = (gds_buf){own.key.data, own.key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_ALL;
    cfg.keyCredServices = svc;
    cfg.keyCredServicesSize = 1;
    gds_server *s = NULL;
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s)
        serve(s, port);
    gds_server_delete(s);
    UA_ByteString_clear(&own.cert);
    UA_ByteString_clear(&own.key);
    UA_ByteString_clear(&device.cert);
    UA_ByteString_clear(&device.key);
    UA_NodeId_clear(&deviceApp);
    gds_store_close(st);
    gds_ca_close(ca);
    return CHECK_DONE();
}
