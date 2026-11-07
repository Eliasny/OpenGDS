/* OpenGDS unit test: CertificateManager rights for embedders (UASM ask
 * A14, issue #87). A device signs in over SignAndEncrypt with a
 * certificate the GDS CA did not issue (an OPC 10000-21 DeviceIdentity
 * certificate) and no user. The caller view carries that certificate, so a
 * privilege provider can see it; the embedder's may_manage hook lets the
 * device act for its own ApplicationId only: GetCertificateStatus,
 * GetCertificateGroups, GetTrustList, StartSigningRequest and
 * FinishRequest succeed for it, another application and another
 * certificate are refused, and the hook is never asked when the core's
 * own checks already decide.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

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

#define TEST_URI "urn:opengds:test:dca"
#define DEVICE_URI "urn:opengds:test:dca:device"
#define OTHER_URI "urn:opengds:test:dca:other"
#define STRANGER_URI "urn:opengds:test:dca:stranger"

typedef struct {
    UA_ByteString cert, key;
} pair;

static pair device, stranger;
static UA_NodeId deviceApp, otherApp;
static int hookCalls, sawCert;
static UA_Boolean running = true;

/* ---- the embedder ---- */

static bool may_manage(void *ctx, const gds_caller *c, const UA_NodeId *app) {
    (void)ctx;
    __atomic_add_fetch(&hookCalls, 1, __ATOMIC_SEQ_CST);
    if(c->struct_size < offsetof(gds_caller, clientCertificateSize) + sizeof(size_t) ||
       !c->clientCertificate)
        return false;
    bool isDevice = c->clientCertificateSize == device.cert.length &&
                    memcmp(c->clientCertificate, device.cert.data, device.cert.length) == 0;
    return isDevice && UA_NodeId_equal(app, &deviceApp);
}

static gds_status grant(void *ctx, const gds_caller *c, gds_privilege_set *set) {
    (void)ctx, (void)set;
    if(c->clientCertificate && c->clientCertificateSize > 0)
        __atomic_store_n(&sawCert, 1, __ATOMIC_SEQ_CST);
    return GDS_OK;
}

static void *loop_main(void *arg) {
    CHECK(gds_server_run(arg, &running) == GDS_OK);
    return NULL;
}

static void stop_cb(UA_Server *ua, void *data) {
    (void)ua;
    *(UA_Boolean *)data = false;
}

/* ---- clients ---- */

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
            usleep(50000); /* the server thread may still be starting */
    }
    if(r != UA_STATUSCODE_GOOD) {
        UA_Client_delete(c);
        return NULL;
    }
    return c;
}

static UA_StatusCode call(UA_Client *c, UA_UInt16 ns, UA_UInt32 method, UA_Variant *in,
                          size_t nIn, UA_Variant **out, size_t *nOut) {
    *out = NULL;
    *nOut = 0;
    return UA_Client_call(c, UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY),
                          UA_NODEID_NUMERIC(ns, method), nIn, in, nOut, out);
}

static UA_StatusCode status_of(UA_Client *c, UA_UInt16 ns, const UA_NodeId *app) {
    UA_NodeId null = UA_NODEID_NULL;
    UA_Variant in[3];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)app, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &null, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &null, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant *out;
    size_t n;
    UA_StatusCode r = call(c, ns, UA_GDSID_DIRECTORY_GETCERTIFICATESTATUS, in, 3, &out, &n);
    UA_Array_delete(out, n, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

static UA_StatusCode app_call(UA_Client *c, UA_UInt16 ns, UA_UInt32 method, const UA_NodeId *app,
                              size_t nNull) {
    UA_NodeId null = UA_NODEID_NULL;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)app, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &null, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant *out;
    size_t n;
    UA_StatusCode r = call(c, ns, method, in, 1 + nNull, &out, &n);
    UA_Array_delete(out, n, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

static gds_status make_csr(UA_ByteString *out) {
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    X509_REQ *req = X509_REQ_new();
    gds_status r = GDS_ECRYPTO;
    *out = UA_BYTESTRING_NULL;
    if(key && req && X509_REQ_set_pubkey(req, key) == 1 &&
       X509_REQ_sign(req, key, EVP_sha256()) > 0) {
        int len = i2d_X509_REQ(req, NULL);
        if(len > 0 && UA_ByteString_allocBuffer(out, (size_t)len) == UA_STATUSCODE_GOOD) {
            unsigned char *p = out->data;
            r = i2d_X509_REQ(req, &p) == len ? GDS_OK : GDS_ECRYPTO;
        }
    }
    X509_REQ_free(req);
    EVP_PKEY_free(key);
    return r;
}

/* StartSigningRequest, then FinishRequest until the worker has signed. */
static UA_StatusCode sign_flow(UA_Client *c, UA_UInt16 ns, const UA_NodeId *app) {
    UA_ByteString csr;
    if(make_csr(&csr) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_NodeId null = UA_NODEID_NULL;
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)app, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &null, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &null, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[3], &csr, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant *out;
    size_t n;
    UA_StatusCode r = call(c, ns, UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST, in, 4, &out, &n);
    UA_NodeId req = UA_NODEID_NULL;
    if(r == UA_STATUSCODE_GOOD &&
       !(n == 1 && UA_Variant_hasScalarType(&out[0], &UA_TYPES[UA_TYPES_NODEID]) &&
         UA_NodeId_copy(out[0].data, &req) == UA_STATUSCODE_GOOD))
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    UA_Array_delete(out, n, &UA_TYPES[UA_TYPES_VARIANT]);
    UA_ByteString_clear(&csr);
    UA_Variant fin[2];
    UA_Variant_setScalar(&fin[0], (void *)(uintptr_t)app, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&fin[1], &req, &UA_TYPES[UA_TYPES_NODEID]);
    for(int i = 0; i < 200 && r == UA_STATUSCODE_GOOD; i++) {
        r = call(c, ns, UA_GDSID_DIRECTORY_FINISHREQUEST, fin, 2, &out, &n);
        bool signed_ = r == UA_STATUSCODE_GOOD && n == 3 &&
                       UA_Variant_hasScalarType(&out[0], &UA_TYPES[UA_TYPES_BYTESTRING]) &&
                       ((UA_ByteString *)out[0].data)->length > 0;
        UA_Array_delete(out, n, &UA_TYPES[UA_TYPES_VARIANT]);
        if(signed_)
            break;
        if(r == UA_STATUSCODE_BADNOTHINGTODO) {
            r = UA_STATUSCODE_GOOD;
            usleep(50000);
        }
    }
    UA_NodeId_clear(&req);
    return r;
}

/* ---- the tests ---- */

static void test_device(gds_server *s, const char *url) {
    UA_Client *c = connect_as(&device, DEVICE_URI, url);
    if(!CHECK(c != NULL))
        return;
    UA_UInt16 ns = s->ns;
    /* its own ApplicationId: the hook allows every CertificateManager call */
    CHECK_EQ_INT(status_of(c, ns, &deviceApp), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(app_call(c, ns, UA_GDSID_DIRECTORY_GETCERTIFICATEGROUPS, &deviceApp, 0),
                 UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(app_call(c, ns, UA_GDSID_DIRECTORY_GETTRUSTLIST, &deviceApp, 1),
                 UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(sign_flow(c, ns, &deviceApp), UA_STATUSCODE_GOOD);
    CHECK(__atomic_load_n(&sawCert, __ATOMIC_SEQ_CST) == 1);
    /* another application: refused */
    CHECK_EQ_INT(status_of(c, ns, &otherApp), UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(app_call(c, ns, UA_GDSID_DIRECTORY_GETTRUSTLIST, &otherApp, 1),
                 UA_STATUSCODE_BADUSERACCESSDENIED);
    /* an unknown application: the core answers, the hook is not asked */
    int before = __atomic_load_n(&hookCalls, __ATOMIC_SEQ_CST);
    UA_NodeId unknown = UA_NODEID_GUID(ns, UA_GUID("00000000-0000-0000-0000-00000000abcd"));
    CHECK(status_of(c, ns, &unknown) != UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(__atomic_load_n(&hookCalls, __ATOMIC_SEQ_CST), before);
    (void)UA_Client_disconnect(c);
    UA_Client_delete(c);
}

static void test_stranger(gds_server *s, const char *url) {
    UA_Client *c = connect_as(&stranger, STRANGER_URI, url);
    if(!CHECK(c != NULL))
        return;
    CHECK_EQ_INT(status_of(c, s->ns, &deviceApp), UA_STATUSCODE_BADUSERACCESSDENIED);
    (void)UA_Client_disconnect(c);
    UA_Client_delete(c);
}

static bool register_apps(gds_server *s) {
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
    if(!CHECK(gds_server_register_application(s, "test", &rec, &deviceApp, &created) == GDS_OK))
        return false;
    rec.applicationUri = UA_STRING(OTHER_URI);
    return CHECK(gds_server_register_application(s, "test", &rec, &otherApp, &created) == GDS_OK);
}

static void serve(gds_server *s, UA_UInt16 port) {
    static gds_privilege_provider pp = {GDS_PLUGIN_ABI_MAJOR, GDS_PLUGIN_ABI_MINOR,
                                        sizeof(gds_privilege_provider), NULL, grant};
    CHECK(gds_server_add_privilege_provider(s, &pp) == GDS_OK);
    CHECK(gds_server_set_application_rights_hook(s, may_manage, NULL) == GDS_OK);
    if(!register_apps(s))
        return;
    pthread_t loop;
    if(!CHECK(pthread_create(&loop, NULL, loop_main, s) == 0))
        return;
    char url[64];
    (void)snprintf(url, sizeof(url), "opc.tcp://127.0.0.1:%u", (unsigned)port);
    test_device(s, url);
    test_stranger(s, url);
    /* fixed once the server runs */
    CHECK(gds_server_set_application_rights_hook(s, NULL, NULL) == GDS_ESTATE);
    (void)UA_Server_addTimedCallback(gds_server_ua(s), stop_cb, &running,
                                     UA_DateTime_nowMonotonic(), NULL);
    (void)pthread_join(loop, NULL);
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

    static uint8_t pw[] = "dca-test-passphrase";
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
       !CHECK(make_cert(TEST_URI, &own)) || !CHECK(make_cert(DEVICE_URI, &device)) ||
       !CHECK(make_cert(STRANGER_URI, &stranger)))
        return CHECK_DONE();

    static gds_users users;
    UA_UInt16 port = (UA_UInt16)(47000 + getpid() % 1000);
    gds_server_config cfg = {0};
    cfg.port = port;
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS DCA rights test";
    cfg.ownCert = (gds_buf){own.cert.data, own.cert.length};
    cfg.ownKey = (gds_buf){own.key.data, own.key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_ALL;
    gds_server *s = NULL;
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s)
        serve(s, port);
    gds_server_delete(s);
    UA_ByteString_clear(&own.cert);
    UA_ByteString_clear(&own.key);
    UA_ByteString_clear(&device.cert);
    UA_ByteString_clear(&device.key);
    UA_ByteString_clear(&stranger.cert);
    UA_ByteString_clear(&stranger.key);
    UA_NodeId_clear(&deviceApp);
    UA_NodeId_clear(&otherApp);
    gds_store_close(st);
    gds_ca_close(ca);
    return CHECK_DONE();
}
