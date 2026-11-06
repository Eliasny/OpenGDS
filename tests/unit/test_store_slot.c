/* OpenGDS unit test: the store slot and a store that loses leadership
 * (UASM ask A4, issue #15).
 *
 * A test backend wraps the SQLite store and refuses every write with
 * GDS_ENOTLEADER on demand, as a replicated store does when it is not (or
 * stops being) the primary. The GDS methods then answer Bad_InvalidState,
 * nothing changes, and no certificate leaves the server; a STANDBY node
 * refuses the state-changing methods before it touches the store.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ca.h"
#include "check.h"
#include "common/buf.h"
#include "gds_internal.h"
#include "gds_server.h"
#include "store.h"
#include "common/banned.h"

#define TEST_URI "urn:opengds:test:slot"
#define APP_URI "urn:opengds:test:slot:app"

/* ---- the refusing backend ---- */

typedef struct {
    gds_store *inner;
    bool refuse;      /* every write */
    bool refuseIssue; /* the signing worker's writes only */
    int refused, closed;
} refusing;

static refusing *R(void *ctx) {
    return ctx;
}

/* The test thread flips the flags while the signing worker reads them. */
static bool flag(const bool *f) {
    return __atomic_load_n(f, __ATOMIC_SEQ_CST);
}
static void set_flag(bool *f, bool v) {
    __atomic_store_n(f, v, __ATOMIC_SEQ_CST);
}
static int refused(const refusing *r) {
    return __atomic_load_n(&r->refused, __ATOMIC_SEQ_CST);
}

static gds_status no(refusing *r) {
    __atomic_add_fetch(&r->refused, 1, __ATOMIC_SEQ_CST);
    return GDS_ENOTLEADER;
}

static void rf_close(void *ctx) {
    R(ctx)->closed++;
}
static int rf_version(void *ctx) {
    return gds_store_schema_version(R(ctx)->inner);
}
static gds_status rf_app_insert(void *ctx, const UA_Guid *id, const UA_ApplicationRecordDataType *rec) {
    return flag(&R(ctx)->refuse) ? no(R(ctx)) : gds_store_app_insert(R(ctx)->inner, id, rec);
}
static gds_status rf_app_get(void *ctx, const UA_Guid *id, UA_ApplicationRecordDataType *out) {
    return gds_store_app_get(R(ctx)->inner, id, out);
}
static gds_status rf_app_find_uri(void *ctx, const UA_String *uri, size_t max,
                                  UA_ApplicationRecordDataType **out, size_t *n) {
    return gds_store_app_find_uri(R(ctx)->inner, uri, max, out, n);
}
static gds_status rf_app_update(void *ctx, const UA_Guid *id, const UA_ApplicationRecordDataType *rec) {
    return flag(&R(ctx)->refuse) ? no(R(ctx)) : gds_store_app_update(R(ctx)->inner, id, rec);
}
static gds_status rf_app_delete(void *ctx, const UA_Guid *id) {
    return flag(&R(ctx)->refuse) ? no(R(ctx)) : gds_store_app_delete(R(ctx)->inner, id);
}
static gds_status rf_app_scan(void *ctx, int64_t from, gds_store_scan_cb cb, void *cbCtx) {
    return gds_store_app_scan(R(ctx)->inner, from, cb, cbCtx);
}
static gds_status rf_req_insert(void *ctx, const gds_request *q) {
    return flag(&R(ctx)->refuse) ? no(R(ctx)) : gds_store_req_insert(R(ctx)->inner, q);
}
static gds_status rf_req_get(void *ctx, const UA_Guid *id, gds_request *out) {
    return gds_store_req_get(R(ctx)->inner, id, out);
}
static gds_status rf_req_next(void *ctx, gds_request *out) {
    return gds_store_req_next_received(R(ctx)->inner, out);
}
static gds_status rf_req_set_state(void *ctx, const UA_Guid *id, gds_req_state st,
                                   const gds_buf *cert, UA_StatusCode err) {
    return flag(&R(ctx)->refuse) || flag(&R(ctx)->refuseIssue)
               ? no(R(ctx))
               : gds_store_req_set_state(R(ctx)->inner, id, st, cert, err);
}
static gds_status rf_cert_add(void *ctx, const UA_Guid *appId, uint32_t g, uint32_t t,
                              const gds_buf *serial, const gds_buf *der, int64_t nb, int64_t na) {
    return flag(&R(ctx)->refuse) || flag(&R(ctx)->refuseIssue)
               ? no(R(ctx))
               : gds_store_cert_add(R(ctx)->inner, appId, g, t, serial, der, nb, na);
}
static gds_status rf_cert_latest(void *ctx, const UA_Guid *appId, uint32_t g, uint32_t t,
                                 gds_buf *der, int64_t *na) {
    return gds_store_cert_latest(R(ctx)->inner, appId, g, t, der, na);
}

static gds_status rf_req_scan(void *ctx, gds_req_state st, gds_store_req_cb cb, void *cbCtx) {
    return gds_store_req_scan(R(ctx)->inner, st, cb, cbCtx);
}

static const gds_store_backend refusingBackend = {
    GDS_STORE_ABI_MAJOR, GDS_STORE_ABI_MINOR, sizeof(gds_store_backend),
    rf_close, rf_version, rf_app_insert, rf_app_get, rf_app_find_uri, rf_app_update,
    rf_app_delete, rf_app_scan, rf_req_insert, rf_req_get, rf_req_next, rf_req_set_state,
    rf_cert_add, rf_cert_latest,
    NULL, NULL, /* no audit log */
    rf_req_scan,
};

static void test_open_backend(void) {
    refusing r = {0};
    gds_store *s = (gds_store *)&r; /* overwritten on every path */
    gds_store_backend be = refusingBackend;
    be.abi_major = GDS_STORE_ABI_MAJOR + 1;
    CHECK(gds_store_open_backend(&be, &r, &s) == GDS_EINVAL && s == NULL);
    CHECK_EQ_INT(r.closed, 0); /* another ABI: its close is not called */
    be = refusingBackend;
    be.struct_size = offsetof(gds_store_backend, cert_latest);
    CHECK(gds_store_open_backend(&be, &r, &s) == GDS_EINVAL && s == NULL);
    CHECK_EQ_INT(r.closed, 1); /* ctx is taken also on failure */
    be = refusingBackend;
    be.req_set_state = NULL;
    CHECK(gds_store_open_backend(&be, &r, &s) == GDS_EINVAL && s == NULL);
    CHECK_EQ_INT(r.closed, 2);
    CHECK(gds_store_open_backend(&refusingBackend, &r, &s) == GDS_OK && s != NULL);
    gds_store_close(s);
    CHECK_EQ_INT(r.closed, 3);
    /* a minor 1 backend opens; it cannot list requests */
    be = refusingBackend;
    be.abi_minor = 1;
    be.struct_size = offsetof(gds_store_backend, req_scan);
    if(CHECK(gds_store_open_backend(&be, &r, &s) == GDS_OK && s != NULL))
        CHECK(gds_store_req_scan(s, GDS_REQ_PENDING, NULL, NULL) == GDS_EUNSUPPORTED);
    gds_store_close(s);
    CHECK_EQ_INT(r.closed, 4);
}

/* ---- calls ---- */

static UA_CallMethodResult call(gds_server *s, UA_UInt32 method, UA_Variant *in, size_t n) {
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY);
    req.methodId = UA_NODEID_NUMERIC(s->ns, method);
    req.inputArguments = in;
    req.inputArgumentsSize = n;
    return UA_Server_call(gds_server_ua(s), &req);
}

static UA_StatusCode call_status(gds_server *s, UA_UInt32 method, UA_Variant *in, size_t n) {
    UA_CallMethodResult res = call(s, method, in, n);
    UA_StatusCode r = res.statusCode;
    UA_CallMethodResult_clear(&res);
    return r;
}

static void make_record(UA_ApplicationRecordDataType *rec) {
    static UA_LocalizedText name;
    static UA_String disc;
    name = UA_LOCALIZEDTEXT("en", "Slot app");
    disc = UA_STRING("opc.tcp://localhost:4840");
    UA_ApplicationRecordDataType_init(rec);
    rec->applicationUri = UA_STRING(APP_URI);
    rec->applicationType = UA_APPLICATIONTYPE_SERVER;
    rec->productUri = UA_STRING("urn:opengds:test:product");
    rec->applicationNames = &name;
    rec->applicationNamesSize = 1;
    rec->discoveryUrls = &disc;
    rec->discoveryUrlsSize = 1;
}

static size_t count_apps(gds_store *st) {
    UA_ApplicationRecordDataType *found = NULL;
    size_t n = 0;
    UA_String uri = UA_STRING(APP_URI);
    if(gds_store_app_find_uri(st, &uri, 4, &found, &n) != GDS_OK)
        return 99;
    UA_Array_delete(found, n, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    return n;
}

static gds_status make_csr(gds_buf *out) {
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    X509_REQ *req = X509_REQ_new();
    gds_status r = GDS_ECRYPTO;
    if(key && req && X509_REQ_set_pubkey(req, key) == 1 &&
       X509_REQ_sign(req, key, EVP_sha256()) > 0) {
        int len = i2d_X509_REQ(req, NULL);
        out->data = len > 0 ? malloc((size_t)len) : NULL;
        unsigned char *p = out->data;
        out->len = len > 0 ? (size_t)len : 0;
        r = (out->data && i2d_X509_REQ(req, &p) == len) ? GDS_OK : GDS_ECRYPTO;
    }
    X509_REQ_free(req);
    EVP_PKEY_free(key);
    return r;
}

/* Register: refused while not the primary, then accepted. */
static bool register_app(gds_server *s, refusing *rf, UA_NodeId *appId) {
    UA_ApplicationRecordDataType rec;
    make_record(&rec);
    UA_Variant in;
    UA_Variant_setScalar(&in, &rec, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    set_flag(&rf->refuse, true);
    CHECK_EQ_INT(call_status(s, UA_GDSID_DIRECTORY_REGISTERAPPLICATION, &in, 1),
                 UA_STATUSCODE_BADINVALIDSTATE);
    CHECK_EQ_INT(count_apps(rf->inner), 0);
    set_flag(&rf->refuse, false);
    UA_CallMethodResult res = call(s, UA_GDSID_DIRECTORY_REGISTERAPPLICATION, &in, 1);
    bool ok = CHECK(res.statusCode == UA_STATUSCODE_GOOD) && res.outputArgumentsSize == 1 &&
              UA_Variant_hasScalarType(&res.outputArguments[0], &UA_TYPES[UA_TYPES_NODEID]) &&
              UA_NodeId_copy(res.outputArguments[0].data, appId) == UA_STATUSCODE_GOOD;
    UA_CallMethodResult_clear(&res);
    CHECK_EQ_INT(count_apps(rf->inner), 1);

    /* Update and Unregister change nothing while refused */
    rec.productUri = UA_STRING("urn:opengds:test:changed");
    rec.applicationId = *appId;
    set_flag(&rf->refuse, true);
    CHECK_EQ_INT(call_status(s, UA_GDSID_DIRECTORY_UPDATEAPPLICATION, &in, 1),
                 UA_STATUSCODE_BADINVALIDSTATE);
    UA_Variant idv;
    UA_Variant_setScalar(&idv, appId, &UA_TYPES[UA_TYPES_NODEID]);
    CHECK_EQ_INT(call_status(s, UA_GDSID_DIRECTORY_UNREGISTERAPPLICATION, &idv, 1),
                 UA_STATUSCODE_BADINVALIDSTATE);
    set_flag(&rf->refuse, false);
    CHECK_EQ_INT(count_apps(rf->inner), 1);
    return ok;
}

static UA_StatusCode finish(gds_server *s, const UA_NodeId *appId, const UA_NodeId *reqId,
                            bool *gotCert) {
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], (void *)(uintptr_t)reqId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_CallMethodResult res = call(s, UA_GDSID_DIRECTORY_FINISHREQUEST, in, 2);
    *gotCert = res.outputArgumentsSize >= 1 &&
               UA_Variant_hasScalarType(&res.outputArguments[0], &UA_TYPES[UA_TYPES_BYTESTRING]) &&
               ((UA_ByteString *)res.outputArguments[0].data)->length > 0;
    UA_StatusCode r = res.statusCode;
    UA_CallMethodResult_clear(&res);
    return r;
}

/* Wait for the signing worker to leave the request in `want`. */
static bool wait_state(refusing *rf, const UA_Guid *id, gds_req_state want) {
    for(int i = 0; i < 300; i++) {
        gds_request q;
        memset(&q, 0, sizeof(q));
        gds_status st = gds_store_req_get(rf->inner, id, &q);
        gds_req_state got = q.state;
        gds_request_clear(&q);
        if(st == GDS_OK && got == want)
            return true;
        usleep(20000);
    }
    return false;
}

static void test_signing(gds_server *s, refusing *rf, const UA_NodeId *appId) {
    gds_buf csr = {0};
    if(!CHECK(make_csr(&csr) == GDS_OK))
        return;
    UA_NodeId nullId = UA_NODEID_NULL;
    UA_ByteString csrBs = {csr.len, csr.data};
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &nullId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &nullId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[3], &csrBs, &UA_TYPES[UA_TYPES_BYTESTRING]);

    /* the request itself is refused: nothing stored */
    set_flag(&rf->refuse, true);
    CHECK_EQ_INT(call_status(s, UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST, in, 4),
                 UA_STATUSCODE_BADINVALIDSTATE);
    set_flag(&rf->refuse, false);

    /* accepted while the store refuses the worker's commit: the request
     * stays Received, FinishRequest has nothing to return */
    int before = refused(rf);
    set_flag(&rf->refuseIssue, true);
    UA_CallMethodResult res = call(s, UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST, in, 4);
    UA_NodeId reqId = UA_NODEID_NULL;
    if(CHECK(res.statusCode == UA_STATUSCODE_GOOD) && res.outputArgumentsSize == 1)
        (void)UA_NodeId_copy(res.outputArguments[0].data, &reqId);
    UA_CallMethodResult_clear(&res);
    for(int i = 0; i < 300 && refused(rf) == before; i++)
        usleep(20000);
    CHECK(refused(rf) > before); /* the worker's commit was refused */
    CHECK(wait_state(rf, &reqId.identifier.guid, GDS_REQ_RECEIVED));
    bool cert = false;
    set_flag(&rf->refuseIssue, false);
    CHECK_EQ_INT(finish(s, appId, &reqId, &cert), UA_STATUSCODE_BADNOTHINGTODO);
    CHECK(!cert);

    /* the primary again: the worker signs on its next kick */
    gds_worker_kick(s);
    CHECK(wait_state(rf, &reqId.identifier.guid, GDS_REQ_ISSUED));
    /* FinishRequest's Delivered commit refused: no certificate leaves */
    set_flag(&rf->refuse, true);
    CHECK_EQ_INT(finish(s, appId, &reqId, &cert), UA_STATUSCODE_BADINVALIDSTATE);
    CHECK(!cert);
    set_flag(&rf->refuse, false);

    /* a standby refuses before it reads anything */
    CHECK(gds_server_set_role(s, GDS_NODE_STANDBY, 150, 0) == GDS_OK);
    before = refused(rf);
    CHECK_EQ_INT(finish(s, appId, &reqId, &cert), UA_STATUSCODE_BADINVALIDSTATE);
    CHECK_EQ_INT(call_status(s, UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST, in, 4),
                 UA_STATUSCODE_BADINVALIDSTATE);
    CHECK(!cert);
    CHECK_EQ_INT(refused(rf), before); /* refused before the store */
    CHECK(gds_server_set_role(s, GDS_NODE_PRIMARY, 255, 0) == GDS_OK);
    CHECK_EQ_INT(finish(s, appId, &reqId, &cert), UA_STATUSCODE_GOOD);
    CHECK(cert);
    CHECK(wait_state(rf, &reqId.identifier.guid, GDS_REQ_DELIVERED));
    UA_NodeId_clear(&reqId);
    gds_buf_free(&csr);
}

static void test_standby_directory(gds_server *s, refusing *rf, const UA_NodeId *appId) {
    UA_ApplicationRecordDataType rec;
    make_record(&rec);
    rec.applicationUri = UA_STRING("urn:opengds:test:slot:other");
    UA_Variant in;
    UA_Variant_setScalar(&in, &rec, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    UA_Variant idv;
    UA_Variant_setScalar(&idv, (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    CHECK(gds_server_set_role(s, GDS_NODE_STANDBY, 150, 0) == GDS_OK);
    int before = refused(rf);
    CHECK_EQ_INT(call_status(s, UA_GDSID_DIRECTORY_REGISTERAPPLICATION, &in, 1),
                 UA_STATUSCODE_BADINVALIDSTATE);
    CHECK_EQ_INT(call_status(s, UA_GDSID_DIRECTORY_UNREGISTERAPPLICATION, &idv, 1),
                 UA_STATUSCODE_BADINVALIDSTATE);
    CHECK_EQ_INT(refused(rf), before); /* refused before the store */
    /* reads still work on a standby */
    CHECK_EQ_INT(call_status(s, UA_GDSID_DIRECTORY_GETAPPLICATION, &idv, 1), UA_STATUSCODE_GOOD);
    CHECK(gds_server_set_role(s, GDS_NODE_STANDALONE, 255, 0) == GDS_OK);
    CHECK_EQ_INT(count_apps(rf->inner), 1);
}

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    test_open_backend();
    char db[1024], caDir[1024];
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    CHECK(gds_path(db, sizeof(db), "%s/store.db", argv[1]) == GDS_OK);
    CHECK(gds_path(caDir, sizeof(caDir), "%s/ca", argv[1]) == GDS_OK);
    (void)unlink(db);

    static uint8_t pw[] = "slot-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    static refusing rf;
    gds_store *st = NULL;
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    UA_String subject[] = {UA_STRING_STATIC("CN=OpenGDS test")};
    UA_String san[] = {UA_STRING_STATIC("URI:" TEST_URI), UA_STRING_STATIC("DNS:localhost")};
    if(!CHECK(gds_ca_openssl_open(&cc, &ca) == GDS_OK) ||
       !CHECK(gds_store_open(db, &rf.inner) == GDS_OK) ||
       !CHECK(gds_store_open_backend(&refusingBackend, &rf, &st) == GDS_OK) ||
       !CHECK(UA_CreateCertificate(UA_Log_Stdout, subject, 1, san, 2, UA_CERTIFICATEFORMAT_DER,
                                   NULL, &key, &cert) == UA_STATUSCODE_GOOD))
        return CHECK_DONE();

    static gds_users users;
    gds_server_config cfg = {0};
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS store slot test";
    cfg.ownCert = (gds_buf){cert.data, cert.length};
    cfg.ownKey = (gds_buf){key.data, key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_ALL;
    gds_server *s = NULL;
    static gds_session admin;
    admin.roles = GDS_ROLE_DISCOVERY_ADMIN | GDS_ROLE_CERTIFICATE_AUTHORITY_ADMIN;
    admin.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s) {
        UA_Server_setAdminSessionContext(gds_server_ua(s), &admin);
        UA_NodeId appId = UA_NODEID_NULL;
        if(register_app(s, &rf, &appId)) {
            test_signing(s, &rf, &appId);
            test_standby_directory(s, &rf, &appId);
        }
        UA_NodeId_clear(&appId);
        UA_Server_setAdminSessionContext(gds_server_ua(s), NULL);
    }
    gds_server_delete(s);
    gds_store_close(st);
    gds_store_close(rf.inner);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    gds_ca_close(ca);
    return CHECK_DONE();
}
