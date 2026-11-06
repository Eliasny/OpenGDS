/* OpenGDS unit test: approvals (gds_approvals.c, gds_policy.c).
 *
 * A request that the policy does not approve waits as Pending with a Part 9
 * DialogCondition (ns=1;g=<RequestId>); FinishRequest answers
 * Bad_NothingToDo. A RegistrationAuthorityAdmin approves it with Respond2
 * (the worker then signs it) or rejects it with Respond (FinishRequest then
 * answers Bad_RequestNotAllowed). Other sessions are refused; decided
 * dialogs are gone; a restart raises the dialogs of Pending requests
 * again; the renewals policy approves a renewal on arrival.
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
#include "common/ids.h"
#include "gds_internal.h"
#include "gds_server.h"
#include "store.h"
#include "common/banned.h"

#define TEST_URI "urn:opengds:test:approvals"

static gds_session admin, approver, outsider;

/* ---- helpers ---- */

static UA_CallMethodResult call_on(gds_server *s, gds_session *as, UA_NodeId obj, UA_NodeId method,
                                   UA_Variant *in, size_t n) {
    UA_Server_setAdminSessionContext(gds_server_ua(s), as);
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = obj;
    req.methodId = method;
    req.inputArguments = in;
    req.inputArgumentsSize = n;
    UA_CallMethodResult res = UA_Server_call(gds_server_ua(s), &req);
    UA_Server_setAdminSessionContext(gds_server_ua(s), &admin);
    return res;
}

static UA_CallMethodResult call(gds_server *s, UA_UInt32 method, UA_Variant *in, size_t n) {
    return call_on(s, &admin, UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY),
                   UA_NODEID_NUMERIC(s->ns, method), in, n);
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

static bool register_app(gds_server *s, const char *uri, UA_NodeId *appId) {
    UA_LocalizedText name = UA_LOCALIZEDTEXT("en", "Approvals app");
    UA_String disc = UA_STRING("opc.tcp://localhost:4840");
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    rec.applicationUri = UA_STRING((char *)(uintptr_t)uri);
    rec.applicationType = UA_APPLICATIONTYPE_SERVER;
    rec.productUri = UA_STRING("urn:opengds:test:product");
    rec.applicationNames = &name;
    rec.applicationNamesSize = 1;
    rec.discoveryUrls = &disc;
    rec.discoveryUrlsSize = 1;
    UA_Variant in;
    UA_Variant_setScalar(&in, &rec, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    UA_CallMethodResult res = call(s, UA_GDSID_DIRECTORY_REGISTERAPPLICATION, &in, 1);
    bool ok = CHECK(res.statusCode == UA_STATUSCODE_GOOD) && res.outputArgumentsSize == 1 &&
              UA_Variant_hasScalarType(&res.outputArguments[0], &UA_TYPES[UA_TYPES_NODEID]) &&
              UA_NodeId_copy(res.outputArguments[0].data, appId) == UA_STATUSCODE_GOOD;
    UA_CallMethodResult_clear(&res);
    return ok;
}

/* StartSigningRequest made by session `as`; the RequestId's GUID in *reqId. */
static UA_StatusCode start_as(gds_server *s, gds_session *as, const UA_NodeId *appId,
                              UA_NodeId *reqId) {
    gds_buf csr = {0};
    if(make_csr(&csr) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_NodeId group = UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_NodeId type = UA_NS0ID(RSASHA256APPLICATIONCERTIFICATETYPE);
    UA_ByteString csrBs = {csr.len, csr.data};
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &type, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[3], &csrBs, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_CallMethodResult res = call_on(s, as, UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY),
                                      UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST),
                                      in, 4);
    UA_StatusCode r = res.statusCode;
    if(r == UA_STATUSCODE_GOOD &&
       !(res.outputArgumentsSize == 1 &&
         UA_Variant_hasScalarType(&res.outputArguments[0], &UA_TYPES[UA_TYPES_NODEID]) &&
         UA_NodeId_copy(res.outputArguments[0].data, reqId) == UA_STATUSCODE_GOOD))
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    UA_CallMethodResult_clear(&res);
    gds_buf_free(&csr);
    return r;
}

static UA_StatusCode start(gds_server *s, const UA_NodeId *appId, UA_NodeId *reqId) {
    return start_as(s, &admin, appId, reqId);
}

static UA_StatusCode finish(gds_server *s, const UA_NodeId *appId, const UA_NodeId *reqId) {
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], (void *)(uintptr_t)reqId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_CallMethodResult res = call(s, UA_GDSID_DIRECTORY_FINISHREQUEST, in, 2);
    UA_StatusCode r = res.statusCode;
    if(r == UA_STATUSCODE_GOOD &&
       !(res.outputArgumentsSize >= 1 &&
         UA_Variant_hasScalarType(&res.outputArguments[0], &UA_TYPES[UA_TYPES_BYTESTRING]) &&
         ((UA_ByteString *)res.outputArguments[0].data)->length > 0))
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    UA_CallMethodResult_clear(&res);
    return r;
}

/* FinishRequest until it stops answering Bad_NothingToDo (the worker signs). */
static UA_StatusCode finish_wait(gds_server *s, const UA_NodeId *appId, const UA_NodeId *reqId) {
    UA_StatusCode r = UA_STATUSCODE_BADNOTHINGTODO;
    for(int i = 0; i < 500 && r == UA_STATUSCODE_BADNOTHINGTODO; i++) {
        r = finish(s, appId, reqId);
        if(r == UA_STATUSCODE_BADNOTHINGTODO)
            usleep(20000);
    }
    return r;
}

static UA_NodeId dialog_of(const UA_NodeId *reqId) {
    return UA_NODEID_GUID(1, reqId->identifier.guid);
}

static UA_StatusCode respond2(gds_server *s, gds_session *as, const UA_NodeId *reqId, UA_Int32 resp,
                              const char *comment) {
    UA_LocalizedText c = comment ? UA_LOCALIZEDTEXT("en", (char *)(uintptr_t)comment)
                                 : (UA_LocalizedText){UA_STRING_NULL, UA_STRING_NULL};
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &resp, &UA_TYPES[UA_TYPES_INT32]);
    UA_Variant_setScalar(&in[1], &c, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    UA_CallMethodResult res = call_on(s, as, dialog_of(reqId), UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND2),
                                      in, 2);
    UA_StatusCode r = res.statusCode;
    UA_CallMethodResult_clear(&res);
    return r;
}

static UA_StatusCode respond(gds_server *s, gds_session *as, const UA_NodeId *reqId, UA_Int32 resp) {
    UA_Variant in;
    UA_Variant_setScalar(&in, &resp, &UA_TYPES[UA_TYPES_INT32]);
    UA_CallMethodResult res = call_on(s, as, dialog_of(reqId), UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND),
                                      &in, 1);
    UA_StatusCode r = res.statusCode;
    UA_CallMethodResult_clear(&res);
    return r;
}

/* Retain and DialogState/Id of the dialog; false if it does not exist. */
static bool dialog_active(gds_server *s, const UA_NodeId *reqId, bool *retain) {
    UA_Server *ua = gds_server_ua(s);
    UA_QualifiedName path[2] = {UA_QUALIFIEDNAME(0, "DialogState"), UA_QUALIFIEDNAME(0, "Id")};
    UA_QualifiedName rp = UA_QUALIFIEDNAME(0, "Retain");
    UA_BrowsePathResult b1 = UA_Server_browseSimplifiedBrowsePath(ua, dialog_of(reqId), 2, path);
    UA_BrowsePathResult b2 = UA_Server_browseSimplifiedBrowsePath(ua, dialog_of(reqId), 1, &rp);
    bool active = false;
    *retain = false;
    if(b1.statusCode == UA_STATUSCODE_GOOD && b1.targetsSize == 1 &&
       b2.statusCode == UA_STATUSCODE_GOOD && b2.targetsSize == 1) {
        UA_Variant v;
        if(UA_Server_readValue(ua, b1.targets[0].targetId.nodeId, &v) == UA_STATUSCODE_GOOD &&
           UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_BOOLEAN]))
            active = *(UA_Boolean *)v.data;
        UA_Variant_clear(&v);
        if(UA_Server_readValue(ua, b2.targets[0].targetId.nodeId, &v) == UA_STATUSCODE_GOOD &&
           UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_BOOLEAN]))
            *retain = *(UA_Boolean *)v.data;
        UA_Variant_clear(&v);
    }
    bool exists = b2.statusCode == UA_STATUSCODE_GOOD;
    UA_BrowsePathResult_clear(&b1);
    UA_BrowsePathResult_clear(&b2);
    return exists && active;
}

static bool dialog_exists(gds_server *s, const UA_NodeId *reqId) {
    UA_NodeClass nc;
    return UA_Server_readNodeClass(gds_server_ua(s), dialog_of(reqId), &nc) == UA_STATUSCODE_GOOD;
}

/* ---- cases ---- */

/* Manual: pending, refused answers, approve, reject; one left pending. */
static void test_manual(gds_server *s, const UA_NodeId *appId, UA_NodeId *leftPending) {
    UA_NodeId a = UA_NODEID_NULL, b = UA_NODEID_NULL;
    if(!CHECK_EQ_INT(start(s, appId, &a), UA_STATUSCODE_GOOD))
        return;
    CHECK_EQ_INT(finish(s, appId, &a), UA_STATUSCODE_BADNOTHINGTODO);
    bool retain = false;
    CHECK(dialog_active(s, &a, &retain) && retain);
    usleep(300000); /* the worker must not sign a Pending request */
    CHECK_EQ_INT(finish(s, appId, &a), UA_STATUSCODE_BADNOTHINGTODO);

    /* refused: a CA admin without RegistrationAuthorityAdmin, bad answers */
    UA_NodeId r2 = UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND2), r1 = UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND);
    CHECK(!gds_method_executable(s, &admin, &r2));
    CHECK(gds_method_executable(s, &approver, &r2));
    CHECK(gds_method_executable(s, &approver, &r1));
    CHECK_EQ_INT(respond2(s, &admin, &a, 0, "self-approval"), UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(respond2(s, &outsider, &a, 0, NULL), UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(respond2(s, &approver, &a, 7, NULL), UA_STATUSCODE_BADDIALOGRESPONSEINVALID);
    CHECK(dialog_active(s, &a, &retain) && retain);
    CHECK_EQ_INT(finish(s, appId, &a), UA_STATUSCODE_BADNOTHINGTODO);

    /* approve: the dialog goes, the worker signs */
    CHECK_EQ_INT(respond2(s, &approver, &a, 0, "known device"), UA_STATUSCODE_GOOD);
    CHECK(!dialog_exists(s, &a));
    CHECK_EQ_INT(finish_wait(s, appId, &a), UA_STATUSCODE_GOOD);
    CHECK(respond2(s, &approver, &a, 0, NULL) != UA_STATUSCODE_GOOD); /* decided */

    /* reject with Respond (1.04) */
    if(CHECK_EQ_INT(start(s, appId, &b), UA_STATUSCODE_GOOD)) {
        CHECK(dialog_exists(s, &b));
        CHECK_EQ_INT(respond(s, &approver, &b, 1), UA_STATUSCODE_GOOD);
        CHECK(!dialog_exists(s, &b));
        CHECK_EQ_INT(finish(s, appId, &b), UA_STATUSCODE_BADREQUESTNOTALLOWED);
    }
    CHECK_EQ_INT(start(s, appId, leftPending), UA_STATUSCODE_GOOD);
    UA_NodeId_clear(&a);
    UA_NodeId_clear(&b);
}

/* After a restart: the Pending request has its dialog again. */
static void test_rebuilt(gds_server *s, const UA_NodeId *appId, const UA_NodeId *pending) {
    bool retain = false;
    CHECK(dialog_active(s, pending, &retain) && retain);
    CHECK_EQ_INT(finish(s, appId, pending), UA_STATUSCODE_BADNOTHINGTODO);
    CHECK_EQ_INT(respond2(s, &approver, pending, 0, NULL), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(finish_wait(s, appId, pending), UA_STATUSCODE_GOOD);
}

static void iterate(gds_server *s) {
    for(int i = 0; i < 20; i++)
        (void)UA_Server_run_iterate(gds_server_ua(s), false);
}

/* Failover: a STANDBY shows no dialogs; on promotion the dialogs follow
 * the store, where another node decided one request and received another. */
static void test_failover(gds_server *s, gds_store *st, const UA_NodeId *appId) {
    UA_NodeId a = UA_NODEID_NULL, b = UA_NODEID_NULL;
    if(!CHECK_EQ_INT(start(s, appId, &a), UA_STATUSCODE_GOOD) ||
       !CHECK_EQ_INT(UA_Server_run_startup(gds_server_ua(s)), UA_STATUSCODE_GOOD))
        return;
    CHECK(gds_server_set_role(s, GDS_NODE_STANDBY, 100, 0) == GDS_OK);
    iterate(s);
    CHECK(!dialog_exists(s, &a));
    CHECK_EQ_INT(respond2(s, &approver, &a, 0, NULL), UA_STATUSCODE_BADNODEIDUNKNOWN);
    /* meanwhile on the primary: a decided, b received */
    CHECK(gds_store_req_set_state(st, &a.identifier.guid, GDS_REQ_RECEIVED, NULL, 0) == GDS_OK);
    gds_request q;
    memset(&q, 0, sizeof(q));
    CHECK(gds_guid_random(&q.id) == GDS_OK);
    q.appId = appId->identifier.guid;
    q.groupId = UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP;
    q.certType = UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE;
    q.state = GDS_REQ_PENDING;
    CHECK(gds_store_req_insert(st, &q) == GDS_OK);
    b = UA_NODEID_GUID(s->ns, q.id);
    CHECK(gds_server_set_role(s, GDS_NODE_PRIMARY, 255, 0) == GDS_OK);
    iterate(s);
    bool retain = false;
    CHECK(!dialog_exists(s, &a));
    CHECK(dialog_active(s, &b, &retain) && retain);
    CHECK_EQ_INT(respond2(s, &approver, &b, 1, "duplicate"), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(finish(s, appId, &b), UA_STATUSCODE_BADREQUESTNOTALLOWED);
    CHECK_EQ_INT(UA_Server_run_shutdown(gds_server_ua(s)), UA_STATUSCODE_GOOD);
    UA_NodeId_clear(&a);
}

/* Renewals: the app with a certificate is approved on arrival; a new one waits. */
/* A session whose secure channel uses the application's newest certificate. */
static bool holder_of_latest(gds_store *st, const UA_NodeId *appId, gds_session *out) {
    gds_buf der = {0};
    int64_t notAfter = 0;
    memset(out, 0, sizeof(*out));
    if(!CHECK(gds_store_cert_latest(st, &appId->identifier.guid,
                                    UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP,
                                    UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE, &der,
                                    &notAfter) == GDS_OK))
        return false;
    out->securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    out->clientAppUri = UA_STRING_ALLOC(TEST_URI ":app");
    out->clientCert.data = der.data; /* owned by the session now */
    out->clientCert.length = der.len;
    return true;
}

static void holder_clear(gds_session *h) {
    UA_String_clear(&h->clientAppUri);
    UA_ByteString_clear(&h->clientCert);
}

/* Only the holder of the prior certificate renews without approval. */
static void test_renewals(gds_server *s, gds_store *st, const UA_NodeId *appId) {
    UA_NodeId r1 = UA_NODEID_NULL, r2 = UA_NODEID_NULL, r3 = UA_NODEID_NULL,
              r4 = UA_NODEID_NULL, other = UA_NODEID_NULL;
    gds_session holder, older;
    memset(&older, 0, sizeof(older));
    if(holder_of_latest(st, appId, &holder) &&
       CHECK_EQ_INT(start_as(s, &holder, appId, &r1), UA_STATUSCODE_GOOD)) {
        CHECK(!dialog_exists(s, &r1));
        CHECK_EQ_INT(finish_wait(s, appId, &r1), UA_STATUSCODE_GOOD);
    }
    /* the certificate just replaced no longer renews */
    older = holder;
    if(holder_of_latest(st, appId, &holder) &&
       CHECK_EQ_INT(start_as(s, &older, appId, &r2), UA_STATUSCODE_GOOD))
        CHECK(dialog_exists(s, &r2));
    /* an administrator does not hold the certificate */
    if(CHECK_EQ_INT(start(s, appId, &r3), UA_STATUSCODE_GOOD))
        CHECK(dialog_exists(s, &r3));
    if(register_app(s, TEST_URI ":new", &other) &&
       CHECK_EQ_INT(start(s, &other, &r4), UA_STATUSCODE_GOOD)) {
        CHECK(dialog_exists(s, &r4));
        CHECK_EQ_INT(finish(s, &other, &r4), UA_STATUSCODE_BADNOTHINGTODO);
    }
    holder_clear(&holder);
    holder_clear(&older);
    UA_NodeId_clear(&r1);
    UA_NodeId_clear(&r2);
    UA_NodeId_clear(&r3);
    UA_NodeId_clear(&r4);
    UA_NodeId_clear(&other);
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

    static uint8_t pw[] = "approvals-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    gds_store *st = NULL;
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    UA_String subject[] = {UA_STRING_STATIC("CN=OpenGDS test")};
    UA_String san[] = {UA_STRING_STATIC("URI:" TEST_URI), UA_STRING_STATIC("DNS:localhost")};
    if(!CHECK(gds_ca_openssl_open(&cc, &ca) == GDS_OK) || !CHECK(gds_store_open(db, &st) == GDS_OK) ||
       !CHECK(UA_CreateCertificate(UA_Log_Stdout, subject, 1, san, 2, UA_CERTIFICATEFORMAT_DER,
                                   NULL, &key, &cert) == UA_STATUSCODE_GOOD))
        return CHECK_DONE();

    admin.roles = GDS_ROLE_DISCOVERY_ADMIN | GDS_ROLE_CERTIFICATE_AUTHORITY_ADMIN;
    admin.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    memcpy(admin.user, "registrar", sizeof("registrar"));
    approver.roles = GDS_ROLE_REGISTRATION_AUTHORITY_ADMIN;
    approver.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    memcpy(approver.user, "approver", sizeof("approver"));
    outsider.anonymous = true;
    outsider.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;

    static gds_users users;
    gds_server_config cfg = {0};
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS approvals test";
    cfg.ownCert = (gds_buf){cert.data, cert.length};
    cfg.ownKey = (gds_buf){key.data, key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;

    gds_server *s = NULL;
    gds_server_config bad = cfg; /* no policy: refused */
    CHECK(gds_server_new(&bad, &s) == GDS_EINVAL && !s);

    UA_NodeId appId = UA_NODEID_NULL, pending = UA_NODEID_NULL;
    cfg.approval = GDS_APPROVE_MANUAL;
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s) {
        UA_Server_setAdminSessionContext(gds_server_ua(s), &admin);
        if(register_app(s, TEST_URI ":app", &appId))
            test_manual(s, &appId, &pending);
        UA_Server_setAdminSessionContext(gds_server_ua(s), NULL);
    }
    gds_server_delete(s);
    s = NULL;

    /* restart on the same store */
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s) {
        UA_Server_setAdminSessionContext(gds_server_ua(s), &admin);
        test_rebuilt(s, &appId, &pending);
        test_failover(s, st, &appId);
        UA_Server_setAdminSessionContext(gds_server_ua(s), NULL);
    }
    gds_server_delete(s);
    s = NULL;

    cfg.approval = GDS_APPROVE_RENEWALS;
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s) {
        UA_Server_setAdminSessionContext(gds_server_ua(s), &admin);
        test_renewals(s, st, &appId);
        UA_Server_setAdminSessionContext(gds_server_ua(s), NULL);
    }
    gds_server_delete(s);

    UA_NodeId_clear(&appId);
    UA_NodeId_clear(&pending);
    gds_store_close(st);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    gds_ca_close(ca);
    return CHECK_DONE();
}
