/* OpenGDS unit test: the Directory and the CertificateManager for
 * embedders (UASM ask A13, issue #81), as a Part 21 Registrar uses them.
 * Registration is idempotent per ApplicationUri; a held application gets
 * no certificate, neither from gds_server_sign_request nor from
 * StartSigningRequest, until it is released; a signed CSR comes back with
 * the issuer chain; the trust list starts with the certificate and CRL of
 * every issuing CA (RSA, P-256, P-384), which are also the group's
 * CertificateTypes;
 * every change is in the audit log with the actor as ClientUserId; a
 * STANDBY node refuses with GDS_ENOTLEADER.
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
#include "gds_plugin.h"
#include "gds_server.h"
#include "store.h"
#include "common/banned.h"

#define TEST_URI "urn:opengds:test:registrar"
#define DEVICE_URI "urn:opengds:test:registrar:device"
#define ACTOR "uasm-registrar"
#define TIMEOUT_MS 20000u

static gds_session admin;

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

static void record(UA_ApplicationRecordDataType *rec, const char *uri, UA_LocalizedText *name,
                   UA_String *disc) {
    UA_ApplicationRecordDataType_init(rec);
    rec->applicationUri = UA_STRING((char *)(uintptr_t)uri);
    rec->applicationType = UA_APPLICATIONTYPE_SERVER;
    rec->productUri = UA_STRING("urn:opengds:test:product");
    rec->applicationNames = name;
    rec->applicationNamesSize = 1;
    rec->discoveryUrls = disc;
    rec->discoveryUrlsSize = 1;
}

/* ---- the audit log ---- */

typedef struct {
    int64_t rows;
    int withActor;
} audit_count;

static bool count_cb(void *ctx, const gds_audit_row *row) {
    audit_count *c = ctx;
    c->rows++;
    static const char actor[] = ACTOR;
    for(size_t i = 0; i + sizeof(actor) - 1 <= row->body.len; i++)
        if(memcmp(row->body.data + i, actor, sizeof(actor) - 1) == 0) {
            c->withActor++;
            break;
        }
    return true;
}

static audit_count audit_rows(gds_server *s) {
    audit_count c = {0, 0};
    gds_lock(s);
    CHECK(gds_store_audit_scan(s->store, 0, count_cb, &c) == GDS_OK);
    gds_unlock(s);
    return c;
}

/* ---- the tests ---- */

static void test_register(gds_server *s, UA_NodeId *appId) {
    UA_LocalizedText name = UA_LOCALIZEDTEXT("en", "Onboarded device");
    UA_String disc = UA_STRING("opc.tcp://device:4840");
    UA_ApplicationRecordDataType rec;
    record(&rec, DEVICE_URI, &name, &disc);
    audit_count before = audit_rows(s);
    bool created = false;
    CHECK(gds_server_register_application(s, ACTOR, &rec, appId, &created) == GDS_OK);
    CHECK(created);
    CHECK(appId->namespaceIndex == s->ns && appId->identifierType == UA_NODEIDTYPE_GUID);
    audit_count after = audit_rows(s);
    CHECK_EQ_INT(after.rows, before.rows + 1);
    CHECK_EQ_INT(after.withActor, before.withActor + 1);

    /* again, e.g. after a failover: the same ApplicationId, nothing new */
    UA_NodeId again = UA_NODEID_NULL;
    CHECK(gds_server_register_application(s, ACTOR, &rec, &again, &created) == GDS_OK);
    CHECK(!created && UA_NodeId_equal(&again, appId));
    CHECK_EQ_INT(audit_rows(s).rows, after.rows);
    UA_NodeId_clear(&again);

    /* the checks of RegisterApplication, and a named actor */
    UA_ApplicationRecordDataType bad = rec;
    bad.applicationUri = UA_STRING_NULL;
    CHECK(gds_server_register_application(s, ACTOR, &bad, &again, &created) == GDS_EINVAL);
    CHECK(gds_server_register_application(s, "", &rec, &again, &created) == GDS_EINVAL);
    CHECK(gds_server_register_application(s, NULL, &rec, &again, &created) == GDS_EINVAL);
}

static void test_trust_list(gds_server *s) {
    UA_TrustListDataType tl;
    if(CHECK(gds_server_get_trust_list(s, NULL, &tl) == GDS_OK)) {
        CHECK_EQ_INT(tl.specifiedLists, UA_TRUSTLISTMASKS_ALL);
        CHECK(tl.trustedCertificatesSize == GDS_CA_ISSUERS &&
              tl.trustedCertificates[0].length == s->caCert.len &&
              memcmp(tl.trustedCertificates[0].data, s->caCert.data, s->caCert.len) == 0);
        for(size_t i = 0; i < tl.trustedCertificatesSize && i < GDS_CA_ISSUERS; i++)
            CHECK(tl.trustedCertificates[i].length == s->issuerCert[i].len &&
                  memcmp(tl.trustedCertificates[i].data, s->issuerCert[i].data,
                         s->issuerCert[i].len) == 0);
        CHECK_EQ_INT(tl.trustedCrlsSize, GDS_CA_ISSUERS);
    }
    /* DefaultApplicationGroup.CertificateTypes: RSA first, then the curves */
    UA_Variant v;
    UA_Variant_init(&v);
    UA_NodeId types = UA_NODEID_NUMERIC(
        s->ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_CERTIFICATETYPES);
    if(CHECK(UA_Server_readValue(gds_server_ua(s), types, &v) == UA_STATUSCODE_GOOD) &&
       CHECK(UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_NODEID])) &&
       CHECK_EQ_INT(v.arrayLength, 3)) {
        const UA_NodeId *t = v.data;
        CHECK(t[0].identifier.numeric == UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE &&
              t[1].identifier.numeric == UA_NS0ID_ECCNISTP256APPLICATIONCERTIFICATETYPE &&
              t[2].identifier.numeric == UA_NS0ID_ECCNISTP384APPLICATIONCERTIFICATETYPE);
    }
    UA_Variant_clear(&v);
    UA_TrustListDataType_clear(&tl);
    UA_NodeId def =
        UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    CHECK(gds_server_get_trust_list(s, &def, &tl) == GDS_OK);
    UA_TrustListDataType_clear(&tl);
    UA_NodeId other = UA_NODEID_NUMERIC(s->ns, 999999);
    CHECK(gds_server_get_trust_list(s, &other, &tl) == GDS_ENOTFOUND);
}

static gds_status sign(gds_server *s, const UA_NodeId *appId, UA_ByteString *cert) {
    UA_ByteString csr;
    if(make_csr(&csr) != GDS_OK)
        return GDS_ECRYPTO;
    UA_ByteString *issuers = NULL;
    size_t n = 0;
    gds_status st =
        gds_server_sign_request(s, ACTOR, appId, NULL, NULL, &csr, TIMEOUT_MS, cert, &issuers, &n);
    if(st == GDS_OK)
        CHECK(n == 1 && issuers[0].length == s->caCert.len &&
              memcmp(issuers[0].data, s->caCert.data, s->caCert.len) == 0);
    else
        CHECK(n == 0 && !issuers && cert->length == 0);
    UA_Array_delete(issuers, n, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_ByteString_clear(&csr);
    return st;
}

/* StartSigningRequest as a CertificateAuthorityAdmin session */
static UA_StatusCode start_signing(gds_server *s, const UA_NodeId *appId) {
    UA_ByteString csr;
    if(make_csr(&csr) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_NodeId group = UA_NODEID_NULL, type = UA_NODEID_NULL;
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &type, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[3], &csr, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY);
    req.methodId = UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST);
    req.inputArguments = in;
    req.inputArgumentsSize = 4;
    UA_CallMethodResult res = UA_Server_call(gds_server_ua(s), &req);
    UA_StatusCode r = res.statusCode;
    UA_CallMethodResult_clear(&res);
    UA_ByteString_clear(&csr);
    return r;
}

static void test_sign(gds_server *s, const UA_NodeId *appId) {
    /* held until the software is updated */
    CHECK(gds_server_set_issuance_allowed(s, appId, false) == GDS_OK);
    CHECK(gds_server_set_issuance_allowed(s, appId, false) == GDS_OK); /* twice is fine */
    UA_ByteString cert = UA_BYTESTRING_NULL;
    CHECK(sign(s, appId, &cert) == GDS_EDENIED);
    CHECK_EQ_INT(start_signing(s, appId), UA_STATUSCODE_BADREQUESTNOTALLOWED);

    /* released: signed through the worker and the CA, delivered */
    CHECK(gds_server_set_issuance_allowed(s, appId, true) == GDS_OK);
    audit_count before = audit_rows(s);
    if(CHECK(sign(s, appId, &cert) == GDS_OK)) {
        const unsigned char *p = cert.data;
        X509 *x = d2i_X509(NULL, &p, (long)cert.length);
        CHECK(x != NULL);
        X509_free(x);
    }
    UA_ByteString_clear(&cert);
    audit_count after = audit_rows(s);
    CHECK_EQ_INT(after.rows, before.rows + 2); /* requested, delivered */
    CHECK_EQ_INT(after.withActor, before.withActor + 2);
    /* the certificate is in the directory */
    gds_buf der = {0};
    int64_t notAfter = 0;
    gds_lock(s);
    CHECK(gds_store_cert_latest(s->store, &appId->identifier.guid,
                                UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP,
                                UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE, &der,
                                &notAfter) == GDS_OK);
    gds_unlock(s);
    gds_buf_free(&der);

    /* bad input */
    UA_ByteString junk = UA_BYTESTRING("not a CSR"), *iss = NULL;
    size_t n = 0;
    CHECK(gds_server_sign_request(s, ACTOR, appId, NULL, NULL, &junk, TIMEOUT_MS, &cert, &iss,
                                  &n) == GDS_EINVAL);
    UA_NodeId otherGroup = UA_NODEID_NUMERIC(s->ns, 999999);
    UA_ByteString csr;
    if(CHECK(make_csr(&csr) == GDS_OK)) {
        CHECK(gds_server_sign_request(s, ACTOR, appId, &otherGroup, NULL, &csr, TIMEOUT_MS, &cert,
                                      &iss, &n) == GDS_EINVAL);
        UA_NodeId unknown = UA_NODEID_GUID(s->ns, UA_GUID("00000000-0000-0000-0000-00000000abcd"));
        CHECK(gds_server_sign_request(s, ACTOR, &unknown, NULL, NULL, &csr, TIMEOUT_MS, &cert,
                                      &iss, &n) == GDS_ENOTFOUND);
        CHECK(gds_server_set_issuance_allowed(s, &unknown, false) == GDS_ENOTFOUND);
        CHECK(gds_server_set_issuance_allowed(s, &unknown, true) == GDS_OK);
        UA_NodeId wrongNs = UA_NODEID_GUID(0, appId->identifier.guid);
        CHECK(gds_server_sign_request(s, ACTOR, &wrongNs, NULL, NULL, &csr, TIMEOUT_MS, &cert,
                                      &iss, &n) == GDS_EINVAL);
    }
    UA_ByteString_clear(&csr);
}

static void test_standby(gds_server *s, const UA_NodeId *appId) {
    CHECK(gds_server_set_role(s, GDS_NODE_STANDBY, 150, 0) == GDS_OK);
    UA_LocalizedText name = UA_LOCALIZEDTEXT("en", "Another device");
    UA_String disc = UA_STRING("opc.tcp://other:4840");
    UA_ApplicationRecordDataType rec;
    record(&rec, DEVICE_URI ":2", &name, &disc);
    UA_NodeId id = UA_NODEID_NULL;
    bool created = true;
    CHECK(gds_server_register_application(s, ACTOR, &rec, &id, &created) == GDS_ENOTLEADER);
    CHECK(!created);
    UA_ByteString cert = UA_BYTESTRING_NULL;
    CHECK(sign(s, appId, &cert) == GDS_ENOTLEADER);
    /* reading the trust list is not a change */
    UA_TrustListDataType tl;
    CHECK(gds_server_get_trust_list(s, NULL, &tl) == GDS_OK);
    UA_TrustListDataType_clear(&tl);
    CHECK(gds_server_set_role(s, GDS_NODE_STANDALONE, 255, 0) == GDS_OK);
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

    static uint8_t pw[] = "registrar-test-passphrase";
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
    memcpy(admin.user, "admin", sizeof("admin"));

    static gds_users users;
    gds_server_config cfg = {0};
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS registrar test";
    cfg.ownCert = (gds_buf){cert.data, cert.length};
    cfg.ownKey = (gds_buf){key.data, key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_MANUAL; /* the embedder is the approver: no dialog */

    gds_server *s = NULL;
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s) {
        UA_Server_setAdminSessionContext(gds_server_ua(s), &admin);
        UA_NodeId appId = UA_NODEID_NULL;
        test_register(s, &appId);
        test_trust_list(s);
        if(!UA_NodeId_isNull(&appId)) {
            test_sign(s, &appId);
            test_standby(s, &appId);
        }
        UA_NodeId_clear(&appId);
        UA_Server_setAdminSessionContext(gds_server_ua(s), NULL);
    }
    gds_server_delete(s);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    gds_store_close(st);
    gds_ca_close(ca);
    return CHECK_DONE();
}
