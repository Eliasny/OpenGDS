/* OpenGDS unit test: RevokeCertificate (OPC 10000-12 §7.9.6) and the
 * revocation done by UnregisterApplication (§6.5.8).
 *
 * Only a CertificateAuthorityAdmin revokes; an unknown application is
 * Bad_NotFound; a certificate this GDS did not issue to that application is
 * Bad_InvalidArgument. A revoked certificate is on the CA's CRL (which every
 * trust list carries) and GetCertificateStatus then asks for an update.
 * Revoking again succeeds and adds nothing. Unregistering an application
 * puts all of its certificates on the CRL. A STANDBY refuses.
 * GetCertificates (§7.9.8) returns the valid certificate and no revoked
 * one; CheckRevocationStatus (§7.9.11) tells Good, revoked, a broken
 * signature, garbage and a certificate of another issuer apart.
 * ECC certificates (P-256, P-384) come from, are checked against and are
 * revoked on the CRL of their own curve's issuing CA.
 * gds_server_revoke_serial (UASM ask A23) puts a serial the store marks
 * revoked on the issuer's CRL by certificate, by type, or on all of them.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/plugin/certificategroup.h>
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

#define TEST_URI "urn:opengds:test:revoke"

/* Entries on a CRL (an empty CRL has no list at all). */
static int crl_count(X509_CRL *crl) {
    STACK_OF(X509_REVOKED) *l = X509_CRL_get_REVOKED(crl);
    return l ? sk_X509_REVOKED_num(l) : 0;
}

static gds_session admin, registrar;

/* ---- helpers ---- */

static UA_CallMethodResult call_as(gds_server *s, gds_session *as, UA_UInt32 method,
                                   UA_Variant *in, size_t n) {
    UA_Server_setAdminSessionContext(gds_server_ua(s), as);
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY);
    req.methodId = UA_NODEID_NUMERIC(s->ns, method);
    req.inputArguments = in;
    req.inputArgumentsSize = n;
    UA_CallMethodResult res = UA_Server_call(gds_server_ua(s), &req);
    UA_Server_setAdminSessionContext(gds_server_ua(s), &admin);
    return res;
}

static UA_StatusCode call_status(gds_server *s, gds_session *as, UA_UInt32 method, UA_Variant *in,
                                 size_t n) {
    UA_CallMethodResult res = call_as(s, as, method, in, n);
    UA_StatusCode r = res.statusCode;
    UA_CallMethodResult_clear(&res);
    return r;
}

/* A CSR for certType: RSA 2048, or an EC key on the type's curve. */
static gds_status make_csr_of(UA_UInt32 certType, gds_buf *out) {
    EVP_PKEY *key = NULL;
    if(certType == UA_NS0ID_ECCNISTP256APPLICATIONCERTIFICATETYPE)
        key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    else if(certType == UA_NS0ID_ECCNISTP384APPLICATIONCERTIFICATETYPE)
        key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384");
    else
        key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
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
    UA_LocalizedText name = UA_LOCALIZEDTEXT("en", "Revoke app");
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
    UA_CallMethodResult res = call_as(s, &admin, UA_GDSID_DIRECTORY_REGISTERAPPLICATION, &in, 1);
    bool ok = CHECK(res.statusCode == UA_STATUSCODE_GOOD) && res.outputArgumentsSize == 1 &&
              UA_Variant_hasScalarType(&res.outputArguments[0], &UA_TYPES[UA_TYPES_NODEID]) &&
              UA_NodeId_copy(res.outputArguments[0].data, appId) == UA_STATUSCODE_GOOD;
    UA_CallMethodResult_clear(&res);
    return ok;
}

/* The issuer FinishRequest returned is the one for certType. */
static void check_issuers(gds_server *s, UA_UInt32 certType, const UA_Variant *v) {
    const gds_buf *want = gds_issuer_cert(s, certType);
    const UA_ByteString *got = v->data;
    if(CHECK(want != NULL) && CHECK(v->arrayLength == 1) &&
       CHECK(UA_Variant_hasArrayType(v, &UA_TYPES[UA_TYPES_BYTESTRING])))
        CHECK(got[0].length == want->len && memcmp(got[0].data, want->data, want->len) == 0);
}

/* StartSigningRequest for certType, then FinishRequest until the worker
 * has signed: the issued certificate in *cert. */
static bool issue_type(gds_server *s, const UA_NodeId *appId, UA_UInt32 certType,
                       UA_ByteString *cert) {
    gds_buf csr = {0};
    if(!CHECK(make_csr_of(certType, &csr) == GDS_OK))
        return false;
    UA_NodeId group = UA_NODEID_NUMERIC(s->ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_NodeId type = UA_NODEID_NUMERIC(0, certType);
    UA_ByteString csrBs = {csr.len, csr.data};
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &type, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[3], &csrBs, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_CallMethodResult res = call_as(s, &admin, UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST, in, 4);
    gds_buf_free(&csr);
    UA_NodeId reqId = UA_NODEID_NULL;
    bool ok = CHECK(res.statusCode == UA_STATUSCODE_GOOD) && res.outputArgumentsSize == 1 &&
              UA_Variant_hasScalarType(&res.outputArguments[0], &UA_TYPES[UA_TYPES_NODEID]) &&
              UA_NodeId_copy(res.outputArguments[0].data, &reqId) == UA_STATUSCODE_GOOD;
    UA_CallMethodResult_clear(&res);
    UA_StatusCode r = UA_STATUSCODE_BADNOTHINGTODO;
    for(int i = 0; ok && i < 500 && r == UA_STATUSCODE_BADNOTHINGTODO; i++) {
        UA_Variant fin[2];
        UA_Variant_setScalar(&fin[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&fin[1], &reqId, &UA_TYPES[UA_TYPES_NODEID]);
        res = call_as(s, &admin, UA_GDSID_DIRECTORY_FINISHREQUEST, fin, 2);
        r = res.statusCode;
        if(r == UA_STATUSCODE_GOOD && res.outputArgumentsSize == 3 &&
           UA_Variant_hasScalarType(&res.outputArguments[0], &UA_TYPES[UA_TYPES_BYTESTRING])) {
            check_issuers(s, certType, &res.outputArguments[2]);
            r = UA_ByteString_copy(res.outputArguments[0].data, cert);
        }
        UA_CallMethodResult_clear(&res);
        if(r == UA_STATUSCODE_BADNOTHINGTODO)
            usleep(20000);
    }
    UA_NodeId_clear(&reqId);
    return ok && CHECK_EQ_INT(r, UA_STATUSCODE_GOOD) && cert->length > 0;
}

static bool issue(gds_server *s, const UA_NodeId *appId, UA_ByteString *cert) {
    return issue_type(s, appId, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE, cert);
}

static UA_StatusCode revoke_cert(gds_server *s, gds_session *as, const UA_NodeId *appId,
                                 const UA_ByteString *cert) {
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], (void *)(uintptr_t)cert, &UA_TYPES[UA_TYPES_BYTESTRING]);
    return call_status(s, as, UA_GDSID_DIRECTORY_REVOKECERTIFICATE, in, 2);
}

/* Is cert on the issuer's current CRL? *entries: the CRL's entry count. */
static bool on_issuer_crl(gds_ca *ca, gds_ca_issuer issuer, const UA_ByteString *cert,
                          int *entries) {
    gds_buf der = {0};
    CHECK(gds_ca_get_issuer_crl(ca, issuer, &der) == GDS_OK);
    const unsigned char *p = der.data;
    X509_CRL *crl = der.data ? d2i_X509_CRL(NULL, &p, (long)der.len) : NULL;
    p = cert->data;
    X509 *x = cert->length ? d2i_X509(NULL, &p, (long)cert->length) : NULL;
    X509_REVOKED *e = NULL;
    bool found = crl && x && X509_CRL_get0_by_cert(crl, &e, x) == 1;
    if(entries)
        *entries = crl ? crl_count(crl) : -1;
    X509_free(x);
    X509_CRL_free(crl);
    gds_buf_free(&der);
    return found;
}

static bool on_crl(gds_ca *ca, const UA_ByteString *cert, int *entries) {
    return on_issuer_crl(ca, GDS_CA_ISSUER_RSA, cert, entries);
}

static bool update_required(gds_server *s, const UA_NodeId *appId) {
    UA_Variant in[3];
    UA_NodeId none = UA_NODEID_NULL;
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &none, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &none, &UA_TYPES[UA_TYPES_NODEID]);
    UA_CallMethodResult res = call_as(s, &admin, UA_GDSID_DIRECTORY_GETCERTIFICATESTATUS, in, 3);
    bool req = CHECK(res.statusCode == UA_STATUSCODE_GOOD) && res.outputArgumentsSize == 1 &&
               UA_Variant_hasScalarType(&res.outputArguments[0], &UA_TYPES[UA_TYPES_BOOLEAN]) &&
               *(UA_Boolean *)res.outputArguments[0].data;
    UA_CallMethodResult_clear(&res);
    return req;
}

/* ---- tests ---- */

static void test_revoke(gds_server *s, gds_ca *ca, const UA_NodeId *a, const UA_NodeId *b) {
    UA_ByteString certA = UA_BYTESTRING_NULL;
    if(!issue(s, a, &certA))
        return;
    int before = 0, after = 0;
    CHECK(!on_crl(ca, &certA, &before));
    CHECK(!update_required(s, a));
    /* only a CertificateAuthorityAdmin */
    CHECK_EQ_INT(revoke_cert(s, &registrar, a, &certA), UA_STATUSCODE_BADUSERACCESSDENIED);
    /* an application that is not registered */
    UA_Guid g;
    CHECK(gds_guid_random(&g) == GDS_OK);
    UA_NodeId unknown = UA_NODEID_GUID(s->ns, g);
    CHECK_EQ_INT(revoke_cert(s, &admin, &unknown, &certA), UA_STATUSCODE_BADNOTFOUND);
    /* a certificate not issued to that application, or not by this GDS */
    CHECK_EQ_INT(revoke_cert(s, &admin, b, &certA), UA_STATUSCODE_BADINVALIDARGUMENT);
    UA_ByteString junk = UA_BYTESTRING("not a certificate");
    CHECK_EQ_INT(revoke_cert(s, &admin, a, &junk), UA_STATUSCODE_BADINVALIDARGUMENT);
    UA_ByteString empty = UA_BYTESTRING_NULL;
    CHECK_EQ_INT(revoke_cert(s, &admin, a, &empty), UA_STATUSCODE_BADINVALIDARGUMENT);
    UA_Variant one;
    UA_Variant_setScalar(&one, (void *)(uintptr_t)a, &UA_TYPES[UA_TYPES_NODEID]);
    CHECK_EQ_INT(call_status(s, &admin, UA_GDSID_DIRECTORY_REVOKECERTIFICATE, &one, 1),
                 UA_STATUSCODE_BADARGUMENTSMISSING);
    CHECK(!on_crl(ca, &certA, &after) && after == before);

    CHECK_EQ_INT(revoke_cert(s, &admin, a, &certA), UA_STATUSCODE_GOOD);
    CHECK(on_crl(ca, &certA, &after) && after == before + 1);
    CHECK(update_required(s, a)); /* its only certificate is revoked */
    CHECK_EQ_INT(revoke_cert(s, &admin, a, &certA), UA_STATUSCODE_GOOD); /* again: no change */
    CHECK(on_crl(ca, &certA, &after) && after == before + 1);

    /* a STANDBY changes nothing */
    CHECK(gds_server_set_role(s, GDS_NODE_STANDBY, 100, 0) == GDS_OK);
    CHECK_EQ_INT(revoke_cert(s, &admin, a, &certA), UA_STATUSCODE_BADINVALIDSTATE);
    CHECK(gds_server_set_role(s, GDS_NODE_STANDALONE, 255, 0) == GDS_OK);
    UA_ByteString_clear(&certA);
}

/* CheckRevocationStatus (§7.9.11): status and ValidityTime */
static UA_StatusCode check(gds_server *s, const UA_ByteString *cert, UA_DateTime *validity) {
    UA_Variant in;
    UA_Variant_setScalar(&in, (void *)(uintptr_t)cert, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_CallMethodResult res = call_as(s, &registrar, UA_GDSID_DIRECTORY_CHECKREVOCATIONSTATUS,
                                      &in, 1);
    UA_StatusCode st = UA_STATUSCODE_BADINTERNALERROR;
    if(CHECK(res.statusCode == UA_STATUSCODE_GOOD) && CHECK(res.outputArgumentsSize == 2) &&
       CHECK(UA_Variant_hasScalarType(&res.outputArguments[0], &UA_TYPES[UA_TYPES_STATUSCODE])) &&
       CHECK(UA_Variant_hasScalarType(&res.outputArguments[1], &UA_TYPES[UA_TYPES_DATETIME]))) {
        st = *(UA_StatusCode *)res.outputArguments[0].data;
        *validity = *(UA_DateTime *)res.outputArguments[1].data;
    }
    UA_CallMethodResult_clear(&res);
    return st;
}

/* GetCertificates (§7.9.8): the number of certificates, or -1 on refusal */
static int get_certs(gds_server *s, gds_session *as, const UA_NodeId *app,
                     const UA_ByteString *want, UA_StatusCode *code) {
    UA_NodeId nullGroup = UA_NODEID_NULL;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)app, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &nullGroup, &UA_TYPES[UA_TYPES_NODEID]);
    UA_CallMethodResult res = call_as(s, as, UA_GDSID_DIRECTORY_GETCERTIFICATES, in, 2);
    *code = res.statusCode;
    int n = -1;
    if(res.statusCode == UA_STATUSCODE_GOOD && CHECK(res.outputArgumentsSize == 2)) {
        n = (int)res.outputArguments[1].arrayLength;
        CHECK_EQ_INT(res.outputArguments[0].arrayLength, (size_t)n);
        if(n == 1) {
            UA_NodeId rsa = UA_NS0ID(RSASHA256APPLICATIONCERTIFICATETYPE);
            CHECK(UA_NodeId_equal(res.outputArguments[0].data, &rsa));
            CHECK(UA_ByteString_equal(res.outputArguments[1].data, want));
        }
    }
    UA_CallMethodResult_clear(&res);
    return n;
}

static void test_get_and_check(gds_server *s, const UA_NodeId *app, const UA_ByteString *own) {
    UA_ByteString cert = UA_BYTESTRING_NULL;
    if(!issue(s, app, &cert))
        return;
    UA_StatusCode code = UA_STATUSCODE_GOOD;
    CHECK_EQ_INT(get_certs(s, &admin, app, &cert, &code), 1);
    CHECK_EQ_INT(get_certs(s, &registrar, app, &cert, &code), -1); /* neither CA admin nor it */
    CHECK_EQ_INT(code, UA_STATUSCODE_BADUSERACCESSDENIED);

    UA_DateTime v = 0;
    CHECK_EQ_INT(check(s, &cert, &v), UA_STATUSCODE_GOOD);
    CHECK(v > UA_DateTime_now()); /* the CRL's nextUpdate */
    v = 1;
    CHECK_EQ_INT(check(s, own, &v), UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN); /* not ours */
    CHECK_EQ_INT(v, 0);
    UA_ByteString junk = UA_BYTESTRING("not a certificate");
    CHECK_EQ_INT(check(s, &junk, &v), UA_STATUSCODE_BADCERTIFICATEINVALID);
    UA_ByteString broken;
    if(CHECK(UA_ByteString_copy(&cert, &broken) == UA_STATUSCODE_GOOD)) {
        broken.data[broken.length - 8] ^= 0x5a; /* in the signature */
        CHECK_EQ_INT(check(s, &broken, &v), UA_STATUSCODE_BADCERTIFICATEINVALID);
        UA_ByteString_clear(&broken);
    }
    CHECK_EQ_INT(revoke_cert(s, &admin, app, &cert), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(check(s, &cert, &v), UA_STATUSCODE_BADCERTIFICATEREVOKED);
    CHECK_EQ_INT(get_certs(s, &admin, app, &cert, &code), 0); /* only valid ones */
    UA_ByteString_clear(&cert);
}

/* One certificate per curve: each from its own CA, checked and revoked
 * against that CA's CRL only; unregistering revokes on every curve. */
/* open62541 loads the ECC CRLs, which are below 256 bytes when empty
 * (docs/upstream/09-short-der-crl.md, patch 0007). */
static void check_crls_load(gds_ca *ca) {
    for(unsigned i = GDS_CA_ISSUER_P256; i < GDS_CA_ISSUERS; i++) {
        gds_buf der = {0};
        if(!CHECK(gds_ca_get_issuer_crl(ca, (gds_ca_issuer)i, &der) == GDS_OK)) // NOLINT(clang-analyzer-optin.core.EnumCastOutOfRange): i < GDS_CA_ISSUERS
            continue;
        CHECK(der.len < 256); /* empty: the short DER form 0x30 0x81 */
        UA_ByteString b = {der.len, der.data};
        UA_String name = UA_STRING_NULL;
        CHECK_EQ_INT(UA_CertificateUtils_getSubjectName(&b, &name), UA_STATUSCODE_GOOD);
        CHECK(name.length > 0);
        UA_String_clear(&name);
        gds_buf_free(&der);
    }
}

static void test_ecc(gds_server *s, gds_ca *ca, const UA_NodeId *app) {
    check_crls_load(ca);
    UA_ByteString p256 = UA_BYTESTRING_NULL, p384 = UA_BYTESTRING_NULL;
    if(!issue_type(s, app, UA_NS0ID_ECCNISTP256APPLICATIONCERTIFICATETYPE, &p256) ||
       !issue_type(s, app, UA_NS0ID_ECCNISTP384APPLICATIONCERTIFICATETYPE, &p384)) {
        UA_ByteString_clear(&p256);
        return;
    }
    UA_DateTime v = 0;
    CHECK_EQ_INT(check(s, &p256, &v), UA_STATUSCODE_GOOD);
    CHECK_EQ_INT(check(s, &p384, &v), UA_STATUSCODE_GOOD);
    /* the CA directory outlives a run: count entries, not absolutes */
    int rsaBefore = 0, rsaAfter = 0, n256 = 0, n384 = 0, n = 0;
    CHECK(!on_crl(ca, &p256, &rsaBefore));
    CHECK(!on_issuer_crl(ca, GDS_CA_ISSUER_P256, &p256, &n256));
    CHECK(!on_issuer_crl(ca, GDS_CA_ISSUER_P384, &p384, &n384));
    CHECK_EQ_INT(revoke_cert(s, &admin, app, &p256), UA_STATUSCODE_GOOD);
    CHECK(on_issuer_crl(ca, GDS_CA_ISSUER_P256, &p256, &n) && n == n256 + 1);
    CHECK(!on_crl(ca, &p256, &rsaAfter) && rsaAfter == rsaBefore);
    CHECK(!on_issuer_crl(ca, GDS_CA_ISSUER_P384, &p256, NULL));
    CHECK_EQ_INT(check(s, &p256, &v), UA_STATUSCODE_BADCERTIFICATEREVOKED);
    CHECK_EQ_INT(check(s, &p384, &v), UA_STATUSCODE_GOOD);
    UA_Variant in;
    UA_Variant_setScalar(&in, (void *)(uintptr_t)app, &UA_TYPES[UA_TYPES_NODEID]);
    CHECK_EQ_INT(call_status(s, &admin, UA_GDSID_DIRECTORY_UNREGISTERAPPLICATION, &in, 1),
                 UA_STATUSCODE_GOOD);
    CHECK(on_issuer_crl(ca, GDS_CA_ISSUER_P384, &p384, &n) && n == n384 + 1);
    CHECK(on_issuer_crl(ca, GDS_CA_ISSUER_P256, &p256, &n) && n == n256 + 1); /* not twice */
    CHECK(!on_crl(ca, &p384, &rsaAfter) && rsaAfter == rsaBefore);
    UA_ByteString_clear(&p256);
    UA_ByteString_clear(&p384);
}

/* ---- the Part 12 audit events of the methods ---- */

typedef struct {
    int64_t rows;
    bool secret; /* the needle was found in a body */
    const char *needle;
} audit_scan;

static bool scan_cb(void *ctx, const gds_audit_row *row) {
    audit_scan *c = ctx;
    c->rows++;
    size_t n = c->needle ? strlen(c->needle) : 0;
    for(size_t i = 0; n && i + n <= row->body.len && !c->secret; i++)
        c->secret = memcmp(row->body.data + i, c->needle, n) == 0;
    return true;
}

static audit_scan audit_log(gds_server *s, const char *needle) {
    audit_scan c = {0, false, needle};
    gds_lock(s);
    CHECK(gds_store_audit_scan(s->store, 0, scan_cb, &c) == GDS_OK);
    gds_unlock(s);
    return c;
}

#define KEY_PASSWORD "audit-must-never-see-this-password"

/* One record per allowed call, success or failure; none for a refused
 * session; never the key password. Server.Auditing reads TRUE. */
static void test_method_audit(gds_server *s, const UA_NodeId *app) {
    UA_Variant v;
    UA_Variant_init(&v);
    if(CHECK(UA_Server_readValue(gds_server_ua(s), UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_AUDITING),
                                 &v) == UA_STATUSCODE_GOOD) &&
       CHECK(UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_BOOLEAN])))
        CHECK(*(UA_Boolean *)v.data);
    UA_Variant_clear(&v);

    int64_t n0 = audit_log(s, NULL).rows;
    UA_NodeId other = UA_NODEID_NULL;
    if(CHECK(register_app(s, TEST_URI ":audit", &other))) /* ApplicationRegistrationChanged */
        CHECK_EQ_INT(audit_log(s, NULL).rows, n0 + 1);
    UA_ByteString junk = UA_BYTESTRING("not a certificate");
    CHECK_EQ_INT(revoke_cert(s, &registrar, app, &junk), UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK_EQ_INT(audit_log(s, NULL).rows, n0 + 1); /* refused session: no record */
    CHECK_EQ_INT(revoke_cert(s, &admin, app, &junk), UA_STATUSCODE_BADINVALIDARGUMENT);
    CHECK_EQ_INT(audit_log(s, NULL).rows, n0 + 2); /* CertificateRevoked, Status FALSE */

    /* StartNewKeyPairRequest: CertificateRequested without the password */
    UA_NodeId group = UA_NODEID_NULL, type = UA_NODEID_NULL;
    UA_String subject = UA_STRING_NULL, fmt = UA_STRING("PEM"), pw = UA_STRING(KEY_PASSWORD);
    UA_Variant in[7];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)app, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &type, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[3], &subject, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setArray(&in[4], NULL, 0, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[5], &fmt, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[6], &pw, &UA_TYPES[UA_TYPES_STRING]);
    CHECK_EQ_INT(call_status(s, &admin, UA_GDSID_DIRECTORY_STARTNEWKEYPAIRREQUEST, in, 7),
                 UA_STATUSCODE_GOOD);
    audit_scan after = audit_log(s, KEY_PASSWORD);
    CHECK_EQ_INT(after.rows, n0 + 3);
    CHECK(!after.secret);
    UA_NodeId_clear(&other);
}

/* gds_server_export_ca_keys: only through a signer, which picks the
 * recipients; this server's CA is in process. */
static void test_export_in_process(gds_server *s) {
    UA_ByteString out = UA_BYTESTRING_NULL;
    CHECK_EQ_INT(gds_server_export_ca_keys(NULL, &out), GDS_EINVAL);
    CHECK_EQ_INT(gds_server_export_ca_keys(s, NULL), GDS_EINVAL);
    CHECK_EQ_INT(gds_server_export_ca_keys(s, &out), GDS_EUNSUPPORTED);
    CHECK(out.data == NULL && out.length == 0);
}

/* A23: the store marks the serial revoked, then gds_server_revoke_serial
 * puts it on the issuing CA's CRL: by the certificate's issuer, by the
 * certificate type, or, with neither, on every issuer's CRL. */
static UA_ByteString store_revoke(gds_server *s, const UA_NodeId *app, const UA_ByteString *cert) {
    gds_buf der = {cert->data, cert->length}, serial = {0};
    CHECK(gds_store_cert_revoke(s->store, &app->identifier.guid, &der, &serial) == GDS_OK);
    UA_ByteString r = {serial.len, serial.data};
    return r;
}

static void test_revoke_serial(gds_server *s, gds_ca *ca, const UA_NodeId *app) {
    UA_ByteString rsa = UA_BYTESTRING_NULL, p256 = UA_BYTESTRING_NULL, p384 = UA_BYTESTRING_NULL;
    if(!issue(s, app, &rsa) ||
       !issue_type(s, app, UA_NS0ID_ECCNISTP256APPLICATIONCERTIFICATETYPE, &p256) ||
       !issue_type(s, app, UA_NS0ID_ECCNISTP384APPLICATIONCERTIFICATETYPE, &p384)) {
        UA_ByteString_clear(&rsa);
        UA_ByteString_clear(&p256);
        return;
    }
    int nr = 0, n2 = 0, n3 = 0, n = 0;
    CHECK(!on_crl(ca, &rsa, &nr));
    CHECK(!on_issuer_crl(ca, GDS_CA_ISSUER_P256, &p256, &n2));
    CHECK(!on_issuer_crl(ca, GDS_CA_ISSUER_P384, &p384, &n3));

    UA_ByteString empty = UA_BYTESTRING_NULL;
    UA_NodeId notType = UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATATYPE);
    UA_NodeId t256 = UA_NODEID_NUMERIC(0, UA_NS0ID_ECCNISTP256APPLICATIONCERTIFICATETYPE);
    UA_ByteString srsa = store_revoke(s, app, &rsa);
    CHECK_EQ_INT(gds_server_revoke_serial(NULL, &srsa, NULL, NULL), GDS_EINVAL);
    CHECK_EQ_INT(gds_server_revoke_serial(s, &empty, NULL, NULL), GDS_EINVAL);
    CHECK_EQ_INT(gds_server_revoke_serial(s, &srsa, NULL, &notType), GDS_EINVAL);
    CHECK(gds_server_set_role(s, GDS_NODE_STANDBY, 100, 0) == GDS_OK);
    CHECK_EQ_INT(gds_server_revoke_serial(s, &srsa, &rsa, NULL), GDS_ESTATE);
    CHECK(gds_server_set_role(s, GDS_NODE_STANDALONE, 255, 0) == GDS_OK);
    CHECK(!on_crl(ca, &rsa, NULL));

    /* Neither certificate nor type: on every issuer's CRL, once. */
    CHECK_EQ_INT(gds_server_revoke_serial(s, &srsa, NULL, NULL), GDS_OK);
    CHECK_EQ_INT(gds_server_revoke_serial(s, &srsa, NULL, NULL), GDS_OK);
    CHECK(on_crl(ca, &rsa, &n) && n == nr + 1);
    CHECK(!on_issuer_crl(ca, GDS_CA_ISSUER_P256, &p256, &n) && n == n2 + 1);
    CHECK(!on_issuer_crl(ca, GDS_CA_ISSUER_P384, &p384, &n) && n == n3 + 1);

    /* By type: only that curve's CRL. */
    UA_ByteString s256 = store_revoke(s, app, &p256);
    CHECK_EQ_INT(gds_server_revoke_serial(s, &s256, NULL, &t256), GDS_OK);
    CHECK(on_issuer_crl(ca, GDS_CA_ISSUER_P256, &p256, &n) && n == n2 + 2);
    CHECK(!on_crl(ca, &p256, &n) && n == nr + 1);
    CHECK(!on_issuer_crl(ca, GDS_CA_ISSUER_P384, &p256, &n) && n == n3 + 1);

    /* By the certificate's issuer name. */
    UA_ByteString s384 = store_revoke(s, app, &p384);
    CHECK_EQ_INT(gds_server_revoke_serial(s, &s384, &p384, NULL), GDS_OK);
    CHECK(on_issuer_crl(ca, GDS_CA_ISSUER_P384, &p384, &n) && n == n3 + 2);
    CHECK(!on_crl(ca, &p384, &n) && n == nr + 1);

    UA_ByteString_clear(&srsa);
    UA_ByteString_clear(&s256);
    UA_ByteString_clear(&s384);
    UA_ByteString_clear(&rsa);
    UA_ByteString_clear(&p256);
    UA_ByteString_clear(&p384);
}

static void test_unregister(gds_server *s, gds_ca *ca, const UA_NodeId *b) {
    UA_ByteString c1 = UA_BYTESTRING_NULL, c2 = UA_BYTESTRING_NULL;
    if(!issue(s, b, &c1) || !issue(s, b, &c2)) {
        UA_ByteString_clear(&c1);
        return;
    }
    int before = 0, after = 0;
    CHECK(!on_crl(ca, &c1, &before) && !on_crl(ca, &c2, NULL));
    UA_Variant in;
    UA_Variant_setScalar(&in, (void *)(uintptr_t)b, &UA_TYPES[UA_TYPES_NODEID]);
    CHECK_EQ_INT(call_status(s, &admin, UA_GDSID_DIRECTORY_UNREGISTERAPPLICATION, &in, 1),
                 UA_STATUSCODE_GOOD);
    CHECK(on_crl(ca, &c1, &after) && on_crl(ca, &c2, NULL) && after == before + 2);
    CHECK_EQ_INT(call_status(s, &admin, UA_GDSID_DIRECTORY_UNREGISTERAPPLICATION, &in, 1),
                 UA_STATUSCODE_BADNOTFOUND);
    CHECK_EQ_INT(revoke_cert(s, &admin, b, &c1), UA_STATUSCODE_BADNOTFOUND);
    UA_ByteString_clear(&c1);
    UA_ByteString_clear(&c2);
}

/* Remove the CA of an earlier run: each issuer's directory holds these. */
static void fresh_ca(const char *caDir) {
    static const char *const sub[] = {"", "/nistP256", "/nistP384"};
    static const char *const file[] = {"ca.der", "ca.crl", "ca.key.pem"};
    for(size_t i = GDS_ARRAY_SIZE(sub); i-- > 0;) {
        char path[1100];
        for(size_t j = 0; j < GDS_ARRAY_SIZE(file); j++)
            if(gds_path(path, sizeof(path), "%s%s/%s", caDir, sub[i], file[j]) == GDS_OK)
                (void)unlink(path);
        if(i > 0 && gds_path(path, sizeof(path), "%s%s", caDir, sub[i]) == GDS_OK)
            (void)rmdir(path);
    }
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
    fresh_ca(caDir); /* empty CRLs for check_crls_load */

    static uint8_t pw[] = "revoke-test-passphrase";
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
    memcpy(admin.user, "caadmin", sizeof("caadmin"));
    registrar.roles = GDS_ROLE_DISCOVERY_ADMIN | GDS_ROLE_REGISTRATION_AUTHORITY_ADMIN;
    registrar.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    memcpy(registrar.user, "registrar", sizeof("registrar"));

    static gds_users users;
    gds_server_config cfg = {0};
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS revoke test";
    cfg.ownCert = (gds_buf){cert.data, cert.length};
    cfg.ownKey = (gds_buf){key.data, key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_ALL;

    gds_server *s = NULL;
    if(CHECK(gds_server_new(&cfg, &s) == GDS_OK) && s) {
        UA_Server_setAdminSessionContext(gds_server_ua(s), &admin);
        UA_NodeId a = UA_NODEID_NULL, b = UA_NODEID_NULL, c = UA_NODEID_NULL,
                  d = UA_NODEID_NULL, e = UA_NODEID_NULL;
        if(register_app(s, TEST_URI ":a", &a) && register_app(s, TEST_URI ":b", &b) &&
           register_app(s, TEST_URI ":c", &c) && register_app(s, TEST_URI ":d", &d) &&
           register_app(s, TEST_URI ":e", &e)) {
            test_revoke(s, ca, &a, &b);
            test_get_and_check(s, &c, &cert);
            test_unregister(s, ca, &b);
            test_ecc(s, ca, &d);
            test_method_audit(s, &c);
            test_revoke_serial(s, ca, &e);
            test_export_in_process(s);
        }
        UA_NodeId_clear(&e);
        UA_NodeId_clear(&d);
        UA_NodeId_clear(&c);
        UA_NodeId_clear(&a);
        UA_NodeId_clear(&b);
        UA_Server_setAdminSessionContext(gds_server_ua(s), NULL);
    }
    gds_server_delete(s);
    gds_store_close(st);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    gds_ca_close(ca);
    return CHECK_DONE();
}
