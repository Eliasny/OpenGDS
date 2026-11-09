/* OpenGDS unit test: writing the DefaultApplicationGroup TrustList (OPC
 * 10000-12 §7.8.2.1-§7.8.2.7, OPC 10000-20 §4.2.2).
 *
 * Open allows Read and Write+EraseExisting only; writing needs
 * CertificateAuthorityAdmin over an authenticated channel. One writer and
 * no reader at a time. Close discards what was written; CloseAndUpdate
 * validates and applies it (partial updates keep the other lists) and moves
 * LastUpdateTime. The certificate and CRL of every GDS issuing CA (RSA,
 * P-256, P-384) always stay.
 * AddCertificate takes trusted, non-CA certificates whose issuer is in the
 * list; RemoveCertificate refuses unknown thumbprints and CAs still needed.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdio.h>
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

#define TEST_URI "urn:opengds:test:tlwrite"
#define TL(m) UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_##m

static gds_session admin, observer, plain;

/* ---- certificates ---- */

typedef struct {
    EVP_PKEY *key;
    X509 *x;
    UA_ByteString der;
} tcert;

static void tcert_clear(tcert *c) {
    EVP_PKEY_free(c->key);
    X509_free(c->x);
    UA_ByteString_clear(&c->der);
    memset(c, 0, sizeof(*c));
}

static bool add_ext(X509 *x, X509 *issuer, int nid, const char *value) {
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer, x, NULL, NULL, 0);
    X509_EXTENSION *e = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    bool ok = e && X509_add_ext(x, e, -1) == 1;
    X509_EXTENSION_free(e);
    return ok;
}

/* Signed by issuer (self-signed when NULL), valid from fromDays to toDays
 * from now. */
static bool make(tcert *c, const tcert *issuer, const char *cn, bool ca, long fromDays,
                 long toDays) {
    static long serial = 1000;
    memset(c, 0, sizeof(*c));
    c->key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    c->x = X509_new();
    X509_NAME *name = X509_NAME_new();
    bool ok = c->key && c->x && name && X509_set_version(c->x, 2) == 1 &&
              ASN1_INTEGER_set(X509_get_serialNumber(c->x), serial++) == 1 &&
              X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1,
                                         -1, 0) == 1 &&
              X509_set_subject_name(c->x, name) == 1 &&
              X509_set_issuer_name(c->x, issuer ? X509_get_subject_name(issuer->x) : name) == 1 &&
              X509_gmtime_adj(X509_getm_notBefore(c->x), fromDays * 86400) &&
              X509_gmtime_adj(X509_getm_notAfter(c->x), toDays * 86400) &&
              X509_set_pubkey(c->x, c->key) == 1 &&
              add_ext(c->x, issuer ? issuer->x : c->x, NID_basic_constraints,
                      ca ? "critical,CA:TRUE" : "critical,CA:FALSE") &&
              X509_sign(c->x, issuer ? issuer->key : c->key, EVP_sha256()) > 0;
    X509_NAME_free(name);
    int len = ok ? i2d_X509(c->x, NULL) : -1;
    if(len > 0 && UA_ByteString_allocBuffer(&c->der, (size_t)len) == UA_STATUSCODE_GOOD) {
        unsigned char *p = c->der.data;
        ok = i2d_X509(c->x, &p) == len;
    } else {
        ok = false;
    }
    return ok;
}

/* An empty CRL of ca */
static bool make_crl(const tcert *ca, UA_ByteString *out) {
    X509_CRL *crl = X509_CRL_new();
    ASN1_TIME *now = ASN1_TIME_set(NULL, time(NULL));
    bool ok = crl && now && X509_CRL_set_version(crl, 1) == 1 &&
              X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca->x)) == 1 &&
              X509_CRL_set1_lastUpdate(crl, now) == 1 &&
              X509_CRL_sign(crl, ca->key, EVP_sha256()) > 0;
    int len = ok ? i2d_X509_CRL(crl, NULL) : -1;
    ok = len > 0 && UA_ByteString_allocBuffer(out, (size_t)len) == UA_STATUSCODE_GOOD;
    if(ok) {
        unsigned char *p = out->data;
        ok = i2d_X509_CRL(crl, &p) == len;
    }
    ASN1_TIME_free(now);
    X509_CRL_free(crl);
    return ok;
}

static void thumbprint(const UA_ByteString *der, char out[41]) {
    unsigned char md[20];
    unsigned int n = 0;
    EVP_Digest(der->data, der->length, md, &n, EVP_sha1(), NULL);
    for(unsigned i = 0; i < 20; i++)
        snprintf(out + (size_t)2 * i, 3, "%02X", md[i]);
}

/* ---- calls ---- */

static UA_CallMethodResult call(gds_server *s, gds_session *as, UA_UInt32 method, UA_Variant *in,
                                size_t n) {
    UA_Server_setAdminSessionContext(gds_server_ua(s), as);
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = UA_NODEID_NUMERIC(s->ns,
                                                UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST);
    req.methodId = UA_NODEID_NUMERIC(s->ns, method);
    req.inputArguments = in;
    req.inputArgumentsSize = n;
    UA_CallMethodResult res = UA_Server_call(gds_server_ua(s), &req);
    UA_Server_setAdminSessionContext(gds_server_ua(s), &admin);
    return res;
}

static UA_StatusCode status_of(UA_CallMethodResult res) {
    UA_StatusCode r = res.statusCode;
    UA_CallMethodResult_clear(&res);
    return r;
}

static UA_StatusCode open_mode(gds_server *s, gds_session *as, UA_Byte mode, UA_UInt32 *h) {
    UA_Variant in;
    UA_Variant_setScalar(&in, &mode, &UA_TYPES[UA_TYPES_BYTE]);
    UA_CallMethodResult res = call(s, as, TL(OPEN), &in, 1);
    if(res.statusCode == UA_STATUSCODE_GOOD && res.outputArgumentsSize == 1 &&
       UA_Variant_hasScalarType(&res.outputArguments[0], &UA_TYPES[UA_TYPES_UINT32]))
        *h = *(UA_UInt32 *)res.outputArguments[0].data;
    return status_of(res);
}

static UA_StatusCode with_handle(gds_server *s, UA_UInt32 method, UA_UInt32 h) {
    UA_Variant in;
    UA_Variant_setScalar(&in, &h, &UA_TYPES[UA_TYPES_UINT32]);
    return status_of(call(s, &admin, method, &in, 1));
}

static UA_StatusCode write_data(gds_server *s, UA_UInt32 h, const UA_ByteString *data) {
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &h, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[1], (void *)(uintptr_t)data, &UA_TYPES[UA_TYPES_BYTESTRING]);
    return status_of(call(s, &admin, TL(WRITE), in, 2));
}

/* Open(Write+EraseExisting), Write in two pieces, then CloseAndUpdate (or Close) */
static UA_StatusCode write_list(gds_server *s, const UA_TrustListDataType *tl, bool update) {
    UA_ByteString enc = UA_BYTESTRING_NULL;
    UA_StatusCode r = UA_encodeBinary(tl, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], &enc, NULL);
    UA_UInt32 h = 0;
    if(r == UA_STATUSCODE_GOOD)
        r = open_mode(s, &admin, 0x06, &h);
    if(r != UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(&enc);
        return r;
    }
    size_t half = enc.length / 2;
    UA_ByteString a = {half, enc.data}, b = {enc.length - half, enc.data + half};
    r = write_data(s, h, &a);
    if(r == UA_STATUSCODE_GOOD)
        r = write_data(s, h, &b);
    UA_ByteString_clear(&enc);
    if(r != UA_STATUSCODE_GOOD || !update) {
        CHECK(with_handle(s, TL(CLOSE), h) == UA_STATUSCODE_GOOD);
        return r;
    }
    UA_Variant in;
    UA_Variant_setScalar(&in, &h, &UA_TYPES[UA_TYPES_UINT32]);
    UA_CallMethodResult res = call(s, &admin, TL(CLOSEANDUPDATE), &in, 1);
    if(res.statusCode == UA_STATUSCODE_GOOD)
        CHECK(res.outputArgumentsSize == 1 &&
              UA_Variant_hasScalarType(&res.outputArguments[0], &UA_TYPES[UA_TYPES_BOOLEAN]) &&
              *(UA_Boolean *)res.outputArguments[0].data == false);
    return status_of(res);
}

static UA_StatusCode add(gds_server *s, gds_session *as, const UA_ByteString *der, bool trusted) {
    UA_Variant in[2];
    UA_Boolean t = trusted;
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)der, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&in[1], &t, &UA_TYPES[UA_TYPES_BOOLEAN]);
    return status_of(call(s, as, TL(ADDCERTIFICATE), in, 2));
}

static UA_StatusCode remove_tp(gds_server *s, const char *tp, bool trusted) {
    UA_Variant in[2];
    UA_String str = UA_STRING((char *)(uintptr_t)tp);
    UA_Boolean t = trusted;
    UA_Variant_setScalar(&in[0], &str, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &t, &UA_TYPES[UA_TYPES_BOOLEAN]);
    return status_of(call(s, &admin, TL(REMOVECERTIFICATE), in, 2));
}

static UA_DateTime last_update(gds_server *s) {
    UA_Variant v;
    UA_DateTime t = -1;
    if(UA_Server_readValue(gds_server_ua(s), UA_NODEID_NUMERIC(s->ns, TL(LASTUPDATETIME)), &v) ==
       UA_STATUSCODE_GOOD) {
        if(UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_DATETIME]) ||
           UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_UTCTIME])) /* the node's type */
            t = *(UA_DateTime *)v.data;
        UA_Variant_clear(&v);
    }
    return t;
}

static bool has(const UA_ByteString *list, size_t n, const UA_ByteString *der) {
    for(size_t i = 0; i < n; i++)
        if(UA_ByteString_equal(&list[i], der))
            return true;
    return false;
}

/* ---- tests ---- */

static void test_open_rules(gds_server *s) {
    UA_UInt32 h = 0, h2 = 0;
    const UA_Byte bad[] = {0x02, 0x03, 0x04, 0x07};
    for(size_t i = 0; i < sizeof(bad); i++)
        CHECK(open_mode(s, &admin, bad[i], &h) == UA_STATUSCODE_BADNOTSUPPORTED);
    CHECK(open_mode(s, &observer, 0x06, &h) == UA_STATUSCODE_BADUSERACCESSDENIED);
    CHECK(open_mode(s, &plain, 0x06, &h) == UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT);
    /* a reader blocks writers (20 §4.2.2) */
    CHECK(open_mode(s, &admin, 0x01, &h) == UA_STATUSCODE_GOOD);
    CHECK(open_mode(s, &admin, 0x06, &h2) == UA_STATUSCODE_BADNOTWRITABLE);
    CHECK(with_handle(s, TL(CLOSE), h) == UA_STATUSCODE_GOOD);
    /* a writer blocks readers, writers, Add and Remove */
    CHECK(open_mode(s, &admin, 0x06, &h) == UA_STATUSCODE_GOOD);
    CHECK(open_mode(s, &observer, 0x01, &h2) == UA_STATUSCODE_BADNOTREADABLE);
    CHECK(open_mode(s, &admin, 0x06, &h2) == UA_STATUSCODE_BADNOTWRITABLE);
    UA_ByteString ca = {s->caCert.len, s->caCert.data};
    CHECK(add(s, &admin, &ca, true) == UA_STATUSCODE_BADINVALIDSTATE);
    CHECK(remove_tp(s, "0123456789ABCDEF0123456789ABCDEF01234567", true) ==
          UA_STATUSCODE_BADINVALIDSTATE);
    /* Read on a write handle; CloseAndUpdate on a read handle */
    UA_Variant in[2];
    UA_Int32 len = 100;
    UA_Variant_setScalar(&in[0], &h, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[1], &len, &UA_TYPES[UA_TYPES_INT32]);
    CHECK(status_of(call(s, &admin, TL(READ), in, 2)) == UA_STATUSCODE_BADINVALIDSTATE);
    CHECK(with_handle(s, TL(CLOSE), h) == UA_STATUSCODE_GOOD);
    CHECK(open_mode(s, &admin, 0x01, &h) == UA_STATUSCODE_GOOD);
    CHECK(with_handle(s, TL(CLOSEANDUPDATE), h) == UA_STATUSCODE_BADINVALIDSTATE);
    UA_ByteString junk = UA_BYTESTRING("x");
    CHECK(write_data(s, h, &junk) == UA_STATUSCODE_BADINVALIDSTATE);
    CHECK(with_handle(s, TL(CLOSE), h) == UA_STATUSCODE_GOOD);
    CHECK(with_handle(s, TL(CLOSE), h) == UA_STATUSCODE_BADINVALIDARGUMENT); /* closed */
}

/* The list's sizes: Trusted certificates, Trusted CRLs, Issuer
 * certificates, Issuer CRLs. tc and tl count one entry for the GDS: the
 * other issuing CAs (P-256, P-384) and their CRLs are added here. */
static bool sizes(gds_server *s, size_t tc, size_t tl, size_t ic, size_t il) {
    tc += GDS_CA_ISSUERS - 1;
    tl += GDS_CA_ISSUERS - 1;
    UA_TrustListDataType now;
    if(gds_trustlist_data(s, UA_TRUSTLISTMASKS_ALL, &now) != UA_STATUSCODE_GOOD)
        return false;
    bool ok = now.trustedCertificatesSize == tc && now.trustedCrlsSize == tl &&
              now.issuerCertificatesSize == ic && now.issuerCrlsSize == il;
    UA_TrustListDataType_clear(&now);
    return ok;
}

static bool holds(gds_server *s, const UA_ByteString *der) {
    UA_TrustListDataType now;
    if(gds_trustlist_data(s, UA_TRUSTLISTMASKS_ALL, &now) != UA_STATUSCODE_GOOD)
        return false;
    bool ok = has(now.trustedCertificates, now.trustedCertificatesSize, der);
    UA_TrustListDataType_clear(&now);
    return ok;
}

/* One list of one entry */
static UA_TrustListDataType one(UA_UInt32 mask, UA_ByteString *entry) {
    UA_TrustListDataType t;
    UA_TrustListDataType_init(&t);
    t.specifiedLists = mask;
    switch(mask) {
    case UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES:
        t.trustedCertificates = entry;
        t.trustedCertificatesSize = 1;
        break;
    case UA_TRUSTLISTMASKS_ISSUERCERTIFICATES:
        t.issuerCertificates = entry;
        t.issuerCertificatesSize = 1;
        break;
    default:
        t.issuerCrls = entry;
        t.issuerCrlsSize = 1;
        break;
    }
    return t;
}

/* Close discards, CloseAndUpdate applies, a partial update keeps the rest */
static void test_write_apply(gds_server *s, const tcert *app) {
    UA_DateTime lu0 = last_update(s);
    CHECK(lu0 == 0); /* never written: DateTime.MinValue */
    UA_TrustListDataType tl;
    CHECK(gds_trustlist_data(s, UA_TRUSTLISTMASKS_ALL, &tl) == UA_STATUSCODE_GOOD);
    CHECK(UA_Array_appendCopy((void **)&tl.trustedCertificates, &tl.trustedCertificatesSize,
                              &app->der, &UA_TYPES[UA_TYPES_BYTESTRING]) == UA_STATUSCODE_GOOD);
    tl.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    CHECK(write_list(s, &tl, false) == UA_STATUSCODE_GOOD);
    CHECK(sizes(s, 1, 1, 0, 0) && last_update(s) == lu0);
    /* the CA and its CRL written back are not doubled */
    CHECK(write_list(s, &tl, true) == UA_STATUSCODE_GOOD);
    UA_TrustListDataType_clear(&tl);
    CHECK(sizes(s, 2, 1, 0, 0) && holds(s, &app->der));
    UA_DateTime lu1 = last_update(s);
    CHECK(lu1 > lu0);
    UA_TrustListDataType part;
    UA_TrustListDataType_init(&part);
    part.specifiedLists = UA_TRUSTLISTMASKS_ISSUERCERTIFICATES;
    CHECK(write_list(s, &part, true) == UA_STATUSCODE_GOOD);
    CHECK(sizes(s, 2, 1, 0, 0));
    CHECK(last_update(s) > lu1);
    CHECK(gds_trustlist_data(s, UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES, &tl) ==
          UA_STATUSCODE_GOOD);
    CHECK(tl.trustedCertificatesSize == GDS_CA_ISSUERS + 1 && tl.trustedCrlsSize == 0 &&
          tl.specifiedLists == UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES);
    UA_TrustListDataType_clear(&tl);
}

/* Garbage, an expired certificate, a CRL of an unknown CA, a leaf as an
 * issuer: each discarded whole */
static void test_write_refused(gds_server *s, tcert *app) {
    UA_UInt32 h = 0;
    UA_ByteString junk = UA_BYTESTRING("not a trust list");
    if(CHECK(open_mode(s, &admin, 0x06, &h) == UA_STATUSCODE_GOOD)) {
        CHECK(write_data(s, h, &junk) == UA_STATUSCODE_GOOD);
        CHECK(with_handle(s, TL(CLOSEANDUPDATE), h) == UA_STATUSCODE_BADINVALIDARGUMENT);
    }
    tcert old = {0}, stranger = {0};
    UA_ByteString crl = UA_BYTESTRING_NULL;
    if(CHECK(make(&old, NULL, "tl expired", false, -30, -1)) &&
       CHECK(make(&stranger, NULL, "tl stranger CA", true, -1, 365)) &&
       CHECK(make_crl(&stranger, &crl))) {
        UA_TrustListDataType bad = one(UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES, &old.der);
        CHECK(write_list(s, &bad, true) == UA_STATUSCODE_BADCERTIFICATETIMEINVALID);
        bad = one(UA_TRUSTLISTMASKS_ISSUERCRLS, &crl);
        CHECK(write_list(s, &bad, true) == UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE);
        bad = one(UA_TRUSTLISTMASKS_ISSUERCERTIFICATES, &app->der);
        CHECK(write_list(s, &bad, true) == UA_STATUSCODE_BADCERTIFICATEINVALID);
    }
    CHECK(sizes(s, 2, 1, 0, 0));
    UA_TrustListDataType empty;
    UA_TrustListDataType_init(&empty);
    empty.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    CHECK(write_list(s, &empty, true) == UA_STATUSCODE_GOOD);
    CHECK(sizes(s, 1, 1, 0, 0)); /* the CA and its CRL stay */
    UA_ByteString_clear(&crl);
    tcert_clear(&old);
    tcert_clear(&stranger);
}

static void test_write(gds_server *s) {
    tcert app = {0};
    if(CHECK(make(&app, NULL, "tl app", false, -1, 365))) {
        test_write_apply(s, &app);
        test_write_refused(s, &app);
    }
    tcert_clear(&app);
}

static void test_add(gds_server *s, const tcert *app) {
    tcert orphanCa = {0}, orphan = {0}, ca = {0};
    if(CHECK(make(&orphanCa, NULL, "tl unknown CA", true, -1, 365)) &&
       CHECK(make(&orphan, &orphanCa, "tl orphan", false, -1, 365)) &&
       CHECK(make(&ca, NULL, "tl a CA", true, -1, 365))) {
        CHECK(add(s, &admin, &orphan.der, true) == UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE);
        CHECK(add(s, &admin, &ca.der, true) == UA_STATUSCODE_BADCERTIFICATEINVALID);
    }
    UA_DateTime lu0 = last_update(s);
    CHECK(add(s, &admin, &app->der, false) == UA_STATUSCODE_BADCERTIFICATEINVALID);
    CHECK(add(s, &observer, &app->der, true) == UA_STATUSCODE_BADUSERACCESSDENIED);
    UA_ByteString junk = UA_BYTESTRING("junk");
    CHECK(add(s, &admin, &junk, true) == UA_STATUSCODE_BADCERTIFICATEINVALID);
    CHECK(last_update(s) == lu0);
    CHECK(add(s, &admin, &app->der, true) == UA_STATUSCODE_GOOD);
    CHECK(last_update(s) > lu0);
    CHECK(add(s, &admin, &app->der, true) == UA_STATUSCODE_GOOD); /* not doubled */
    CHECK(sizes(s, 2, 1, 0, 0) && holds(s, &app->der));
    tcert_clear(&orphanCa);
    tcert_clear(&orphan);
    tcert_clear(&ca);
}

static void test_remove(gds_server *s, const tcert *app) {
    char tp[41], tpGds[41];
    thumbprint(&app->der, tp);
    UA_ByteString gdsCa = {s->caCert.len, s->caCert.data};
    thumbprint(&gdsCa, tpGds);
    CHECK(remove_tp(s, "0123456789ABCDEF0123456789ABCDEF01234567", true) ==
          UA_STATUSCODE_BADINVALIDARGUMENT);
    CHECK(remove_tp(s, "not hex", true) == UA_STATUSCODE_BADINVALIDARGUMENT);
    CHECK(remove_tp(s, tp, false) == UA_STATUSCODE_BADINVALIDARGUMENT); /* wrong list */
    CHECK(remove_tp(s, tpGds, true) == UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE);
    for(size_t i = 1; i < GDS_CA_ISSUERS; i++) { /* the ECC CAs stay as well */
        char tpEcc[41];
        UA_ByteString ecc = {s->issuerCert[i].len, s->issuerCert[i].data};
        if(!CHECK(ecc.length > 0))
            continue;
        thumbprint(&ecc, tpEcc);
        CHECK(remove_tp(s, tpEcc, true) == UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE);
    }
    UA_DateTime lu = last_update(s);
    for(char *c = tp; *c; c++) /* lower case works too */
        if(*c >= 'A' && *c <= 'F')
            *c = (char)(*c - 'A' + 'a');
    CHECK(remove_tp(s, tp, true) == UA_STATUSCODE_GOOD);
    CHECK(last_update(s) > lu);
    CHECK(sizes(s, 1, 1, 0, 0));
}

/* An issuer CA with its CRL, and a certificate it issued: the CA cannot go
 * first; once it goes, its CRL goes with it */
static void test_remove_ca(gds_server *s) {
    tcert ca = {0}, leaf = {0};
    UA_ByteString crl = UA_BYTESTRING_NULL;
    if(CHECK(make(&ca, NULL, "tl issuer CA", true, -1, 365)) &&
       CHECK(make(&leaf, &ca, "tl issued", false, -1, 365)) && CHECK(make_crl(&ca, &crl))) {
        char tpCa[41], tpLeaf[41];
        thumbprint(&ca.der, tpCa);
        thumbprint(&leaf.der, tpLeaf);
        UA_TrustListDataType w = one(UA_TRUSTLISTMASKS_ISSUERCERTIFICATES, &ca.der);
        w.specifiedLists |= UA_TRUSTLISTMASKS_ISSUERCRLS;
        w.issuerCrls = &crl;
        w.issuerCrlsSize = 1;
        CHECK(write_list(s, &w, true) == UA_STATUSCODE_GOOD);
        CHECK(add(s, &admin, &leaf.der, true) == UA_STATUSCODE_GOOD);
        CHECK(remove_tp(s, tpCa, false) == UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE);
        CHECK(remove_tp(s, tpLeaf, true) == UA_STATUSCODE_GOOD);
        CHECK(remove_tp(s, tpCa, false) == UA_STATUSCODE_GOOD);
        CHECK(sizes(s, 1, 1, 0, 0));
    }
    UA_ByteString_clear(&crl);
    tcert_clear(&ca);
    tcert_clear(&leaf);
}

static void test_add_remove(gds_server *s) {
    tcert app = {0};
    if(CHECK(make(&app, NULL, "tl add", false, -1, 365))) {
        test_add(s, &app);
        test_remove(s, &app);
        test_remove_ca(s);
    }
    tcert_clear(&app);
}

static gds_server *start(const char *db, gds_ca *ca, const UA_ByteString *cert,
                         const UA_ByteString *key, gds_store **st) {
    static gds_users users;
    if(!CHECK(gds_store_open(db, st) == GDS_OK))
        return NULL;
    gds_server_config cfg = {0};
    cfg.loopbackOnly = true;
    cfg.applicationUri = TEST_URI;
    cfg.productUri = "urn:opengds:test";
    cfg.applicationName = "OpenGDS trust list write test";
    cfg.ownCert = (gds_buf){cert->data, cert->length};
    cfg.ownKey = (gds_buf){key->data, key->length};
    cfg.store = *st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_ALL;
    gds_server *s = NULL;
    if(!CHECK(gds_server_new(&cfg, &s) == GDS_OK))
        return NULL;
    UA_Server_setAdminSessionContext(gds_server_ua(s), &admin);
    return s;
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

    static uint8_t pw[] = "tlwrite-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    UA_String subject[] = {UA_STRING_STATIC("CN=OpenGDS test")};
    UA_String san[] = {UA_STRING_STATIC("URI:" TEST_URI), UA_STRING_STATIC("DNS:localhost")};
    if(!CHECK(gds_ca_openssl_open(&cc, &ca) == GDS_OK) ||
       !CHECK(UA_CreateCertificate(UA_Log_Stdout, subject, 1, san, 2, UA_CERTIFICATEFORMAT_DER,
                                   NULL, &key, &cert) == UA_STATUSCODE_GOOD))
        return CHECK_DONE();

    admin.roles = GDS_ROLE_CERTIFICATE_AUTHORITY_ADMIN;
    admin.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    memcpy(admin.user, "caadmin", sizeof("caadmin"));
    observer.roles = GDS_ROLE_OBSERVER;
    observer.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    memcpy(observer.user, "observer", sizeof("observer"));
    plain.roles = GDS_ROLE_CERTIFICATE_AUTHORITY_ADMIN;
    plain.securityMode = UA_MESSAGESECURITYMODE_NONE;
    memcpy(plain.user, "plain", sizeof("plain"));

    gds_store *st = NULL;
    gds_server *s = start(db, ca, &cert, &key, &st);
    UA_DateTime lu = 0;
    tcert keep;
    bool made = CHECK(make(&keep, NULL, "tl kept", false, -1, 365));
    if(s) {
        test_open_rules(s);
        test_write(s);
        test_add_remove(s);
        if(made)
            CHECK(add(s, &admin, &keep.der, true) == UA_STATUSCODE_GOOD);
        lu = last_update(s);
        UA_Server_setAdminSessionContext(gds_server_ua(s), NULL);
        gds_server_delete(s);
    }
    gds_store_close(st);
    /* the written list and LastUpdateTime survive a restart */
    s = start(db, ca, &cert, &key, &st);
    if(s && made) {
        UA_TrustListDataType now;
        CHECK(gds_trustlist_data(s, UA_TRUSTLISTMASKS_ALL, &now) == UA_STATUSCODE_GOOD);
        CHECK(has(now.trustedCertificates, now.trustedCertificatesSize, &keep.der));
        UA_TrustListDataType_clear(&now);
        CHECK(last_update(s) == lu && lu > 0);
    }
    if(s) {
        UA_Server_setAdminSessionContext(gds_server_ua(s), NULL);
        gds_server_delete(s);
    }
    gds_store_close(st);
    tcert_clear(&keep);
    gds_ca_close(ca);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    return CHECK_DONE();
}
