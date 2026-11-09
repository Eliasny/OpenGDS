/* OpenGDS unit test: the CA slot and the built-in OpenSSL backend (src/ca).
 * Checks decision G5: everything in an issued certificate comes from the
 * record; the CSR's subject and SAN are ignored.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ca.h"
#include "check.h"
#include "common/buf.h"
#include "common/ids.h"
#include "common/banned.h"

#define APP_URI "urn:opengds:test:server"

/* Entries on a CRL (an empty CRL has no list at all). */
static int crl_count(X509_CRL *crl) {
    STACK_OF(X509_REVOKED) *l = X509_CRL_get_REVOKED(crl);
    return l ? sk_X509_REVOKED_num(l) : 0;
}

static UA_Guid reqId;

/* A CSR that tries to choose its own subject and ApplicationUri. */
static gds_status make_csr(EVP_PKEY *key, gds_buf *out) {
    X509_REQ *req = X509_REQ_new();
    X509_NAME *n = X509_NAME_new();
    GENERAL_NAMES *gens = sk_GENERAL_NAME_new_null();
    GENERAL_NAME *g = GENERAL_NAME_new();
    ASN1_IA5STRING *uri = ASN1_IA5STRING_new();
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
    gds_status r = GDS_ECRYPTO;
    if(!req || !n || !gens || !g || !uri || !exts)
        goto done;
    X509_NAME_add_entry_by_NID(n, NID_commonName, MBSTRING_UTF8, (const unsigned char *)"evil", -1,
                               -1, 0);
    ASN1_STRING_set(uri, "urn:evil:other", -1);
    GENERAL_NAME_set0_value(g, GEN_URI, uri);
    uri = NULL;
    sk_GENERAL_NAME_push(gens, g);
    g = NULL;
    X509_EXTENSION *ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, gens);
    sk_X509_EXTENSION_push(exts, ext);
    if(X509_REQ_set_subject_name(req, n) == 1 && X509_REQ_set_pubkey(req, key) == 1 &&
       X509_REQ_add_extensions(req, exts) == 1 && X509_REQ_sign(req, key, EVP_sha256()) > 0) {
        int len = i2d_X509_REQ(req, NULL);
        out->data = malloc((size_t)len);
        unsigned char *p = out->data;
        out->len = (size_t)len;
        r = (out->data && i2d_X509_REQ(req, &p) == len) ? GDS_OK : GDS_ECRYPTO;
    }
done:
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    GENERAL_NAMES_free(gens);
    GENERAL_NAME_free(g);
    ASN1_IA5STRING_free(uri);
    X509_NAME_free(n);
    X509_REQ_free(req);
    return r;
}

static void make_record(UA_ApplicationRecordDataType *rec, UA_LocalizedText *name,
                        UA_String urls[4]) {
    UA_ApplicationRecordDataType_init(rec);
    rec->applicationUri = UA_STRING(APP_URI);
    rec->applicationType = UA_APPLICATIONTYPE_SERVER;
    *name = UA_LOCALIZEDTEXT("en", "Unit Test Server");
    rec->applicationNames = name;
    rec->applicationNamesSize = 1;
    urls[0] = UA_STRING("opc.tcp://host1.example:4840/ua");
    urls[1] = UA_STRING("opc.tcp://HOST1.example:4841");
    urls[2] = UA_STRING("opc.tcp://192.0.2.7:4840");
    urls[3] = UA_STRING("opc.https://[2001:db8::1]:443/");
    rec->discoveryUrls = urls;
    rec->discoveryUrlsSize = 4;
}

static X509 *parse_cert(const gds_buf *der) {
    const unsigned char *p = der->data;
    return d2i_X509(NULL, &p, (long)der->len);
}

static int count_san(X509 *x, int type, const char *want) {
    GENERAL_NAMES *gens = X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
    int hits = 0;
    for(int i = 0; gens && i < sk_GENERAL_NAME_num(gens); i++) {
        GENERAL_NAME *g = sk_GENERAL_NAME_value(gens, i);
        if(g->type != type)
            continue;
        if(type == GEN_IPADD) {
            ASN1_OCTET_STRING *ip = a2i_IPADDRESS(want);
            hits += ip && ASN1_OCTET_STRING_cmp(ip, g->d.iPAddress) == 0;
            ASN1_OCTET_STRING_free(ip);
        } else {
            const ASN1_IA5STRING *s = g->d.ia5;
            hits += (size_t)s->length == strlen(want) && memcmp(s->data, want, strlen(want)) == 0;
        }
    }
    GENERAL_NAMES_free(gens);
    return hits;
}

static void check_subject(X509 *x) {
    char cn[128] = {0};
    X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_commonName, cn, sizeof(cn));
    CHECK(strcmp(cn, "Unit Test Server") == 0);
    char o[128] = {0};
    X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_organizationName, o, sizeof(o));
    CHECK(strcmp(o, "OpenGDS Test") == 0);
    CHECK_EQ_INT(count_san(x, GEN_URI, APP_URI), 1);
    CHECK_EQ_INT(count_san(x, GEN_URI, "urn:evil:other"), 0);
    CHECK_EQ_INT(count_san(x, GEN_DNS, "host1.example"), 1); /* deduplicated */
    CHECK_EQ_INT(count_san(x, GEN_IPADD, "192.0.2.7"), 1);
    CHECK_EQ_INT(count_san(x, GEN_IPADD, "2001:db8::1"), 1);
}

static void check_profile(X509 *x) {
    CHECK_EQ_INT(X509_get_version(x), X509_VERSION_3);
    CHECK(X509_check_ca(x) == 0);
    uint32_t ku = X509_get_key_usage(x);
    CHECK((ku & (KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION | KU_KEY_ENCIPHERMENT |
                 KU_DATA_ENCIPHERMENT)) == (KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION |
                                            KU_KEY_ENCIPHERMENT | KU_DATA_ENCIPHERMENT));
    CHECK((ku & (KU_KEY_CERT_SIGN | KU_CRL_SIGN)) == 0);
    uint32_t xku = X509_get_extended_key_usage(x);
    CHECK((xku & (XKU_SSL_SERVER | XKU_SSL_CLIENT)) == (XKU_SSL_SERVER | XKU_SSL_CLIENT));
    CHECK(X509_get0_subject_key_id(x) != NULL && X509_get0_authority_key_id(x) != NULL);
}

/* Verify leaf against the CA and its current CRL: the X509_V_ error, or
 * -1 if the CA's certificate or CRL could not be read. */
static int verify_with_crl(X509 *leaf, gds_ca *ca, long *crlNumber, int *entries) {
    gds_buf caDer = {0}, crlDer = {0};
    CHECK(gds_ca_get_ca_cert(ca, &caDer) == GDS_OK);
    CHECK(gds_ca_get_crl(ca, &crlDer) == GDS_OK);
    X509 *caCert = parse_cert(&caDer);
    const unsigned char *p = crlDer.data;
    X509_CRL *crl = d2i_X509_CRL(NULL, &p, (long)crlDer.len);
    X509_STORE *st = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    int err = -1;
    CHECK(caCert && crl && st && ctx);
    if(caCert && crl && st && ctx) {
        CHECK(X509_check_ca(caCert) == 1);
        CHECK(X509_CRL_verify(crl, X509_get0_pubkey(caCert)) == 1);
        if(crlNumber) {
            ASN1_INTEGER *n = X509_CRL_get_ext_d2i(crl, NID_crl_number, NULL, NULL);
            *crlNumber = n ? ASN1_INTEGER_get(n) : -1;
            ASN1_INTEGER_free(n);
        }
        if(entries)
            *entries = crl_count(crl);
        X509_STORE_add_cert(st, caCert);
        X509_STORE_add_crl(st, crl);
        X509_STORE_set_flags(st, X509_V_FLAG_CRL_CHECK);
        X509_STORE_CTX_init(ctx, st, leaf, NULL);
        err = X509_verify_cert(ctx) == 1 ? X509_V_OK : X509_STORE_CTX_get_error(ctx);
        CHECK(ASN1_TIME_compare(X509_get0_notAfter(leaf), X509_get0_notAfter(caCert)) <= 0);
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(st);
    X509_CRL_free(crl);
    X509_free(caCert);
    gds_buf_free(&caDer);
    gds_buf_free(&crlDer);
    return err;
}

/* The issued certificate chains to the CA and passes a CRL check. */
static void check_chain(X509 *leaf, gds_ca *ca) {
    int err = verify_with_crl(leaf, ca, NULL, NULL);
    if(err != X509_V_OK)
        fprintf(stderr, "verify: %s\n", err < 0 ? "no CA" : X509_verify_cert_error_string(err));
    CHECK(err == X509_V_OK);
}

static void test_issue(gds_ca *ca, const gds_ca_subject *subj, const gds_buf *csr) {
    gds_ca_issued out;
    CHECK(gds_ca_sign_csr(ca, subj, csr, &out) == GDS_OK);
    CHECK_EQ_INT(out.serial.len, 20);
    CHECK(out.notAfter > out.notBefore);
    X509 *x = parse_cert(&out.der);
    CHECK(x != NULL);
    if(x) {
        check_subject(x);
        check_profile(x);
        check_chain(x, ca);
    }
    X509_free(x);
    gds_ca_issued_clear(&out);
}

static void test_refusals(gds_ca *ca, const gds_ca_subject *subj, const gds_buf *csr) {
    gds_ca_issued out;
    /* tampered signature: no proof of possession */
    gds_buf bad = {0};
    CHECK(gds_buf_dup(csr->data, csr->len, &bad) == GDS_OK);
    bad.data[bad.len - 3] ^= 0x55u;
    CHECK(gds_ca_sign_csr(ca, subj, &bad, &out) == GDS_EINVAL);
    gds_buf_free(&bad);
    /* trailing bytes */
    CHECK(gds_buf_dup(csr->data, csr->len, &bad) == GDS_OK);
    CHECK(gds_buf_append(&bad, "x", 1, csr->len + 1) == GDS_OK);
    CHECK(gds_ca_sign_csr(ca, subj, &bad, &out) == GDS_EINVAL);
    gds_buf_free(&bad);
    /* not a CSR */
    uint8_t junk[] = {0x30, 0x03, 0x02, 0x01, 0x00};
    gds_buf j = {junk, sizeof(junk)};
    CHECK(gds_ca_sign_csr(ca, subj, &j, &out) == GDS_EINVAL);
    /* RsaMin is not issued */
    gds_ca_subject s2 = *subj;
    s2.certificateType = UA_NS0ID_RSAMINAPPLICATIONCERTIFICATETYPE;
    CHECK(gds_ca_sign_csr(ca, &s2, csr, &out) == GDS_EUNSUPPORTED);
    CHECK(out.der.data == NULL);
}

static void test_small_key(gds_ca *ca, const gds_ca_subject *subj) {
    EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)1024);
    gds_buf csr = {0};
    CHECK(k && make_csr(k, &csr) == GDS_OK);
    gds_ca_issued out;
    CHECK(gds_ca_sign_csr(ca, subj, &csr, &out) == GDS_EINVAL);
    gds_buf_free(&csr);
    EVP_PKEY_free(k);
}

/* A backend whose pre_sign refuses: sign_csr is never reached (issue #13). */
static int signCalls = 0;
static gds_status refuse_pre_sign(void *ctx, gds_ca_op op, const gds_ca_subject *s) {
    (void)ctx;
    CHECK(op == GDS_CA_OP_SIGN_CSR && s->requestId && UA_Guid_equal(s->requestId, &reqId));
    return GDS_ESTATE;
}
static gds_status count_sign(void *ctx, const gds_ca_subject *s, const gds_buf *c,
                             gds_ca_issued *o) {
    (void)ctx, (void)s, (void)c, (void)o;
    signCalls++;
    return GDS_OK;
}
static gds_status no_buf(void *ctx, gds_buf *out) {
    (void)ctx, (void)out;
    return GDS_ENOTFOUND;
}
static void no_destroy(void *ctx) {
    (void)ctx;
}

static void test_pre_sign(const gds_ca_subject *subj, const gds_buf *csr) {
    const gds_ca_backend b = {GDS_CA_ABI_VERSION, refuse_pre_sign, count_sign, no_buf, no_buf,
                              no_destroy, NULL, NULL, NULL, NULL, NULL};
    gds_ca *ca = NULL;
    CHECK(gds_ca_wrap(&b, NULL, &ca) == GDS_OK);
    gds_ca_issued out;
    CHECK(ca && gds_ca_sign_csr(ca, subj, csr, &out) == GDS_ESTATE);
    CHECK_EQ_INT(signCalls, 0);
    uint8_t one = 1;
    gds_buf serial = {&one, 1};
    CHECK(ca && gds_ca_revoke(ca, &serial) == GDS_EUNSUPPORTED); /* revoke is optional */
    gds_ca_close(ca);
    gds_ca_backend wrong = b;
    wrong.abiVersion = 99;
    CHECK(gds_ca_wrap(&wrong, NULL, &ca) == GDS_EINVAL && ca == NULL);
}

/* Revoke a, then b after a reopen: each serial goes on a new CRL
 * (number + 1), once, and stays on every later CRL. */
static void check_revoke(const gds_ca_config *cfg, gds_ca **ca, const gds_ca_issued *a,
                         const gds_ca_issued *b, X509 *xa, X509 *xb) {
    long n0 = 0, n1 = 0, n2 = 0;
    int entries = -1;
    CHECK(verify_with_crl(xa, *ca, &n0, &entries) == X509_V_OK && entries == 0);
    CHECK(gds_ca_revoke(*ca, &a->serial) == GDS_OK);
    CHECK(verify_with_crl(xa, *ca, &n1, &entries) == X509_V_ERR_CERT_REVOKED);
    CHECK(n1 == n0 + 1 && entries == 1);
    CHECK(verify_with_crl(xb, *ca, NULL, NULL) == X509_V_OK);
    CHECK(gds_ca_revoke(*ca, &a->serial) == GDS_OK); /* again: no new CRL */
    CHECK(verify_with_crl(xa, *ca, &n2, &entries) == X509_V_ERR_CERT_REVOKED);
    CHECK(n2 == n1 && entries == 1);
    gds_buf empty = {0};
    CHECK(gds_ca_revoke(*ca, &empty) == GDS_EINVAL);
    gds_ca_close(*ca);
    *ca = NULL;
    /* the CRL file keeps the entry; the next revocation adds to it */
    if(!CHECK(gds_ca_openssl_open(cfg, ca) == GDS_OK) || !*ca)
        return;
    CHECK(gds_ca_revoke(*ca, &b->serial) == GDS_OK);
    CHECK(verify_with_crl(xa, *ca, &n2, &entries) == X509_V_ERR_CERT_REVOKED);
    CHECK(verify_with_crl(xb, *ca, NULL, NULL) == X509_V_ERR_CERT_REVOKED);
    CHECK(n2 == n1 + 1 && entries == 2);
}

static void test_revoke(const gds_ca_config *cfg, const gds_ca_subject *subj,
                        const gds_buf *csr) {
    gds_ca *ca = NULL;
    if(!CHECK(gds_ca_openssl_open(cfg, &ca) == GDS_OK) || !ca)
        return;
    gds_ca_issued a, b;
    CHECK(gds_ca_sign_csr(ca, subj, csr, &a) == GDS_OK);
    CHECK(gds_ca_sign_csr(ca, subj, csr, &b) == GDS_OK);
    X509 *xa = parse_cert(&a.der), *xb = parse_cert(&b.der);
    if(CHECK(xa && xb))
        check_revoke(cfg, &ca, &a, &b, xa, xb);
    X509_free(xa);
    X509_free(xb);
    gds_ca_issued_clear(&a);
    gds_ca_issued_clear(&b);
    gds_ca_close(ca);
}

static void test_reopen(const gds_ca_config *cfg, const gds_buf *firstCa) {
    gds_ca *ca = NULL;
    CHECK(gds_ca_openssl_open(cfg, &ca) == GDS_OK);
    gds_buf again = {0};
    CHECK(ca && gds_ca_get_ca_cert(ca, &again) == GDS_OK);
    CHECK(again.data && firstCa->data && again.len == firstCa->len &&
          memcmp(again.data, firstCa->data, again.len) == 0);
    gds_buf_free(&again);
    gds_ca_close(ca);
    /* the key file is encrypted: a wrong passphrase cannot load it */
    gds_ca_config wrong = *cfg;
    uint8_t bad[] = "wrong";
    gds_buf badPass = {bad, sizeof(bad) - 1};
    wrong.keyPassphrase = &badPass;
    CHECK(gds_ca_openssl_open(&wrong, &ca) == GDS_ECRYPTO && ca == NULL);
    /* a certificate without its key is refused, never replaced */
    char key[1024];
    CHECK(gds_path(key, sizeof(key), "%s/ca.key.pem", cfg->dir) == GDS_OK);
    CHECK(unlink(key) == 0);
    CHECK(gds_ca_openssl_open(cfg, &ca) == GDS_ESTATE && ca == NULL);
}

/* ECC (docs/ca.md "ECC: one issuing CA per curve"): a P-256 or P-384 CSR is
 * signed by the CA on its own curve with ECDSA, keyUsage digitalSignature
 * only (OPC 10000-6 §6.2.2), and verifies against that issuer and its CRL.
 * A key on the wrong curve, or RSA for an ECC type, is refused. */
static void check_ecc_leaf(X509 *leaf, X509 *issuerCert, X509_CRL *crl, const char *curve,
                           int mdNid) {
    CHECK(X509_get_signature_nid(leaf) == mdNid);
    CHECK(X509_get_signature_nid(issuerCert) == mdNid);
    EVP_PKEY *ip = X509_get0_pubkey(issuerCert);
    char group[32] = {0};
    size_t gl = 0;
    CHECK(ip && EVP_PKEY_get_group_name(ip, group, sizeof(group), &gl) == 1);
    CHECK(strcmp(group, strcmp(curve, "P-256") == 0 ? "prime256v1" : "secp384r1") == 0);
    CHECK(X509_verify(leaf, ip) == 1 && X509_CRL_verify(crl, ip) == 1);
    CHECK(X509_get_key_usage(leaf) == KU_DIGITAL_SIGNATURE);
    CHECK(X509_check_issued(issuerCert, leaf) == X509_V_OK);
    check_subject(leaf);
}

/* Revocation lands on this issuer's CRL, not on the RSA one. */
static void check_ecc_revoke(gds_ca *ca, gds_ca_issuer issuer, const gds_buf *serial) {
    gds_buf crlDer = {0}, rsaCrl = {0};
    CHECK(gds_ca_revoke_issuer(ca, issuer, serial) == GDS_OK);
    CHECK(gds_ca_get_issuer_crl(ca, issuer, &crlDer) == GDS_OK);
    CHECK(gds_ca_get_crl(ca, &rsaCrl) == GDS_OK);
    const unsigned char *p = crlDer.data;
    X509_CRL *after = d2i_X509_CRL(NULL, &p, (long)crlDer.len);
    p = rsaCrl.data;
    X509_CRL *rsaAfter = d2i_X509_CRL(NULL, &p, (long)rsaCrl.len);
    CHECK(after && crl_count(after) >= 1 && rsaAfter);
    X509_CRL_free(after);
    X509_CRL_free(rsaAfter);
    gds_buf_free(&crlDer);
    gds_buf_free(&rsaCrl);
}

static void check_ecc(gds_ca *ca, const UA_ApplicationRecordDataType *rec, UA_UInt32 type,
                      gds_ca_issuer issuer, const char *curve, const char *otherCurve, int mdNid) {
    gds_ca_subject subj = {&reqId, rec, 615, type};
    EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "EC", curve);
    EVP_PKEY *wrong = EVP_PKEY_Q_keygen(NULL, NULL, "EC", otherCurve);
    EVP_PKEY *rsa = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    gds_buf csr = {0}, bad = {0}, badRsa = {0}, caDer = {0}, crlDer = {0};
    CHECK(k && wrong && rsa && make_csr(k, &csr) == GDS_OK && make_csr(wrong, &bad) == GDS_OK &&
          make_csr(rsa, &badRsa) == GDS_OK);
    gds_ca_issued out;
    CHECK(gds_ca_sign_csr(ca, &subj, &bad, &out) == GDS_EINVAL);
    CHECK(gds_ca_sign_csr(ca, &subj, &badRsa, &out) == GDS_EINVAL);
    CHECK(gds_ca_sign_csr(ca, &subj, &csr, &out) == GDS_OK);
    CHECK(gds_ca_get_issuer_cert(ca, issuer, &caDer) == GDS_OK);
    CHECK(gds_ca_get_issuer_crl(ca, issuer, &crlDer) == GDS_OK);
    X509 *leaf = parse_cert(&out.der), *issuerCert = parse_cert(&caDer);
    const unsigned char *p = crlDer.data;
    X509_CRL *crl = d2i_X509_CRL(NULL, &p, (long)crlDer.len);
    CHECK(leaf && issuerCert && crl);
    if(leaf && issuerCert && crl)
        check_ecc_leaf(leaf, issuerCert, crl, curve, mdNid);
    gds_buf_free(&crlDer);
    check_ecc_revoke(ca, issuer, &out.serial);
    X509_CRL_free(crl);
    X509_free(issuerCert);
    X509_free(leaf);
    gds_ca_issued_clear(&out);
    gds_buf_free(&caDer);
    gds_buf_free(&crlDer);
    gds_buf_free(&csr);
    gds_buf_free(&bad);
    gds_buf_free(&badRsa);
    EVP_PKEY_free(k);
    EVP_PKEY_free(wrong);
    EVP_PKEY_free(rsa);
}

/* StartNewKeyPairRequest for an ECC type: an EC key on the curve. */
static void check_ecc_key_pair(gds_ca *ca, const UA_ApplicationRecordDataType *rec) {
    gds_ca_subject subj = {&reqId, rec, 615, UA_NS0ID_ECCNISTP384APPLICATIONCERTIFICATETYPE};
    gds_ca_keyreq kr = {GDS_CA_KEY_PEM, NULL};
    gds_ca_issued out;
    gds_buf key = {0};
    CHECK(gds_ca_new_key_pair(ca, &subj, &kr, &out, &key) == GDS_OK);
    BIO *b = key.data ? BIO_new_mem_buf(key.data, (int)key.len) : NULL;
    EVP_PKEY *k = b ? PEM_read_bio_PrivateKey(b, NULL, NULL, NULL) : NULL;
    X509 *leaf = parse_cert(&out.der);
    CHECK(k && EVP_PKEY_is_a(k, "EC") && leaf && X509_check_private_key(leaf, k) == 1);
    X509_free(leaf);
    EVP_PKEY_free(k);
    BIO_free(b);
    gds_buf_free_secret(&key);
    gds_ca_issued_clear(&out);
    subj.certificateType = UA_NS0ID_ECCBRAINPOOLP256R1APPLICATIONCERTIFICATETYPE;
    CHECK(gds_ca_new_key_pair(ca, &subj, &kr, &out, &key) == GDS_EUNSUPPORTED);
}

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    char dir[1024];
    CHECK(gds_path(dir, sizeof(dir), "%s/ca", argv[1]) == GDS_OK);
    char f[1100];
    CHECK(gds_path(f, sizeof(f), "%s/ca.key.pem", dir) == GDS_OK);
    (void)unlink(f);
    CHECK(gds_path(f, sizeof(f), "%s/ca.der", dir) == GDS_OK);
    (void)unlink(f);
    CHECK(gds_path(f, sizeof(f), "%s/ca.crl", dir) == GDS_OK);
    (void)unlink(f);

    gds_ca_config cfg;
    gds_ca_config_init(&cfg);
    cfg.dir = dir;
    cfg.organization = "OpenGDS Test";
    cfg.caKeyBits = 2048; /* fast test; the default is 3072 */
    gds_ca *ca = NULL;
    CHECK(gds_ca_openssl_open(&cfg, &ca) == GDS_EINVAL && ca == NULL); /* no passphrase */
    uint8_t pw[] = "unit-test-passphrase";
    gds_buf pass = {pw, sizeof(pw) - 1};
    cfg.keyPassphrase = &pass;
    if(!CHECK(gds_ca_openssl_open(&cfg, &ca) == GDS_OK) || !ca)
        return CHECK_DONE();

    CHECK(gds_guid_random(&reqId) == GDS_OK);
    UA_ApplicationRecordDataType rec;
    UA_LocalizedText name;
    UA_String urls[4];
    make_record(&rec, &name, urls);
    gds_ca_subject subj = {&reqId, &rec, 615, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE};
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    gds_buf csr = {0};
    CHECK(key && make_csr(key, &csr) == GDS_OK);

    test_issue(ca, &subj, &csr);
    test_refusals(ca, &subj, &csr);
    test_small_key(ca, &subj);
    test_pre_sign(&subj, &csr);
    check_ecc(ca, &rec, UA_NS0ID_ECCNISTP256APPLICATIONCERTIFICATETYPE, GDS_CA_ISSUER_P256, "P-256",
              "P-384", NID_ecdsa_with_SHA256);
    check_ecc(ca, &rec, UA_NS0ID_ECCNISTP384APPLICATIONCERTIFICATETYPE, GDS_CA_ISSUER_P384, "P-384",
              "P-256", NID_ecdsa_with_SHA384);
    check_ecc_key_pair(ca, &rec);
    gds_buf first = {0};
    CHECK(gds_ca_get_ca_cert(ca, &first) == GDS_OK);
    gds_ca_close(ca);
    test_revoke(&cfg, &subj, &csr);
    test_reopen(&cfg, &first);

    gds_buf_free(&first);
    gds_buf_free(&csr);
    EVP_PKEY_free(key);
    return CHECK_DONE();
}
