/* OpenGDS Auditor - test PKI on OpenSSL 3.
 * SPDX-License-Identifier: MPL-2.0 */
#include "test_ca.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include "common/limits.h"
#include "common/banned.h"

static int clamp_days(int days) {
    if(days < 1)
        return 1;
    return days > TESTCA_MAX_DAYS ? TESTCA_MAX_DAYS : days;
}

static gds_status add_ext(X509 *cert, X509 *issuer, int nid, const char *value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if(!ex)
        return GDS_ECRYPTO;
    int ok = X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return ok == 1 ? GDS_OK : GDS_ECRYPTO;
}

/* 128 random bits, positive and non-zero */
static gds_status set_random_serial(X509 *x) {
    unsigned char rnd[16];
    if(RAND_bytes(rnd, sizeof(rnd)) != 1)
        return GDS_ECRYPTO;
    rnd[0] &= 0x7F;
    rnd[0] |= 0x01;
    BIGNUM *bn = BN_bin2bn(rnd, sizeof(rnd), NULL);
    OPENSSL_cleanse(rnd, sizeof(rnd));
    if(!bn)
        return GDS_ENOMEM;
    gds_status r = BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x)) ? GDS_OK : GDS_ECRYPTO;
    BN_free(bn);
    return r;
}

static gds_status set_name(X509_NAME *n, const char *cn) {
    if(X509_NAME_add_entry_by_txt(n, "O", MBSTRING_UTF8, (const unsigned char *)TESTCA_ORG,
                                  -1, -1, 0) != 1 ||
       X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_UTF8, (const unsigned char *)cn,
                                  -1, -1, 0) != 1)
        return GDS_ECRYPTO;
    return GDS_OK;
}

static gds_status set_validity(X509 *x, int days) {
    if(!X509_gmtime_adj(X509_getm_notBefore(x), -3600) || /* tolerate device clock skew */
       !X509_gmtime_adj(X509_getm_notAfter(x), (long)clamp_days(days) * 24 * 3600))
        return GDS_ECRYPTO;
    return GDS_OK;
}

/* A CA certificate: self-signed, or issued by `parent` (an intermediate) */
static gds_status ca_build(testca_t *ca, const testca_t *parent, const char *cn) {
    ca->key = EVP_RSA_gen(2048);
    ca->cert = X509_new();
    if(!ca->key || !ca->cert)
        return GDS_ECRYPTO;
    X509 *c = ca->cert;
    X509 *issuer = parent ? parent->cert : c;
    gds_status r;
    if(X509_set_version(c, 2) != 1 || X509_set_pubkey(c, ca->key) != 1)
        return GDS_ECRYPTO;
    if((r = set_random_serial(c)) != GDS_OK || (r = set_validity(c, TESTCA_MAX_DAYS)) != GDS_OK ||
       (r = set_name(X509_get_subject_name(c), cn)) != GDS_OK)
        return r;
    if(X509_set_issuer_name(c, X509_get_subject_name(issuer)) != 1)
        return GDS_ECRYPTO;
    if((r = add_ext(c, c, NID_basic_constraints, "critical,CA:TRUE")) != GDS_OK ||
       (r = add_ext(c, c, NID_key_usage, "critical,keyCertSign,cRLSign")) != GDS_OK ||
       (r = add_ext(c, c, NID_subject_key_identifier, "hash")) != GDS_OK ||
       (r = add_ext(c, issuer, NID_authority_key_identifier, "keyid:always")) != GDS_OK)
        return r;
    return X509_sign(c, parent ? parent->key : ca->key, EVP_sha256()) > 0 ? GDS_OK : GDS_ECRYPTO;
}

static gds_status testca_create(testca_t *ca, const char *cn) {
    return ca_build(ca, NULL, cn);
}

gds_status testca_create_sub(testca_t *ca, const testca_t *parent, const char *cn) {
    memset(ca, 0, sizeof(*ca));
    gds_status r = ca_build(ca, parent, cn);
    if(r != GDS_OK) {
        x509_drain_errors("testca_create_sub");
        testca_free(ca);
    }
    return r;
}

gds_status testca_load_or_create(testca_t *ca, const char *dir, const char *cn) {
    memset(ca, 0, sizeof(*ca));
    char certPath[GDS_MAX_PATH], keyPath[GDS_MAX_PATH];
    gds_status r;
    if((r = gds_path(certPath, sizeof(certPath), "%s/ca.der", dir)) != GDS_OK ||
       (r = gds_path(keyPath, sizeof(keyPath), "%s/ca.key.der", dir)) != GDS_OK)
        return r;
    gds_buf c = {0}, k = {0};
    gds_status rc = gds_file_read(certPath, GDS_MAX_CERT_SIZE, &c);
    gds_status rk = gds_file_read(keyPath, GDS_MAX_KEY_SIZE, &k);
    if(rc == GDS_OK && rk == GDS_OK) {
        ca->cert = x509_parse_cert(&c);
        ca->key = x509_parse_key(&k);
        gds_buf_free(&c);
        gds_buf_free_secret(&k);
        if(ca->cert && ca->key && X509_check_private_key(ca->cert, ca->key) == 1)
            return GDS_OK;
        ERR_clear_error();
        testca_free(ca);
        return GDS_ECRYPTO;
    }
    gds_buf_free(&c);
    gds_buf_free_secret(&k);
    if(rc != GDS_ENOTFOUND || rk != GDS_ENOTFOUND)
        return rc != GDS_OK && rc != GDS_ENOTFOUND ? rc : GDS_ENOTFOUND; /* half a CA: refuse */

    gds_buf out = {0};
    if((r = gds_mkdirs(dir, 0700)) != GDS_OK || (r = testca_create(ca, cn)) != GDS_OK)
        goto fail;
    if((r = x509_cert_to_der(ca->cert, &out)) != GDS_OK ||
       (r = gds_file_write_atomic(certPath, out.data, out.len, 0644)) != GDS_OK)
        goto fail;
    gds_buf_free(&out);
    if((r = x509_key_to_der(ca->key, &out)) != GDS_OK ||
       (r = gds_file_write_atomic(keyPath, out.data, out.len, 0600)) != GDS_OK)
        goto fail;
    gds_buf_free_secret(&out);
    return GDS_OK;
fail:
    x509_drain_errors("testca_create");
    gds_buf_free_secret(&out);
    testca_free(ca);
    return r;
}

void testca_free(testca_t *ca) {
    if(!ca)
        return;
    EVP_PKEY_free(ca->key);
    X509_free(ca->cert);
    memset(ca, 0, sizeof(*ca));
}

gds_status testca_cert_der(const testca_t *ca, gds_buf *out) {
    return x509_cert_to_der(ca->cert, out);
}

gds_status testca_crl_der(const testca_t *ca, gds_buf *out) {
    gds_status ret = GDS_ECRYPTO;
    out->data = NULL;
    out->len = 0;
    X509_CRL *crl = X509_CRL_new();
    ASN1_TIME *now = ASN1_TIME_adj(NULL, time(NULL), 0, -3600);
    ASN1_TIME *next = ASN1_TIME_adj(NULL, time(NULL), TESTCA_MAX_DAYS, 0);
    ASN1_INTEGER *crlNum = ASN1_INTEGER_new();
    X509_EXTENSION *ex = NULL;
    unsigned char *p = NULL;
    if(!crl || !now || !next || !crlNum)
        goto cleanup;
    if(X509_CRL_set_version(crl, 1) != 1 ||
       X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca->cert)) != 1 ||
       X509_CRL_set1_lastUpdate(crl, now) != 1 || X509_CRL_set1_nextUpdate(crl, next) != 1)
        goto cleanup;
    /* AKI so validators can match the CRL to the CA */
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca->cert, NULL, NULL, crl, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, "keyid:always");
    if(!ex || X509_CRL_add_ext(crl, ex, -1) != 1)
        goto cleanup;
    if(ASN1_INTEGER_set(crlNum, 1) != 1 ||
       X509_CRL_add1_ext_i2d(crl, NID_crl_number, crlNum, 0, 0) != 1)
        goto cleanup;
    if(X509_CRL_sign(crl, ca->key, EVP_sha256()) <= 0)
        goto cleanup;
    int n = i2d_X509_CRL(crl, &p);
    if(n > 0 && p) {
        ret = gds_buf_dup(p, (size_t)n, out);
        OPENSSL_free(p);
    }
cleanup:
    if(ret != GDS_OK)
        x509_drain_errors("testca_crl");
    X509_EXTENSION_free(ex);
    ASN1_INTEGER_free(crlNum);
    ASN1_TIME_free(now);
    ASN1_TIME_free(next);
    X509_CRL_free(crl);
    return ret;
}

/* Common leaf-certificate builder */
static gds_status build_leaf(const testca_t *ca, X509 *x, EVP_PKEY *pub, const char *san,
                             int days) {
    gds_status r;
    if(X509_set_version(x, 2) != 1 || X509_set_pubkey(x, pub) != 1 ||
       X509_set_issuer_name(x, X509_get_subject_name(ca->cert)) != 1)
        return GDS_ECRYPTO;
    if((r = set_random_serial(x)) != GDS_OK || (r = set_validity(x, days)) != GDS_OK)
        return r;
    if((r = add_ext(x, ca->cert, NID_basic_constraints, "critical,CA:FALSE")) != GDS_OK ||
       (r = add_ext(x, ca->cert, NID_key_usage,
                    "critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment")) != GDS_OK ||
       (r = add_ext(x, ca->cert, NID_ext_key_usage, "serverAuth,clientAuth")) != GDS_OK ||
       (r = add_ext(x, ca->cert, NID_subject_key_identifier, "hash")) != GDS_OK ||
       (r = add_ext(x, ca->cert, NID_authority_key_identifier, "keyid:always")) != GDS_OK)
        return r;
    if(san && (r = add_ext(x, ca->cert, NID_subject_alt_name, san)) != GDS_OK)
        return r;
    return X509_sign(x, ca->key, EVP_sha256()) > 0 ? GDS_OK : GDS_ECRYPTO;
}

/* Append ",DNS:<name>" for each DNS entry of the CSR's SAN; first URI to uri. */
static gds_status csr_san(X509_REQ *req, char *dns, size_t dnsLen, char *uri, size_t uriLen) {
    dns[0] = '\0';
    uri[0] = '\0';
    STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req);
    if(!exts)
        return GDS_OK;
    gds_status ret = GDS_OK;
    for(int i = 0; ret == GDS_OK && i < sk_X509_EXTENSION_num(exts); i++) {
        X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
        if(OBJ_obj2nid(X509_EXTENSION_get_object(ex)) != NID_subject_alt_name)
            continue;
        GENERAL_NAMES *gens = X509V3_EXT_d2i(ex);
        for(int j = 0; ret == GDS_OK && gens && j < sk_GENERAL_NAME_num(gens); j++) {
            GENERAL_NAME *g = sk_GENERAL_NAME_value(gens, j);
            if(g->type == GEN_DNS) {
                size_t used = strlen(dns);
                ret = gds_path(dns + used, dnsLen - used, ",DNS:%.*s",
                               ASN1_STRING_length(g->d.dNSName),
                               (const char *)ASN1_STRING_get0_data(g->d.dNSName));
            } else if(g->type == GEN_URI && !uri[0]) {
                ret = gds_path(uri, uriLen, "%.*s",
                               ASN1_STRING_length(g->d.uniformResourceIdentifier),
                               (const char *)ASN1_STRING_get0_data(g->d.uniformResourceIdentifier));
            }
        }
        GENERAL_NAMES_free(gens);
    }
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return ret;
}

gds_status testca_sign_csr(const testca_t *ca, const gds_buf *csrDer,
                           const char *applicationUri, int days, gds_buf *certOut) {
    gds_status ret = GDS_EINVAL;
    certOut->data = NULL;
    certOut->len = 0;
    if(!csrDer || !csrDer->data || csrDer->len == 0 || csrDer->len > GDS_MAX_CSR_SIZE)
        return GDS_EINVAL;
    const unsigned char *p = csrDer->data;
    X509_REQ *req = d2i_X509_REQ(NULL, &p, (long)csrDer->len);
    X509 *x = X509_new();
    EVP_PKEY *pub = req ? X509_REQ_get_pubkey(req) : NULL;
    if(!req || !pub || !x || p != csrDer->data + csrDer->len)
        goto cleanup;
    if(X509_REQ_verify(req, pub) != 1) {
        fprintf(stderr, "testca: CSR signature invalid (no proof of possession)\n");
        goto cleanup;
    }
    if(X509_set_subject_name(x, X509_REQ_get_subject_name(req)) != 1) {
        ret = GDS_ECRYPTO;
        goto cleanup;
    }
    char dns[1024], uri[GDS_MAX_APPLICATION_URI + 1], san[GDS_MAX_APPLICATION_URI + 1100];
    if((ret = csr_san(req, dns, sizeof(dns), uri, sizeof(uri))) != GDS_OK)
        goto cleanup;
    if((ret = gds_path(san, sizeof(san), "URI:%s%s", applicationUri ? applicationUri : uri,
                       dns)) != GDS_OK)
        goto cleanup;
    if((ret = build_leaf(ca, x, pub, san, days)) != GDS_OK)
        goto cleanup;
    ret = x509_cert_to_der(x, certOut);
cleanup:
    if(ret != GDS_OK)
        x509_drain_errors("testca_sign_csr");
    ERR_clear_error();
    EVP_PKEY_free(pub);
    X509_REQ_free(req);
    X509_free(x);
    return ret;
}

gds_status testca_issue(const testca_t *ca, const char *commonName, const char *applicationUri,
                        const char *dnsName, int days, gds_buf *certOut, gds_buf *keyOut) {
    gds_status ret = GDS_ECRYPTO;
    certOut->data = keyOut->data = NULL;
    certOut->len = keyOut->len = 0;
    EVP_PKEY *key = EVP_RSA_gen(2048);
    X509 *x = X509_new();
    char san[GDS_MAX_APPLICATION_URI + 300];
    if(!key || !x)
        goto cleanup;
    if((ret = set_name(X509_get_subject_name(x), commonName)) != GDS_OK ||
       (ret = gds_path(san, sizeof(san), "URI:%s,DNS:%s", applicationUri, dnsName)) != GDS_OK ||
       (ret = build_leaf(ca, x, key, san, days)) != GDS_OK ||
       (ret = x509_cert_to_der(x, certOut)) != GDS_OK)
        goto cleanup;
    ret = x509_key_to_der(key, keyOut);
cleanup:
    if(ret != GDS_OK) {
        x509_drain_errors("testca_issue");
        gds_buf_free(certOut);
        gds_buf_free_secret(keyOut);
    }
    EVP_PKEY_free(key);
    X509_free(x);
    return ret;
}

gds_status testca_identity(const testca_t *ca, const char *dir, const char *name,
                           const char *commonName, const char *applicationUri,
                           gds_buf *certOut, gds_buf *keyOut) {
    char cp[GDS_MAX_PATH], kp[GDS_MAX_PATH];
    gds_status r;
    if((r = gds_path(cp, sizeof(cp), "%s/%s.der", dir, name)) != GDS_OK ||
       (r = gds_path(kp, sizeof(kp), "%s/%s.key.der", dir, name)) != GDS_OK)
        return r;
    if(gds_file_read(cp, GDS_MAX_CERT_SIZE, certOut) == GDS_OK &&
       gds_file_read(kp, GDS_MAX_KEY_SIZE, keyOut) == GDS_OK &&
       x509_key_matches(certOut, keyOut))
        return GDS_OK;
    gds_buf_free(certOut);
    gds_buf_free_secret(keyOut);
    if((r = testca_issue(ca, commonName, applicationUri, "localhost", TESTCA_MAX_DAYS, certOut,
                         keyOut)) != GDS_OK)
        return r;
    if((r = gds_file_write_atomic(cp, certOut->data, certOut->len, 0644)) != GDS_OK ||
       (r = gds_file_write_atomic(kp, keyOut->data, keyOut->len, 0600)) != GDS_OK) {
        gds_buf_free(certOut);
        gds_buf_free_secret(keyOut);
    }
    return r;
}
