/* OpenGDS unit test: cax_set_pubkey_from_req (src/ca/ca_x509.c). The
 * certificate's subjectPublicKeyInfo is byte for byte what
 * X509_set_pubkey writes, whether the request's is copied (canonical) or
 * the key is encoded again (anything else: absent RSA parameters, a
 * compressed EC point, BER lengths).
 * SPDX-License-Identifier: MPL-2.0 */
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <stdlib.h>
#include <string.h>

#include "ca_x509.h"
#include "check.h"
#include "common/banned.h"

static int spki_der(X509 *x, unsigned char **out) {
    return i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), out);
}

/* The SPKI that cax_set_pubkey_from_req gives x for req, against the one
 * X509_set_pubkey gives for the request's decoded key. */
static bool same_as_set_pubkey(X509_REQ *req) {
    EVP_PKEY *pk = X509_REQ_get_pubkey(req);
    X509 *a = X509_new(), *b = X509_new();
    unsigned char *da = NULL, *db = NULL;
    bool ok = pk && a && b && cax_set_pubkey_from_req(a, req, pk) == GDS_OK &&
              X509_set_pubkey(b, pk) == 1;
    int la = ok ? spki_der(a, &da) : -1, lb = ok ? spki_der(b, &db) : -2;
    ok = ok && la > 0 && la == lb && memcmp(da, db, (size_t)la) == 0;
    /* the key the certificate carries is the request's */
    const unsigned char *p = da;
    EVP_PKEY *got = ok ? d2i_PUBKEY(NULL, &p, la) : NULL;
    ok = ok && got && EVP_PKEY_eq(got, pk) == 1;
    EVP_PKEY_free(got);
    OPENSSL_free(da);
    OPENSSL_free(db);
    X509_free(a);
    X509_free(b);
    EVP_PKEY_free(pk);
    return ok;
}

static X509_REQ *req_for(EVP_PKEY *k) {
    X509_REQ *r = X509_REQ_new();
    if(r && X509_REQ_set_pubkey(r, k) == 1)
        return r;
    X509_REQ_free(r);
    return NULL;
}

/* Rewrite the request's SPKI: algorithm parameters and key bits. */
static bool set_spki(X509_REQ *r, int algNid, int ptype, void *pval, const unsigned char *bits,
                     int len) {
    unsigned char *copy = OPENSSL_memdup(bits, (size_t)len);
    ASN1_OBJECT *o = OBJ_nid2obj(algNid);
    if(copy && X509_PUBKEY_set0_param(X509_REQ_get_X509_PUBKEY(r), o, ptype, pval, copy, len) == 1)
        return true;
    OPENSSL_free(copy);
    return false;
}

static void test_rsa(void) {
    EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    X509_REQ *r = k ? req_for(k) : NULL;
    if(!CHECK(r))
        return;
    CHECK(same_as_set_pubkey(r)); /* copied */

    const unsigned char *bits = NULL;
    int len = 0;
    CHECK(X509_PUBKEY_get0_param(NULL, &bits, &len, NULL, X509_REQ_get_X509_PUBKEY(r)) == 1);
    unsigned char *saved = OPENSSL_memdup(bits, (size_t)len);
    /* rsaEncryption without the NULL parameters: encoded again */
    CHECK(saved && set_spki(r, NID_rsaEncryption, V_ASN1_UNDEF, NULL, saved, len));
    CHECK(same_as_set_pubkey(r));
    /* the RSAPublicKey SEQUENCE with a long-form length where the short or
     * a shorter one fits (BER, not DER): encoded again */
    if(saved && len > 4 && saved[0] == 0x30 && saved[1] == 0x82) {
        size_t n = (size_t)len + 1;
        unsigned char *ber = malloc(n);
        if(CHECK(ber)) {
            ber[0] = 0x30;
            ber[1] = 0x83;
            ber[2] = 0x00;
            memcpy(ber + 3, saved + 2, (size_t)len - 2);
            CHECK(set_spki(r, NID_rsaEncryption, V_ASN1_NULL, NULL, ber, (int)n));
            EVP_PKEY *pk = X509_REQ_get_pubkey(r);
            /* OpenSSL may refuse the BER key outright; if it decodes, the
             * certificate still gets the DER form */
            if(pk)
                CHECK(same_as_set_pubkey(r));
            EVP_PKEY_free(pk);
            free(ber);
        }
    }
    OPENSSL_free(saved);
    X509_REQ_free(r);
    EVP_PKEY_free(k);
}

static void test_ec(const char *curve) {
    EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "EC", curve);
    X509_REQ *r = k ? req_for(k) : NULL;
    if(!CHECK(r))
        return;
    CHECK(same_as_set_pubkey(r)); /* copied */
    /* the same key with a compressed point: encoded again */
    const unsigned char *u = NULL;
    int ulen = 0;
    CHECK(X509_PUBKEY_get0_param(NULL, &u, &ulen, NULL, X509_REQ_get_X509_PUBKEY(r)) == 1 &&
          ulen > 1 && u[0] == 0x04);
    unsigned char pt[100];
    size_t n = ulen > 1 ? 1 + ((size_t)ulen - 1) / 2 : 0;
    if(!CHECK(n > 1 && n <= sizeof(pt)))
        n = 1;
    pt[0] = (unsigned char)(0x02 | (u[ulen - 1] & 1)); /* SEC 1 §2.3.3 */
    memcpy(pt + 1, u + 1, n - 1);
    const ASN1_OBJECT *alg = NULL;
    const void *pval = NULL;
    int ptype = 0;
    X509_ALGOR *a = NULL;
    CHECK(X509_PUBKEY_get0_param(NULL, NULL, NULL, &a, X509_REQ_get_X509_PUBKEY(r)) == 1);
    X509_ALGOR_get0(&alg, &ptype, &pval, a);
    CHECK(ptype == V_ASN1_OBJECT &&
          set_spki(r, NID_X9_62_id_ecPublicKey, V_ASN1_OBJECT, OBJ_dup(pval), pt, (int)n));
    EVP_PKEY *pk = X509_REQ_get_pubkey(r);
    X509 *x = X509_new();
    const unsigned char *bits = NULL;
    int len = 0;
    if(CHECK(pk && x) && CHECK(cax_set_pubkey_from_req(x, r, pk) == GDS_OK))
        CHECK(X509_PUBKEY_get0_param(NULL, &bits, &len, NULL, X509_get_X509_PUBKEY(x)) == 1 &&
              len > 0 && (size_t)len != n); /* not the compressed copy */
    X509_free(x);
    EVP_PKEY_free(pk);
    X509_REQ_free(r);
    EVP_PKEY_free(k);
}

int main(void) {
    test_rsa();
    test_ec("P-256");
    test_ec("P-384");
    return CHECK_DONE();
}
