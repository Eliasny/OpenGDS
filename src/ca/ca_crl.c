/* OpenGDS - CRLs of the built-in CA backend (RFC 5280 §5: v2, CRL number,
 * authorityKeyIdentifier). Every trust list carries the CA's CRL so that
 * applications can check revocation (OPC 10000-12 TrustList, OPC 10000-4
 * certificate validation).
 * SPDX-License-Identifier: MPL-2.0 */
#include <openssl/bn.h>
#include <openssl/x509v3.h>

#include <string.h>
#include <time.h>

#include "ca.h"
#include "ca_internal.h"
#include "ca_x509.h"
#include "common/banned.h"

#define DAY_SECONDS 86400

static long crl_number(X509_CRL *crl) {
    ASN1_INTEGER *n = X509_CRL_get_ext_d2i(crl, NID_crl_number, NULL, NULL);
    long v = n ? ASN1_INTEGER_get(n) : 0;
    ASN1_INTEGER_free(n);
    return v > 0 ? v : 0;
}

static gds_status crl_extensions(ossl_ca *c, X509_CRL *crl, long number) {
    ASN1_INTEGER *num = ASN1_INTEGER_new();
    AUTHORITY_KEYID *akid = AUTHORITY_KEYID_new();
    const ASN1_OCTET_STRING *kid = X509_get0_subject_key_id(c->cert);
    gds_status r = GDS_ECRYPTO;
    if(num && akid && kid && ASN1_INTEGER_set(num, number) == 1 &&
       (akid->keyid = ASN1_OCTET_STRING_dup(kid)) != NULL &&
       X509_CRL_add1_ext_i2d(crl, NID_crl_number, num, 0, X509V3_ADD_REPLACE) == 1 &&
       X509_CRL_add1_ext_i2d(crl, NID_authority_key_identifier, akid, 0, X509V3_ADD_REPLACE) == 1)
        r = GDS_OK;
    ASN1_INTEGER_free(num);
    AUTHORITY_KEYID_free(akid);
    return r;
}

/* A revoked entry for serial, dated now. */
static gds_status new_entry(const gds_buf *serial, time_t now, X509_REVOKED **out) {
    *out = NULL;
    X509_REVOKED *e = X509_REVOKED_new();
    BIGNUM *bn = BN_bin2bn(serial->data, (int)serial->len, NULL);
    ASN1_INTEGER *num = bn ? BN_to_ASN1_INTEGER(bn, NULL) : NULL;
    ASN1_TIME *when = ASN1_TIME_new();
    gds_status r = GDS_ECRYPTO;
    if(e && num && when && ASN1_TIME_set(when, now) &&
       X509_REVOKED_set_serialNumber(e, num) == 1 &&
       X509_REVOKED_set_revocationDate(e, when) == 1) {
        *out = e;
        e = NULL;
        r = GDS_OK;
    }
    X509_REVOKED_free(e);
    BN_free(bn);
    ASN1_INTEGER_free(num);
    ASN1_TIME_free(when);
    return r;
}

/* Copy every entry of prev (if any) into crl. Entries are kept until the
 * CA is replaced: a revoked certificate stays on the CRL for its lifetime,
 * and the CA does not know when each one expires. */
static gds_status copy_entries(X509_CRL *crl, X509_CRL *prev) {
    STACK_OF(X509_REVOKED) *old = prev ? X509_CRL_get_REVOKED(prev) : NULL;
    for(int i = 0; i < sk_X509_REVOKED_num(old); i++) {
        X509_REVOKED *e = X509_REVOKED_dup(sk_X509_REVOKED_value(old, i));
        if(!e || X509_CRL_add0_revoked(crl, e) != 1) {
            X509_REVOKED_free(e);
            return GDS_ECRYPTO;
        }
    }
    return GDS_OK;
}

/* A new CRL with number `number`, the entries of prev, and add (if not
 * NULL) as a new entry. */
static gds_status issue_crl(ossl_ca *c, long number, X509_CRL *prev, X509_REVOKED *add,
                            X509_CRL **out) {
    *out = NULL;
    X509_CRL *crl = X509_CRL_new();
    ASN1_TIME *last = ASN1_TIME_new(), *next = ASN1_TIME_new();
    time_t now = time(NULL);
    gds_status r = GDS_ECRYPTO;
    if(crl && last && next && X509_CRL_set_version(crl, X509_CRL_VERSION_2) == 1 &&
       X509_CRL_set_issuer_name(crl, X509_get_subject_name(c->cert)) == 1 &&
       ASN1_TIME_set(last, now) && ASN1_TIME_set(next, now + (time_t)c->crlDays * DAY_SECONDS) &&
       X509_CRL_set1_lastUpdate(crl, last) == 1 && X509_CRL_set1_nextUpdate(crl, next) == 1)
        r = crl_extensions(c, crl, number);
    if(r == GDS_OK)
        r = copy_entries(crl, prev);
    if(r == GDS_OK && add) {
        X509_REVOKED *e = X509_REVOKED_dup(add);
        if(!e || X509_CRL_add0_revoked(crl, e) != 1) {
            X509_REVOKED_free(e);
            r = GDS_ECRYPTO;
        }
    }
    if(r == GDS_OK && (X509_CRL_sort(crl) != 1 || X509_CRL_sign(crl, c->key, EVP_sha256()) <= 0))
        r = GDS_ECRYPTO;
    ASN1_TIME_free(last);
    ASN1_TIME_free(next);
    if(r != GDS_OK) {
        X509_CRL_free(crl);
        return r;
    }
    *out = crl;
    return GDS_OK;
}

static gds_status replace_crl(ossl_ca *c, long number, X509_REVOKED *add) {
    X509_CRL *crl = NULL;
    gds_status r = issue_crl(c, number, c->crl, add, &crl);
    gds_buf der = {0};
    if(r == GDS_OK)
        r = cax_crl_der(crl, &der);
    if(r == GDS_OK && der.len > GDS_MAX_CRL_SIZE)
        r = GDS_ETOOBIG;
    if(r == GDS_OK)
        r = gds_file_write_atomic(c->crlPath, der.data, der.len, 0644);
    gds_buf_free(&der);
    if(r != GDS_OK) {
        X509_CRL_free(crl);
        return r;
    }
    X509_CRL_free(c->crl);
    c->crl = crl;
    return GDS_OK;
}

static gds_status load_crl(ossl_ca *c) {
    gds_buf b = {0};
    gds_status r = gds_file_read(c->crlPath, GDS_MAX_CRL_SIZE, &b);
    if(r != GDS_OK)
        return r;
    const unsigned char *p = b.data;
    X509_CRL *crl = d2i_X509_CRL(NULL, &p, (long)b.len);
    EVP_PKEY *pub = X509_get0_pubkey(c->cert);
    r = GDS_ECRYPTO;
    /* only a CRL this CA signed is used */
    if(crl && p == b.data + b.len && pub && X509_CRL_verify(crl, pub) == 1) {
        c->crl = crl;
        crl = NULL;
        r = GDS_OK;
    }
    X509_CRL_free(crl);
    gds_buf_free(&b);
    return r;
}

gds_status ca_ossl_load_or_issue_crl(ossl_ca *c) {
    gds_status r = load_crl(c);
    if(r == GDS_ENOTFOUND)
        return replace_crl(c, 1, NULL);
    return r;
}

gds_status ca_ossl_get_crl(void *ctx, gds_buf *out) {
    ossl_ca *c = ctx;
    time_t soon = time(NULL) + DAY_SECONDS;
    const ASN1_TIME *next = X509_CRL_get0_nextUpdate(c->crl);
    if(!next || X509_cmp_time(next, &soon) <= 0) {
        gds_status r = replace_crl(c, crl_number(c->crl) + 1, NULL);
        if(r != GDS_OK)
            return r;
    }
    return cax_crl_der(c->crl, out);
}

gds_status ca_ossl_revoke(void *ctx, const gds_buf *serial) {
    ossl_ca *c = ctx;
    X509_REVOKED *e = NULL;
    gds_status r = new_entry(serial, time(NULL), &e);
    if(r != GDS_OK)
        return r;
    X509_REVOKED *found = NULL;
    /* already listed: nothing to change (the retry after a failed call) */
    if(X509_CRL_get0_by_serial(c->crl, &found, X509_REVOKED_get0_serialNumber(e)) == 1)
        r = GDS_OK;
    else
        r = replace_crl(c, crl_number(c->crl) + 1, e);
    X509_REVOKED_free(e);
    return r;
}
