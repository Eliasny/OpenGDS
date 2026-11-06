/* OpenGDS Auditor - X.509 helpers on OpenSSL 3.
 * SPDX-License-Identifier: MPL-2.0 */
#include "x509util.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "common/limits.h"
#include "common/banned.h"

void x509_drain_errors(const char *where) {
    unsigned long e;
    while((e = ERR_get_error()) != 0) {
        char msg[256];
        ERR_error_string_n(e, msg, sizeof(msg));
        fprintf(stderr, "openssl (%s): %s\n", where, msg);
    }
}

/* OpenSSL takes long/int lengths: refuse anything that does not fit, and
 * anything above our own limit. */
static bool fits(const gds_buf *b, size_t max) {
    return b && b->data && b->len > 0 && b->len <= max && b->len <= (size_t)INT_MAX;
}

X509 *x509_parse_cert(const gds_buf *der) {
    if(!fits(der, GDS_MAX_CERT_SIZE))
        return NULL;
    const unsigned char *p = der->data;
    X509 *x = d2i_X509(NULL, &p, (long)der->len);
    /* Trailing bytes mean two parsers could disagree on what was signed */
    if(x && p != der->data + der->len) {
        X509_free(x);
        x = NULL;
    }
    if(!x)
        ERR_clear_error();
    return x;
}

EVP_PKEY *x509_parse_key(const gds_buf *der) {
    if(!fits(der, GDS_MAX_KEY_SIZE))
        return NULL;
    const unsigned char *p = der->data;
    EVP_PKEY *k = d2i_AutoPrivateKey(NULL, &p, (long)der->len);
    if(!k) {
        BIO *bio = BIO_new_mem_buf(der->data, (int)der->len);
        if(bio) {
            k = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
            BIO_free(bio);
        }
    }
    ERR_clear_error();
    return k;
}

/* Copy OpenSSL-allocated DER into a malloc'd gds_buf so gds_buf_free is right */
static gds_status take_openssl_der(unsigned char *p, int n, gds_buf *out, bool secret) {
    if(n <= 0 || !p)
        return GDS_ECRYPTO;
    gds_status r = gds_buf_dup(p, (size_t)n, out);
    if(secret)
        OPENSSL_clear_free(p, (size_t)n);
    else
        OPENSSL_free(p);
    return r;
}

gds_status x509_cert_to_der(X509 *x, gds_buf *out) {
    unsigned char *p = NULL;
    int n = i2d_X509(x, &p);
    return take_openssl_der(p, n, out, false);
}

gds_status x509_key_to_der(EVP_PKEY *k, gds_buf *out) {
    unsigned char *p = NULL;
    int n = i2d_PrivateKey(k, &p);
    return take_openssl_der(p, n, out, true);
}

gds_status x509_thumbprint(const gds_buf *certDer, char out[X509_THUMBPRINT_LEN]) {
    unsigned char md[20];
    unsigned int mdLen = 0;
    out[0] = '\0';
    if(!fits(certDer, GDS_MAX_CERT_SIZE))
        return GDS_EINVAL;
    if(EVP_Digest(certDer->data, certDer->len, md, &mdLen, EVP_sha1(), NULL) != 1 ||
       mdLen != sizeof(md)) {
        x509_drain_errors("thumbprint");
        return GDS_ECRYPTO;
    }
    return gds_hex(md, sizeof(md), out, X509_THUMBPRINT_LEN);
}

bool x509_key_matches(const gds_buf *certDer, const gds_buf *keyDer) {
    X509 *x = x509_parse_cert(certDer);
    EVP_PKEY *k = x509_parse_key(keyDer);
    bool ok = x && k && X509_check_private_key(x, k) == 1;
    X509_free(x);
    EVP_PKEY_free(k);
    ERR_clear_error();
    return ok;
}

bool x509_is_self_signed(const gds_buf *certDer) {
    X509 *x = x509_parse_cert(certDer);
    bool r = x && X509_NAME_cmp(X509_get_subject_name(x), X509_get_issuer_name(x)) == 0;
    X509_free(x);
    return r;
}

void x509_describe(const gds_buf *certDer, char *out, size_t outLen) {
    if(outLen == 0)
        return;
    X509 *x = x509_parse_cert(certDer);
    if(!x) {
        snprintf(out, outLen, "<unparsable certificate>");
        return;
    }
    char subj[256] = "?", iss[256] = "?", until[64] = "?";
    if(!X509_NAME_oneline(X509_get_subject_name(x), subj, sizeof(subj)))
        subj[0] = '\0';
    if(!X509_NAME_oneline(X509_get_issuer_name(x), iss, sizeof(iss)))
        iss[0] = '\0';
    BIO *b = BIO_new(BIO_s_mem());
    if(b && ASN1_TIME_print(b, X509_get0_notAfter(x)) == 1) {
        int n = BIO_read(b, until, (int)sizeof(until) - 1);
        until[n > 0 ? n : 0] = '\0';
    }
    BIO_free(b);
    ERR_clear_error();
    /* Truncation of a display string is acceptable here */
    snprintf(out, outLen, "subject=%s | issuer=%s | notAfter=%s", subj, iss, until);
    X509_free(x);
}

gds_status x509_make_csr(const gds_buf *keyDer, const char *commonName,
                         const char *applicationUri, const char *dnsName, gds_buf *csrOut) {
    gds_status ret = GDS_ECRYPTO;
    csrOut->data = NULL;
    csrOut->len = 0;
    EVP_PKEY *key = x509_parse_key(keyDer);
    X509_REQ *req = X509_REQ_new();
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
    X509_EXTENSION *ex = NULL;
    unsigned char *p = NULL;
    char san[GDS_MAX_APPLICATION_URI + 300];
    if(!key || !req || !exts)
        goto cleanup;
    if(gds_path(san, sizeof(san), "URI:%s%s%s", applicationUri, dnsName ? ",DNS:" : "",
                dnsName ? dnsName : "") != GDS_OK) {
        ret = GDS_ETOOBIG;
        goto cleanup;
    }
    X509_NAME *name = X509_REQ_get_subject_name(req);
    if(X509_REQ_set_version(req, 0) != 1 ||
       X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                                  (const unsigned char *)commonName, -1, -1, 0) != 1 ||
       X509_REQ_set_pubkey(req, key) != 1)
        goto cleanup;
    ex = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san);
    if(!ex || sk_X509_EXTENSION_push(exts, ex) <= 0)
        goto cleanup;
    ex = NULL; /* owned by exts now */
    if(X509_REQ_add_extensions(req, exts) != 1)
        goto cleanup;
    if(X509_REQ_sign(req, key, EVP_sha256()) <= 0)
        goto cleanup;
    int n = i2d_X509_REQ(req, &p);
    ret = take_openssl_der(p, n, csrOut, false);
    p = NULL;
cleanup:
    if(ret != GDS_OK)
        x509_drain_errors("make_csr");
    X509_EXTENSION_free(ex);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    EVP_PKEY_free(key);
    X509_REQ_free(req);
    return ret;
}
