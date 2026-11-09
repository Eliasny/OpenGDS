/* OpenGDS - the CA slot wrapper: one backend behind one interface.
 * SPDX-License-Identifier: MPL-2.0 */
#include "ca.h"

#include <open62541/nodeids.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "common/limits.h"
#include "common/banned.h"

struct gds_ca {
    gds_ca_backend b;
    void *ctx;
};

void gds_ca_issued_clear(gds_ca_issued *c) {
    gds_buf_free(&c->der);
    gds_buf_free(&c->serial);
    c->notBefore = 0;
    c->notAfter = 0;
}

gds_status gds_ca_wrap(const gds_ca_backend *backend, void *ctx, gds_ca **out) {
    *out = NULL;
    if(!backend || backend->abiVersion < GDS_CA_ABI_MIN_VERSION ||
       backend->abiVersion > GDS_CA_ABI_VERSION || !backend->sign_csr ||
       !backend->get_ca_cert || !backend->get_crl || !backend->destroy) {
        if(backend && backend->destroy)
            backend->destroy(ctx);
        return GDS_EINVAL;
    }
    gds_ca *ca = calloc(1, sizeof(*ca));
    if(!ca) {
        backend->destroy(ctx);
        return GDS_ENOMEM;
    }
    /* only the fields the backend's version has (ABI 2 ends before
     * new_key_pair); later ones stay NULL */
    size_t n = sizeof(ca->b);
    if(backend->abiVersion < 3)
        n = offsetof(gds_ca_backend, new_key_pair);
    else if(backend->abiVersion < 4)
        n = offsetof(gds_ca_backend, get_issuer_cert);
    memcpy(&ca->b, backend, n);
    if(!ca->b.get_issuer_cert || !ca->b.get_issuer_crl || !ca->b.revoke_issuer) {
        ca->b.get_issuer_cert = NULL; /* all three or none */
        ca->b.get_issuer_crl = NULL;
        ca->b.revoke_issuer = NULL;
    }
    ca->ctx = ctx;
    *out = ca;
    return GDS_OK;
}

void gds_ca_close(gds_ca *ca) {
    if(!ca)
        return;
    ca->b.destroy(ca->ctx);
    free(ca);
}

gds_status gds_ca_sign_csr(gds_ca *ca, const gds_ca_subject *subj, const gds_buf *csrDer,
                           gds_ca_issued *out) {
    memset(out, 0, sizeof(*out));
    if(!subj || !subj->record || !subj->requestId || !csrDer || !csrDer->data)
        return GDS_EINVAL;
    if(ca->b.pre_sign) {
        gds_status r = ca->b.pre_sign(ca->ctx, GDS_CA_OP_SIGN_CSR, subj);
        if(r != GDS_OK)
            return r;
    }
    gds_status r = ca->b.sign_csr(ca->ctx, subj, csrDer, out);
    if(r != GDS_OK)
        gds_ca_issued_clear(out);
    return r;
}

gds_status gds_ca_get_ca_cert(gds_ca *ca, gds_buf *out) {
    memset(out, 0, sizeof(*out));
    return ca->b.get_ca_cert(ca->ctx, out);
}

gds_status gds_ca_get_crl(gds_ca *ca, gds_buf *out) {
    memset(out, 0, sizeof(*out));
    return ca->b.get_crl(ca->ctx, out);
}

bool gds_ca_issuer_of(UA_UInt32 certType, gds_ca_issuer *out) {
    switch(certType) {
    case UA_NS0ID_APPLICATIONCERTIFICATETYPE:
    case UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE:
        *out = GDS_CA_ISSUER_RSA;
        return true;
    case UA_NS0ID_ECCNISTP256APPLICATIONCERTIFICATETYPE:
        *out = GDS_CA_ISSUER_P256;
        return true;
    case UA_NS0ID_ECCNISTP384APPLICATIONCERTIFICATETYPE:
        *out = GDS_CA_ISSUER_P384;
        return true;
    default:
        return false;
    }
}

static bool issuer_valid(gds_ca_issuer issuer) {
    return (unsigned)issuer < GDS_CA_ISSUERS;
}

gds_status gds_ca_get_issuer_cert(gds_ca *ca, gds_ca_issuer issuer, gds_buf *out) {
    memset(out, 0, sizeof(*out));
    if(!issuer_valid(issuer))
        return GDS_EINVAL;
    if(ca->b.get_issuer_cert)
        return ca->b.get_issuer_cert(ca->ctx, issuer, out);
    return issuer == GDS_CA_ISSUER_RSA ? ca->b.get_ca_cert(ca->ctx, out) : GDS_ENOTFOUND;
}

gds_status gds_ca_get_issuer_crl(gds_ca *ca, gds_ca_issuer issuer, gds_buf *out) {
    memset(out, 0, sizeof(*out));
    if(!issuer_valid(issuer))
        return GDS_EINVAL;
    if(ca->b.get_issuer_crl)
        return ca->b.get_issuer_crl(ca->ctx, issuer, out);
    return issuer == GDS_CA_ISSUER_RSA ? ca->b.get_crl(ca->ctx, out) : GDS_ENOTFOUND;
}

gds_status gds_ca_revoke_issuer(gds_ca *ca, gds_ca_issuer issuer, const gds_buf *serial) {
    if(!issuer_valid(issuer) || !serial || !serial->data || serial->len == 0 ||
       serial->len > GDS_MAX_SERIAL_SIZE)
        return GDS_EINVAL;
    if(ca->b.revoke_issuer)
        return ca->b.revoke_issuer(ca->ctx, issuer, serial);
    if(issuer != GDS_CA_ISSUER_RSA)
        return GDS_ENOTFOUND;
    return ca->b.revoke ? ca->b.revoke(ca->ctx, serial) : GDS_EUNSUPPORTED;
}

gds_status gds_ca_revoke(gds_ca *ca, const gds_buf *serial) {
    if(!serial || !serial->data || serial->len == 0 || serial->len > GDS_MAX_SERIAL_SIZE)
        return GDS_EINVAL;
    if(!ca->b.revoke)
        return GDS_EUNSUPPORTED;
    return ca->b.revoke(ca->ctx, serial);
}

/* ---- StartNewKeyPairRequest ---- */

#define NEW_KEY_BITS 2048 /* RsaSha256ApplicationCertificateType minimum */
#define PFX_ITER 600000   /* PBKDF2 iterations of the PKCS #12 key bag */

/* The key for the CertificateType: RSA 2048, or the type's curve
 * (OPC 10000-12 §7.8.4.11, §7.8.4.12). */
static gds_status new_key(UA_UInt32 certType, EVP_PKEY **out) {
    *out = NULL;
    gds_ca_issuer issuer;
    if(!gds_ca_issuer_of(certType, &issuer))
        return GDS_EUNSUPPORTED;
    if(issuer == GDS_CA_ISSUER_RSA)
        *out = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)NEW_KEY_BITS);
    else
        *out = EVP_PKEY_Q_keygen(NULL, NULL, "EC", issuer == GDS_CA_ISSUER_P256 ? "P-256" : "P-384");
    return *out ? GDS_OK : GDS_ECRYPTO;
}

/* A CSR for key, signed with it (the backend checks proof of possession
 * like for any CSR; every field it uses comes from the record). */
static gds_status csr_for(EVP_PKEY *key, gds_buf *out) {
    memset(out, 0, sizeof(*out));
    X509_REQ *req = X509_REQ_new();
    gds_status r = GDS_ECRYPTO;
    if(req && X509_REQ_set_version(req, X509_REQ_VERSION_1) == 1 &&
       X509_REQ_set_pubkey(req, key) == 1 && X509_REQ_sign(req, key, EVP_sha256()) > 0) {
        int len = i2d_X509_REQ(req, NULL);
        out->data = len > 0 && (size_t)len <= GDS_MAX_CSR_SIZE ? malloc((size_t)len) : NULL;
        if(out->data) {
            out->len = (size_t)len;
            unsigned char *p = out->data;
            r = i2d_X509_REQ(req, &p) == len ? GDS_OK : GDS_ECRYPTO;
        }
    }
    if(r != GDS_OK)
        gds_buf_free(out);
    X509_REQ_free(req);
    return r;
}

static gds_status bio_to_secret(BIO *b, gds_buf *out) {
    char *p = NULL;
    long n = BIO_get_mem_data(b, &p);
    if(n <= 0 || (size_t)n > GDS_MAX_KEY_SIZE)
        return GDS_ECRYPTO;
    return gds_buf_dup(p, (size_t)n, out);
}

/* PEM: PKCS #8, encrypted (PBES2, AES-256-CBC) under a non-empty password */
static gds_status encode_pem(EVP_PKEY *key, const gds_buf *pw, gds_buf *out) {
    BIO *b = BIO_new(BIO_s_secmem());
    bool enc = pw && pw->len > 0;
    gds_status r = GDS_ECRYPTO;
    if(b && (pw ? pw->len : 0) <= INT32_MAX &&
       PEM_write_bio_PKCS8PrivateKey(b, key, enc ? EVP_aes_256_cbc() : NULL,
                                     enc ? (const char *)pw->data : NULL,
                                     enc ? (int)pw->len : 0, NULL, NULL) == 1)
        r = bio_to_secret(b, out);
    BIO_free(b);
    return r;
}

/* PFX: PKCS #12 with key, certificate and the CA certificate (§7.9.4 "the
 * packet shall include the Certificate and the PrivateKey"); AES-256 and a
 * SHA-256 MAC under the password. Without a password nothing is encrypted. */
static gds_status encode_pfx(gds_ca *ca, gds_ca_issuer issuer, EVP_PKEY *key,
                             const gds_buf *certDer, const gds_buf *pw, gds_buf *out) {
    const unsigned char *p = certDer->data;
    X509 *cert = d2i_X509(NULL, &p, (long)certDer->len);
    gds_buf caDer = {0};
    X509 *caCert = NULL;
    STACK_OF(X509) *chain = sk_X509_new_null();
    if(gds_ca_get_issuer_cert(ca, issuer, &caDer) == GDS_OK) {
        p = caDer.data;
        caCert = d2i_X509(NULL, &p, (long)caDer.len);
    }
    char *pass = NULL;
    bool enc = pw && pw->len > 0;
    if(enc && (pass = OPENSSL_secure_malloc(pw->len + 1)) != NULL) {
        memcpy(pass, pw->data, pw->len);
        pass[pw->len] = '\0';
    }
    PKCS12 *p12 = NULL;
    if(cert && caCert && chain && sk_X509_push(chain, caCert) > 0 && (!enc || pass)) {
        caCert = NULL; /* owned by chain */
        int nid = enc ? NID_aes_256_cbc : -1;
        p12 = PKCS12_create_ex(pass, NULL, key, cert, chain, nid, nid, PFX_ITER,
                               enc ? 1 : -1, 0, NULL, NULL);
        if(p12 && enc && PKCS12_set_mac(p12, pass, -1, NULL, 0, PFX_ITER, EVP_sha256()) != 1) {
            PKCS12_free(p12);
            p12 = NULL;
        }
    }
    gds_status r = GDS_ECRYPTO;
    BIO *b = p12 ? BIO_new(BIO_s_secmem()) : NULL;
    if(b && i2d_PKCS12_bio(b, p12) == 1)
        r = bio_to_secret(b, out);
    BIO_free(b);
    PKCS12_free(p12);
    if(pass)
        OPENSSL_secure_clear_free(pass, pw->len + 1);
    sk_X509_pop_free(chain, X509_free);
    X509_free(caCert);
    X509_free(cert);
    gds_buf_free(&caDer);
    return r;
}

static gds_status issue_new_key(gds_ca *ca, const gds_ca_subject *subj, const gds_ca_keyreq *kr,
                                gds_ca_issued *out, gds_buf *key) {
    EVP_PKEY *k = NULL;
    gds_buf csr = {0};
    gds_status r = new_key(subj->certificateType, &k);
    if(r == GDS_OK)
        r = csr_for(k, &csr);
    if(r == GDS_OK && ca->b.pre_sign)
        r = ca->b.pre_sign(ca->ctx, GDS_CA_OP_NEW_KEY_PAIR, subj);
    if(r == GDS_OK)
        r = ca->b.sign_csr(ca->ctx, subj, &csr, out);
    gds_ca_issuer issuer = GDS_CA_ISSUER_RSA;
    if(r == GDS_OK && !gds_ca_issuer_of(subj->certificateType, &issuer))
        r = GDS_EUNSUPPORTED;
    if(r == GDS_OK)
        r = kr->format == GDS_CA_KEY_PFX ? encode_pfx(ca, issuer, k, &out->der, kr->password, key)
                                         : encode_pem(k, kr->password, key);
    gds_buf_free(&csr);
    EVP_PKEY_free(k);
    return r;
}

gds_status gds_ca_new_key_pair(gds_ca *ca, const gds_ca_subject *subj, const gds_ca_keyreq *kr,
                               gds_ca_issued *out, gds_buf *key) {
    memset(out, 0, sizeof(*out));
    memset(key, 0, sizeof(*key));
    if(!subj || !subj->record || !subj->requestId || !kr ||
       (kr->format != GDS_CA_KEY_PFX && kr->format != GDS_CA_KEY_PEM) ||
       (kr->password && kr->password->len > GDS_MAX_KEY_PASSWORD))
        return GDS_EINVAL;
    gds_status r = ca->b.new_key_pair ? ca->b.new_key_pair(ca->ctx, subj, kr, out, key)
                                      : issue_new_key(ca, subj, kr, out, key);
    if(r != GDS_OK) {
        gds_ca_issued_clear(out);
        gds_buf_free_secret(key);
    }
    return r;
}
