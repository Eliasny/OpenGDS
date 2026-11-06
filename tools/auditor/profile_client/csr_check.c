/* OpenGDS Auditor client profile - CSR inspection. See csr_check.h.
 * SPDX-License-Identifier: MPL-2.0 */
#include "csr_check.h"

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string.h>

#include "common/limits.h"
#include "common/banned.h"

#define SCAN_MAX ((size_t)64 * 1024)

static void copy_name(char *dst, const ASN1_IA5STRING *s) {
    int n = ASN1_STRING_length(s);
    if(n < 0)
        n = 0;
    if(n > CSR_MAX_NAME - 1)
        n = CSR_MAX_NAME - 1;
    memcpy(dst, ASN1_STRING_get0_data(s), (size_t)n);
    dst[n] = '\0';
}

static void read_san(X509_REQ *req, csr_info *out) {
    STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req);
    if(!exts)
        return;
    GENERAL_NAMES *names = X509V3_get_d2i(exts, NID_subject_alt_name, NULL, NULL);
    for(int i = 0; names && i < sk_GENERAL_NAME_num(names); i++) {
        const GENERAL_NAME *g = sk_GENERAL_NAME_value(names, i);
        if(g->type == GEN_URI && out->uriN < CSR_MAX_NAMES)
            copy_name(out->uris[out->uriN++], g->d.uniformResourceIdentifier);
        else if(g->type == GEN_DNS && out->dnsN < CSR_MAX_NAMES)
            copy_name(out->dns[out->dnsN++], g->d.dNSName);
    }
    GENERAL_NAMES_free(names);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
}

static void read_key(EVP_PKEY *pk, csr_info *out) {
    out->keyType = EVP_PKEY_get_base_id(pk);
    out->bits = EVP_PKEY_get_bits(pk);
    size_t len = 0;
    if(out->keyType == EVP_PKEY_EC &&
       EVP_PKEY_get_utf8_string_param(pk, OSSL_PKEY_PARAM_GROUP_NAME, out->curve,
                                      sizeof(out->curve), &len) != 1)
        out->curve[0] = '\0';
    unsigned char *p = NULL;
    int n = i2d_PUBKEY(pk, &p);
    if(n > 0 && gds_buf_dup(p, (size_t)n, &out->pubDer) != GDS_OK)
        out->pubDer.len = 0;
    OPENSSL_free(p);
}

void csr_inspect(const gds_buf *csr, csr_info *out) {
    memset(out, 0, sizeof(*out));
    if(!csr->data || csr->len == 0 || csr->len > GDS_MAX_CSR_SIZE)
        return;
    const unsigned char *p = csr->data;
    X509_REQ *req = d2i_X509_REQ(NULL, &p, (long)csr->len);
    if(!req) {
        ERR_clear_error();
        return;
    }
    out->parsed = true;
    EVP_PKEY *pk = X509_REQ_get_pubkey(req);
    if(pk) {
        out->signatureOk = X509_REQ_verify(req, pk) == 1;
        read_key(pk, out);
        EVP_PKEY_free(pk);
    }
    read_san(req, out);
    X509_REQ_free(req);
    ERR_clear_error();
}

void csr_info_clear(csr_info *info) {
    gds_buf_free(&info->pubDer);
    memset(info, 0, sizeof(*info));
}

static bool key_is(EVP_PKEY *k, const gds_buf *pubDer) {
    unsigned char *p = NULL;
    int n = i2d_PUBKEY(k, &p);
    bool same = n > 0 && (size_t)n == pubDer->len && memcmp(p, pubDer->data, pubDer->len) == 0;
    OPENSSL_free(p);
    return same;
}

static bool der_key_at(const uint8_t *data, size_t len, const gds_buf *pubDer) {
    const unsigned char *p = data;
    EVP_PKEY *k = d2i_AutoPrivateKey(NULL, &p, (long)len);
    if(!k)
        return false;
    bool hit = key_is(k, pubDer);
    EVP_PKEY_free(k);
    return hit;
}

static bool pem_key_at(const uint8_t *data, size_t len, const gds_buf *pubDer) {
    BIO *bio = BIO_new_mem_buf(data, (int)len);
    if(!bio)
        return false;
    EVP_PKEY *k = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if(!k)
        return false;
    bool hit = key_is(k, pubDer);
    EVP_PKEY_free(k);
    return hit;
}

bool csr_blob_has_private_key(const gds_buf *blob, const gds_buf *pubDer) {
    if(!blob->data || !pubDer->data || pubDer->len == 0)
        return false;
    size_t n = blob->len < SCAN_MAX ? blob->len : SCAN_MAX;
    static const char pem[] = "-----BEGIN";
    bool hit = false;
    for(size_t i = 0; i + 4 < n && !hit; i++) {
        /* a DER key starts with SEQUENCE and a long-form length */
        if(blob->data[i] == 0x30 && blob->data[i + 1] == 0x82)
            hit = der_key_at(blob->data + i, n - i, pubDer);
        else if(blob->data[i] == '-' && n - i > sizeof(pem) &&
                memcmp(blob->data + i, pem, sizeof(pem) - 1) == 0)
            hit = pem_key_at(blob->data + i, n - i, pubDer);
    }
    ERR_clear_error();
    return hit;
}
