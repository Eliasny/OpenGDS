/* OpenGDS - RsaEncryptedSecret (see enc_secret.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include "enc_secret.h"

#include <open62541/types.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <string.h>

#include "safeint.h"
#include "banned.h"

#define TYPE_ID_RSA_ENCRYPTED_SECRET 17545u /* ns=0, the DataType node */
#define SIG_KEY_LEN 32                      /* HMAC-SHA256 key and signature */
#define SIG_LEN 32
#define IV_LEN 16 /* AES block */
#define NONCE_LEN 32
#define MAX_BLOB (GDS_MAX_SECRET + 4096 + 1024)

typedef struct {
    const char *uri;
    size_t encKeyLen; /* AES-128 or AES-256 */
    bool oaepSha256;  /* else OAEP with SHA1 */
    int minBits, maxBits;
} policy;

static const policy policies[] = {
    {GDS_POLICY_BASIC256SHA256, 32, false, 2048, 4096},
    {GDS_POLICY_AES128_RSAOAEP, 16, false, 2048, 4096},
    {GDS_POLICY_AES256_RSAPSS, 32, true, 2048, 4096},
};

static const policy *find_policy(const char *uri, size_t len) {
    for(size_t i = 0; uri && i < sizeof(policies) / sizeof(policies[0]); i++)
        if(strlen(policies[i].uri) == len && memcmp(policies[i].uri, uri, len) == 0)
            return &policies[i];
    return NULL;
}

bool gds_enc_secret_policy_ok(const char *uri, size_t len) {
    return find_policy(uri, len) != NULL;
}

/* ---- UA Binary writers on a gds_buf ---- */

static gds_status put(gds_buf *b, const void *p, size_t n) {
    return gds_buf_append(b, p, n, MAX_BLOB);
}
static gds_status put_u16(gds_buf *b, uint16_t v) {
    uint8_t x[2] = {(uint8_t)v, (uint8_t)(v >> 8)};
    return put(b, x, 2);
}
static gds_status put_u32(gds_buf *b, uint32_t v) {
    uint8_t x[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
    return put(b, x, 4);
}
static gds_status put_i64(gds_buf *b, int64_t v) {
    uint64_t u = (uint64_t)v;
    uint8_t x[8];
    for(int i = 0; i < 8; i++)
        x[i] = (uint8_t)(u >> (8 * i));
    return put(b, x, 8);
}
static gds_status put_bytes(gds_buf *b, const void *p, size_t n) { /* ByteString / String */
    if(n > INT32_MAX)
        return GDS_ETOOBIG;
    gds_status r = put_u32(b, (uint32_t)n);
    return r == GDS_OK && n ? put(b, p, n) : r;
}

/* ---- readers ---- */

typedef struct {
    const uint8_t *p;
    size_t len, pos;
} rd;

static bool get(rd *r, size_t n, const uint8_t **out) {
    if(n > r->len - r->pos)
        return false;
    *out = r->p + r->pos;
    r->pos += n;
    return true;
}
static bool get_u16(rd *r, uint16_t *v) {
    const uint8_t *x;
    if(!get(r, 2, &x))
        return false;
    *v = (uint16_t)(x[0] | (x[1] << 8));
    return true;
}
static bool get_u32(rd *r, uint32_t *v) {
    const uint8_t *x;
    if(!get(r, 4, &x))
        return false;
    *v = (uint32_t)x[0] | ((uint32_t)x[1] << 8) | ((uint32_t)x[2] << 16) | ((uint32_t)x[3] << 24);
    return true;
}
/* A ByteString: -1 (null) reads as empty. */
static bool get_bytes(rd *r, const uint8_t **p, size_t *n) {
    uint32_t l;
    if(!get_u32(r, &l))
        return false;
    if(l == UINT32_MAX) {
        *p = NULL;
        *n = 0;
        return true;
    }
    *n = l;
    return get(r, l, p);
}

/* ---- crypto pieces ---- */

static EVP_PKEY *cert_key(const gds_buf *der, X509 **cert) {
    const unsigned char *p = der->data;
    *cert = der->len && der->len <= LONG_MAX ? d2i_X509(NULL, &p, (long)der->len) : NULL;
    if(!*cert || p != der->data + der->len) {
        X509_free(*cert);
        *cert = NULL;
        return NULL;
    }
    return X509_get0_pubkey(*cert);
}

static bool key_fits(const policy *pol, EVP_PKEY *k) {
    int bits = EVP_PKEY_get_bits(k);
    return EVP_PKEY_is_a(k, "RSA") && bits >= pol->minBits && bits <= pol->maxBits;
}

static gds_status sha1(const gds_buf *der, uint8_t out[20]) {
    unsigned int n = 0;
    return EVP_Digest(der->data, der->len, out, &n, EVP_sha1(), NULL) == 1 && n == 20
               ? GDS_OK
               : GDS_ECRYPTO;
}

gds_status gds_sha1_hex(const gds_buf *certDer, char out[GDS_SHA1_HEX]) {
    uint8_t h[20];
    gds_status r = sha1(certDer, h);
    return r == GDS_OK ? gds_hex(h, sizeof(h), out, GDS_SHA1_HEX) : r;
}

static EVP_PKEY_CTX *oaep_ctx(const policy *pol, EVP_PKEY *k, bool encrypt) {
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    const EVP_MD *md = pol->oaepSha256 ? EVP_sha256() : EVP_sha1();
    bool ok = c && (encrypt ? EVP_PKEY_encrypt_init(c) : EVP_PKEY_decrypt_init(c)) == 1 &&
              EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_OAEP_PADDING) == 1 &&
              EVP_PKEY_CTX_set_rsa_oaep_md(c, md) == 1 && EVP_PKEY_CTX_set_rsa_mgf1_md(c, md) == 1;
    if(!ok) {
        EVP_PKEY_CTX_free(c);
        return NULL;
    }
    return c;
}

static gds_status aes_cbc(const policy *pol, bool encrypt, const uint8_t *key, const uint8_t *iv,
                          uint8_t *data, size_t len) {
    const EVP_CIPHER *ci = pol->encKeyLen == 16 ? EVP_aes_128_cbc() : EVP_aes_256_cbc();
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int outl = 0, fin = 0;
    bool ok = c && len % IV_LEN == 0 && len <= INT32_MAX &&
              EVP_CipherInit_ex(c, ci, NULL, key, iv, encrypt ? 1 : 0) == 1 &&
              EVP_CIPHER_CTX_set_padding(c, 0) == 1 &&
              EVP_CipherUpdate(c, data, &outl, data, (int)len) == 1 &&
              EVP_CipherFinal_ex(c, data + outl, &fin) == 1 && (size_t)outl + (size_t)fin == len;
    EVP_CIPHER_CTX_free(c);
    return ok ? GDS_OK : GDS_ECRYPTO;
}

static gds_status hmac(const uint8_t *key, const uint8_t *data, size_t len, uint8_t out[SIG_LEN]) {
    size_t n = 0;
    return EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, key, SIG_KEY_LEN, data, len, out, SIG_LEN,
                     &n) && n == SIG_LEN
               ? GDS_OK
               : GDS_ECRYPTO;
}

gds_status gds_enc_secret_check(const char *policyUri, size_t policyLen, const gds_buf *certDer) {
    const policy *pol = find_policy(policyUri, policyLen);
    if(!pol)
        return GDS_EUNSUPPORTED;
    X509 *cert = NULL;
    EVP_PKEY *pub = certDer ? cert_key(certDer, &cert) : NULL;
    gds_status r = !cert ? GDS_EINVAL : !pub || !key_fits(pol, pub) ? GDS_ESTATE : GDS_OK;
    X509_free(cert);
    return r;
}

/* ---- encrypt ---- */

/* KeyData (SigningKey, EncryptingKey, InitializationVector) encrypted with
 * the receiver's public key into *enc (OPENSSL_malloc'd). */
static gds_status key_data(const policy *pol, EVP_PKEY *pub, const uint8_t *sigKey,
                           const uint8_t *encKey, const uint8_t *iv, gds_buf *enc) {
    gds_buf kd = {0};
    EVP_PKEY_CTX *pc = NULL;
    size_t ekLen = 0;
    gds_status r = put_bytes(&kd, sigKey, SIG_KEY_LEN);
    if(r == GDS_OK)
        r = put_bytes(&kd, encKey, pol->encKeyLen);
    if(r == GDS_OK)
        r = put_bytes(&kd, iv, IV_LEN);
    if(r == GDS_OK) {
        pc = oaep_ctx(pol, pub, true);
        r = pc && EVP_PKEY_encrypt(pc, NULL, &ekLen, kd.data, kd.len) == 1 && ekLen <= UINT16_MAX
                ? GDS_OK
                : GDS_ECRYPTO;
    }
    if(r == GDS_OK)
        r = (enc->data = OPENSSL_malloc(ekLen)) != NULL ? GDS_OK : GDS_ENOMEM;
    if(r == GDS_OK)
        r = EVP_PKEY_encrypt(pc, enc->data, &ekLen, kd.data, kd.len) == 1 ? GDS_OK : GDS_ECRYPTO;
    enc->len = r == GDS_OK ? ekLen : 0;
    gds_buf_free_secret(&kd);
    EVP_PKEY_CTX_free(pc);
    return r;
}

/* Nonce, Secret, padding, PaddingSize, encrypted in place. */
static gds_status payload_of(const policy *pol, const uint8_t *encKey, const uint8_t *iv,
                             const gds_buf *secret, gds_buf *payload) {
    uint8_t nonce[NONCE_LEN];
    gds_status r = RAND_bytes(nonce, NONCE_LEN) == 1 ? GDS_OK : GDS_ECRYPTO;
    if(r == GDS_OK)
        r = put_bytes(payload, nonce, NONCE_LEN);
    if(r == GDS_OK)
        r = put_bytes(payload, secret->data, secret->len);
    size_t pad = (IV_LEN - (payload->len + 2) % IV_LEN) % IV_LEN;
    uint8_t p[IV_LEN];
    memset(p, (int)(pad & 0xFF), sizeof(p));
    if(r == GDS_OK)
        r = put(payload, p, pad);
    if(r == GDS_OK)
        r = put_u16(payload, (uint16_t)pad);
    if(r == GDS_OK)
        r = aes_cbc(pol, true, encKey, iv, payload->data, payload->len);
    OPENSSL_cleanse(nonce, sizeof(nonce));
    return r;
}

/* The header and both encrypted parts; *lenPos is the Length field. */
static gds_status body_of(const policy *pol, const uint8_t thumb[20], const gds_buf *enc,
                          const gds_buf *payload, gds_buf *out, size_t *lenPos) {
    static const uint8_t typeId[4] = {0x01, 0x00, (uint8_t)(TYPE_ID_RSA_ENCRYPTED_SECRET & 0xFF),
                                      (uint8_t)(TYPE_ID_RSA_ENCRYPTED_SECRET >> 8)};
    static const uint8_t mask = 1;
    gds_status r = put(out, typeId, sizeof(typeId));
    if(r == GDS_OK)
        r = put(out, &mask, 1);
    *lenPos = out->len;
    if(r == GDS_OK)
        r = put_u32(out, 0);
    if(r == GDS_OK)
        r = put_bytes(out, pol->uri, strlen(pol->uri));
    if(r == GDS_OK)
        r = put_bytes(out, thumb, 20);
    if(r == GDS_OK)
        r = put_i64(out, UA_DateTime_now());
    if(r == GDS_OK)
        r = put_u16(out, (uint16_t)enc->len);
    if(r == GDS_OK)
        r = put(out, enc->data, enc->len);
    if(r == GDS_OK)
        r = put(out, payload->data, payload->len);
    return r;
}

/* Fills in Length and appends the HMAC. */
static gds_status sign_body(const uint8_t *sigKey, size_t lenPos, gds_buf *out) {
    size_t after = out->len + SIG_LEN - (lenPos + 4);
    if(after > INT32_MAX)
        return GDS_ETOOBIG;
    for(int i = 0; i < 4; i++)
        out->data[lenPos + (size_t)i] = (uint8_t)(after >> (8 * i));
    uint8_t sig[SIG_LEN];
    gds_status r = hmac(sigKey, out->data, out->len, sig);
    return r == GDS_OK ? put(out, sig, SIG_LEN) : r;
}

gds_status gds_enc_secret_rsa(const char *policyUri, size_t policyLen, const gds_buf *certDer,
                              const gds_buf *secret, gds_buf *out) {
    memset(out, 0, sizeof(*out));
    const policy *pol = find_policy(policyUri, policyLen);
    if(!pol)
        return GDS_EUNSUPPORTED;
    if(!secret || !secret->data || secret->len == 0 || secret->len > GDS_MAX_SECRET)
        return GDS_EINVAL;
    X509 *cert = NULL;
    EVP_PKEY *pub = cert_key(certDer, &cert);
    if(!pub || !key_fits(pol, pub)) {
        X509_free(cert);
        return GDS_EINVAL;
    }
    uint8_t keys[SIG_KEY_LEN + 32 + IV_LEN], thumb[20];
    uint8_t *sigKey = keys, *encKey = keys + SIG_KEY_LEN, *iv = keys + SIG_KEY_LEN + pol->encKeyLen;
    gds_buf payload = {0}, enc = {0};
    size_t lenPos = 0;
    gds_status r = RAND_bytes(keys, (int)sizeof(keys)) == 1 ? GDS_OK : GDS_ECRYPTO;
    if(r == GDS_OK)
        r = sha1(certDer, thumb);
    if(r == GDS_OK)
        r = key_data(pol, pub, sigKey, encKey, iv, &enc);
    if(r == GDS_OK)
        r = payload_of(pol, encKey, iv, secret, &payload);
    if(r == GDS_OK)
        r = body_of(pol, thumb, &enc, &payload, out, &lenPos);
    if(r == GDS_OK)
        r = sign_body(sigKey, lenPos, out);
    if(r != GDS_OK)
        gds_buf_free(out);
    OPENSSL_cleanse(keys, sizeof(keys));
    gds_buf_free_secret(&payload);
    OPENSSL_free(enc.data);
    X509_free(cert);
    return r;
}

/* ---- decrypt (the receiver's side) ---- */

static gds_status rsa_decrypt(const policy *pol, EVP_PKEY *key, const uint8_t *in, size_t len,
                              uint8_t *out, size_t outMax, size_t *outLen) {
    size_t block = (size_t)EVP_PKEY_get_size(key);
    *outLen = 0;
    if(block == 0 || len == 0 || len % block)
        return GDS_EINVAL;
    EVP_PKEY_CTX *c = oaep_ctx(pol, key, false);
    gds_status r = c ? GDS_OK : GDS_ECRYPTO;
    for(size_t off = 0; r == GDS_OK && off < len; off += block) {
        size_t n = outMax - *outLen;
        if(EVP_PKEY_decrypt(c, out + *outLen, &n, in + off, block) != 1)
            r = GDS_EINVAL;
        else
            *outLen += n;
    }
    EVP_PKEY_CTX_free(c);
    return r;
}

/* The fields before the payload: type, policy, certificate hash; *ek the
 * encrypted KeyData, r->pos at the payload, *sigStart at the signature. */
static gds_status read_header(const policy *pol, const gds_buf *certDer, const gds_buf *blob,
                              rd *r, size_t *sigStart, const uint8_t **ek, uint16_t *ekLen) {
    const uint8_t *typeId, *x, *uri, *thumb;
    size_t uriLen, thumbLen;
    uint32_t length;
    if(!get(r, 4, &typeId) || typeId[0] != 0x01 || typeId[1] != 0 ||
       (typeId[2] | (typeId[3] << 8)) != (int)TYPE_ID_RSA_ENCRYPTED_SECRET || !get(r, 1, &x) ||
       *x != 1 || !get_u32(r, &length) || length != r->len - r->pos || length < SIG_LEN)
        return GDS_EINVAL;
    *sigStart = blob->len - SIG_LEN;
    r->len = *sigStart; /* the fields end where the signature starts */
    if(!get_bytes(r, &uri, &uriLen) || !uri || uriLen != strlen(pol->uri) ||
       memcmp(uri, pol->uri, uriLen) != 0 || !get_bytes(r, &thumb, &thumbLen))
        return GDS_EINVAL;
    uint8_t want[20];
    if(sha1(certDer, want) != GDS_OK ||
       (thumbLen && (!thumb || thumbLen != 20 || memcmp(thumb, want, 20) != 0)))
        return GDS_EINVAL;
    return get(r, 8, &x) && get_u16(r, ekLen) && get(r, *ekLen, ek) ? GDS_OK : GDS_EINVAL;
}

/* The decrypted payload pl: Nonce, Secret, padding, PaddingSize. */
static gds_status read_payload(const gds_buf *pl, gds_buf *secret) {
    rd p = {pl->data, pl->len, 0};
    const uint8_t *nonce, *sec;
    size_t nl, secLen;
    uint16_t pad = (uint16_t)(pl->data[pl->len - 2] | (pl->data[pl->len - 1] << 8));
    if(!get_bytes(&p, &nonce, &nl) || !get_bytes(&p, &sec, &secLen) || !sec ||
       p.len - p.pos != (size_t)pad + 2 || secLen == 0 || secLen > GDS_MAX_SECRET)
        return GDS_EINVAL;
    for(size_t i = 0; i < pad; i++)
        if(pl->data[p.pos + i] != (uint8_t)(pad & 0xFF))
            return GDS_EINVAL;
    return gds_buf_dup(sec, secLen, secret);
}

gds_status gds_enc_secret_rsa_decrypt(const char *policyUri, size_t policyLen,
                                      const gds_buf *certDer, EVP_PKEY *key, const gds_buf *blob,
                                      gds_buf *secret) {
    memset(secret, 0, sizeof(*secret));
    const policy *pol = find_policy(policyUri, policyLen);
    if(!pol)
        return GDS_EUNSUPPORTED;
    if(!blob || !blob->data || blob->len > MAX_BLOB || !key || !EVP_PKEY_is_a(key, "RSA"))
        return GDS_EINVAL;
    rd r = {blob->data, blob->len, 0};
    size_t sigStart = 0;
    const uint8_t *ek = NULL;
    uint16_t ekLen = 0;
    gds_status st = read_header(pol, certDer, blob, &r, &sigStart, &ek, &ekLen);
    uint8_t kd[1024], sig[SIG_LEN];
    size_t kdLen = 0;
    if(st == GDS_OK)
        st = rsa_decrypt(pol, key, ek, ekLen, kd, sizeof(kd), &kdLen);
    rd k = {kd, kdLen, 0};
    const uint8_t *sigKey = NULL, *encKey = NULL, *iv = NULL;
    size_t sl = 0, el = 0, il = 0;
    if(st == GDS_OK &&
       (!get_bytes(&k, &sigKey, &sl) || !get_bytes(&k, &encKey, &el) || !get_bytes(&k, &iv, &il) ||
        k.pos != k.len || sl != SIG_KEY_LEN || el != pol->encKeyLen || il != IV_LEN))
        st = GDS_EINVAL;
    if(st == GDS_OK)
        st = hmac(sigKey, blob->data, sigStart, sig);
    if(st == GDS_OK && CRYPTO_memcmp(sig, blob->data + sigStart, SIG_LEN) != 0)
        st = GDS_EINVAL;
    gds_buf pl = {0};
    size_t plLen = st == GDS_OK ? sigStart - r.pos : 0;
    if(st == GDS_OK && (plLen < 2 || plLen % IV_LEN))
        st = GDS_EINVAL;
    if(st == GDS_OK)
        st = gds_buf_dup(blob->data + r.pos, plLen, &pl);
    if(st == GDS_OK)
        st = aes_cbc(pol, false, encKey, iv, pl.data, pl.len);
    if(st == GDS_OK)
        st = read_payload(&pl, secret);
    gds_buf_free_secret(&pl);
    OPENSSL_cleanse(kd, sizeof(kd));
    return st;
}
