/* OpenGDS - the sealed CA key export; see ca_seal.h.
 * SPDX-License-Identifier: MPL-2.0 */
#define _GNU_SOURCE
#include "ca_seal.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define VERSION 1u
#define HEADER 16u
#define ENC_LEN 32u
#define WRAPPED (GDS_SEAL_KEY_LEN + 16u)
#define RECIPIENT (32u + ENC_LEN + WRAPPED)
#define NONCE 12u
#define TAG 16u
#define RECIPIENTS_FILE_MAX 8192

static const uint8_t MAGIC[4] = {'O', 'G', 'K', 'X'};
static const char INFO[] = "OpenGDS CA key export v1";

static const OSSL_HPKE_SUITE SUITE = {OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256,
                                      OSSL_HPKE_AEAD_ID_AES_GCM_256};

static void put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}
static void put32(uint8_t *p, uint32_t v) {
    for(int i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (24 - 8 * i));
}
static void put64(uint8_t *p, uint64_t v) {
    for(int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint16_t get16(const uint8_t *p) {
    return (uint16_t)(p[0] << 8 | p[1]);
}
static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for(int i = 0; i < 8; i++)
        v = v << 8 | p[i];
    return v;
}

void gds_seal_contents_clear(gds_seal_contents *c) {
    if(!c)
        return;
    for(size_t i = 0; i < GDS_CA_ISSUERS; i++) {
        gds_buf_free(&c->items[i].cert);
        gds_buf_free_secret(&c->items[i].key);
        gds_buf_free(&c->items[i].crl);
    }
    memset(c, 0, sizeof(*c));
}

/* AES-256-GCM, one shot. */
static bool gcm(bool enc, const uint8_t key[32], const uint8_t nonce[NONCE], const uint8_t *aad,
                size_t aadLen, const uint8_t *in, size_t len, uint8_t *out, uint8_t tag[TAG]) {
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    int n = 0, f = 0;
    bool ok = x && EVP_CipherInit_ex(x, EVP_aes_256_gcm(), NULL, key, nonce, enc ? 1 : 0) == 1 &&
              (aadLen == 0 || EVP_CipherUpdate(x, NULL, &n, aad, (int)aadLen) == 1) &&
              (len == 0 || EVP_CipherUpdate(x, out, &n, in, (int)len) == 1) &&
              (enc || EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_TAG, TAG, tag) == 1) &&
              EVP_CipherFinal_ex(x, out + n, &f) == 1 &&
              (!enc || EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_GET_TAG, TAG, tag) == 1);
    EVP_CIPHER_CTX_free(x);
    return ok;
}

static bool item_ok(const gds_seal_item *it) {
    return (unsigned)it->issuer < GDS_CA_ISSUERS && it->cert.len != 0 && it->key.len != 0 &&
           it->cert.len <= GDS_SEAL_MAX_ITEM && it->key.len <= GDS_SEAL_MAX_ITEM &&
           it->crl.len <= GDS_SEAL_MAX_ITEM;
}

/* The plaintext's length, 0 for contents that cannot be sealed. */
static size_t plain_len(const gds_seal_contents *c) {
    if(!c || c->n == 0 || c->n > GDS_CA_ISSUERS)
        return 0;
    size_t pt = 1;
    for(size_t i = 0; i < c->n; i++) {
        if(!item_ok(&c->items[i]))
            return 0;
        pt += 1 + 12 + c->items[i].cert.len + c->items[i].key.len + c->items[i].crl.len;
    }
    return pt;
}

static void write_plain(const gds_seal_contents *c, uint8_t *plain) {
    size_t o = 0;
    plain[o++] = (uint8_t)c->n;
    for(size_t i = 0; i < c->n; i++) {
        const gds_seal_item *it = &c->items[i];
        plain[o++] = (uint8_t)it->issuer;
        const gds_buf *parts[3] = {&it->cert, &it->key, &it->crl};
        for(int k = 0; k < 3; k++) {
            put32(plain + o, (uint32_t)parts[k]->len);
            o += 4;
            if(parts[k]->len)
                memcpy(plain + o, parts[k]->data, parts[k]->len);
            o += parts[k]->len;
        }
    }
}

static bool repeated(const uint8_t (*keys)[32], size_t i) {
    for(size_t j = 0; j < i; j++)
        if(memcmp(keys[j], keys[i], 32) == 0)
            return true;
    return false;
}

/* One recipient's entry: its key, the HPKE enc and the wrapped cek. The
 * header must already be in blob (it is part of the aad). */
static gds_status wrap_for(const uint8_t *header, const uint8_t pub[32],
                           const uint8_t cek[GDS_SEAL_KEY_LEN], uint8_t *rp) {
    uint8_t aad[HEADER + 32];
    memcpy(aad, header, HEADER);
    memcpy(aad + HEADER, pub, 32);
    memcpy(rp, pub, 32);
    OSSL_HPKE_CTX *h =
        OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, SUITE, OSSL_HPKE_ROLE_SENDER, NULL, NULL);
    size_t encLen = ENC_LEN, ctLen = WRAPPED;
    bool ok = h &&
              OSSL_HPKE_encap(h, rp + 32, &encLen, pub, 32, (const unsigned char *)INFO,
                              sizeof(INFO) - 1) == 1 &&
              encLen == ENC_LEN &&
              OSSL_HPKE_seal(h, rp + 32 + ENC_LEN, &ctLen, aad, sizeof(aad), cek,
                             GDS_SEAL_KEY_LEN) == 1 &&
              ctLen == WRAPPED;
    OSSL_HPKE_CTX_free(h);
    return ok ? GDS_OK : GDS_EINVAL; /* e.g. not an X25519 public key */
}

gds_status gds_seal_ca_keys(const gds_seal_contents *c, const uint8_t (*recipients)[32],
                            size_t nRecipients, gds_buf *out) {
    out->data = NULL;
    out->len = 0;
    size_t pt = plain_len(c);
    if(pt == 0 || !recipients || nRecipients == 0 || nRecipients > GDS_SEAL_MAX_RECIPIENTS)
        return GDS_EINVAL;
    size_t pre = HEADER + nRecipients * RECIPIENT, total = pre + NONCE + 4 + pt + TAG;
    if(total > GDS_SEAL_MAX)
        return GDS_ETOOBIG;
    uint8_t *plain = OPENSSL_secure_malloc(pt), *blob = malloc(total);
    uint8_t cek[GDS_SEAL_KEY_LEN];
    gds_status r = plain && blob ? GDS_OK : GDS_ENOMEM;
    if(r == GDS_OK) {
        write_plain(c, plain);
        memcpy(blob, MAGIC, 4);
        put16(blob + 4, VERSION);
        put16(blob + 6, (uint16_t)nRecipients);
        put64(blob + 8, (uint64_t)c->created);
        r = RAND_priv_bytes(cek, sizeof(cek)) == 1 ? GDS_OK : GDS_ECRYPTO;
    }
    for(size_t i = 0; r == GDS_OK && i < nRecipients; i++)
        r = repeated(recipients, i)
                ? GDS_EINVAL
                : wrap_for(blob, recipients[i], cek, blob + HEADER + i * RECIPIENT);
    uint8_t *nonce = blob + pre;
    if(r == GDS_OK && RAND_bytes(nonce, NONCE) != 1)
        r = GDS_ECRYPTO;
    if(r == GDS_OK) {
        put32(nonce + NONCE, (uint32_t)pt);
        uint8_t *ct = nonce + NONCE + 4;
        if(!gcm(true, cek, nonce, blob, pre, plain, pt, ct, ct + pt))
            r = GDS_ECRYPTO;
    }
    OPENSSL_cleanse(cek, sizeof(cek));
    if(plain)
        OPENSSL_cleanse(plain, pt);
    OPENSSL_secure_free(plain);
    if(r != GDS_OK) {
        free(blob);
        return r;
    }
    out->data = blob;
    out->len = total;
    return GDS_OK;
}

static gds_status take(const uint8_t **p, const uint8_t *end, gds_buf *out) {
    if(end - *p < 4)
        return GDS_EINVAL;
    uint32_t n = get32(*p);
    *p += 4;
    if(n > GDS_SEAL_MAX_ITEM || (size_t)(end - *p) < n)
        return GDS_EINVAL;
    out->data = NULL;
    out->len = 0;
    if(n) {
        out->data = malloc(n);
        if(!out->data)
            return GDS_ENOMEM;
        memcpy(out->data, *p, n);
        out->len = n;
    }
    *p += n;
    return GDS_OK;
}

/* The content key from this private key's recipient entry; GDS_EDENIED
 * when it is not a recipient or the entry was altered. */
static gds_status unwrap(const uint8_t *blob, size_t nr, const uint8_t priv[32],
                         uint8_t cek[GDS_SEAL_KEY_LEN]) {
    uint8_t aad[HEADER + 32];
    size_t pubLen = 32;
    EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    if(!pk || EVP_PKEY_get_raw_public_key(pk, aad + HEADER, &pubLen) != 1) {
        EVP_PKEY_free(pk);
        return GDS_EINVAL;
    }
    memcpy(aad, blob, HEADER);
    const uint8_t *rp = NULL;
    for(size_t i = 0; i < nr && !rp; i++)
        if(CRYPTO_memcmp(blob + HEADER + i * RECIPIENT, aad + HEADER, 32) == 0)
            rp = blob + HEADER + i * RECIPIENT;
    OSSL_HPKE_CTX *h =
        rp ? OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, SUITE, OSSL_HPKE_ROLE_RECEIVER, NULL, NULL)
           : NULL;
    size_t cekLen = GDS_SEAL_KEY_LEN;
    bool ok = h &&
              OSSL_HPKE_decap(h, rp + 32, ENC_LEN, pk, (const unsigned char *)INFO,
                              sizeof(INFO) - 1) == 1 &&
              OSSL_HPKE_open(h, cek, &cekLen, aad, sizeof(aad), rp + 32 + ENC_LEN, WRAPPED) == 1 &&
              cekLen == GDS_SEAL_KEY_LEN;
    OSSL_HPKE_CTX_free(h);
    EVP_PKEY_free(pk);
    if(!ok)
        OPENSSL_cleanse(cek, GDS_SEAL_KEY_LEN);
    return ok ? GDS_OK : GDS_EDENIED;
}

/* One item of the plaintext; out->n counts it so a failure clears it. */
static gds_status read_item(const uint8_t **p, const uint8_t *end, gds_seal_contents *out) {
    if(*p >= end || **p >= GDS_CA_ISSUERS)
        return GDS_EINVAL;
    gds_seal_item *it = &out->items[out->n];
    it->issuer = (gds_ca_issuer) * (*p)++;
    for(size_t j = 0; j < out->n; j++)
        if(out->items[j].issuer == it->issuer)
            return GDS_EINVAL;
    out->n++;
    gds_status r = take(p, end, &it->cert);
    if(r == GDS_OK)
        r = take(p, end, &it->key);
    if(r == GDS_OK)
        r = take(p, end, &it->crl);
    if(r == GDS_OK && (it->cert.len == 0 || it->key.len == 0))
        r = GDS_EINVAL;
    return r;
}

static gds_status read_plain(const uint8_t *plain, size_t pt, gds_seal_contents *out) {
    const uint8_t *p = plain, *end = plain + pt;
    size_t n = *p++;
    if(n == 0 || n > GDS_CA_ISSUERS)
        return GDS_EINVAL;
    gds_status r = GDS_OK;
    for(size_t i = 0; r == GDS_OK && i < n; i++)
        r = read_item(&p, end, out);
    return r == GDS_OK && p != end ? GDS_EINVAL : r;
}

gds_status gds_seal_open(const uint8_t *blob, size_t len, const uint8_t priv[32],
                         gds_seal_contents *out) {
    memset(out, 0, sizeof(*out));
    if(!blob || len < HEADER || memcmp(blob, MAGIC, 4) != 0 || get16(blob + 4) != VERSION)
        return GDS_EINVAL;
    size_t nr = get16(blob + 6);
    if(nr == 0 || nr > GDS_SEAL_MAX_RECIPIENTS || len < HEADER + nr * RECIPIENT + NONCE + 4 + TAG)
        return GDS_EINVAL;
    size_t pre = HEADER + nr * RECIPIENT;
    const uint8_t *nonce = blob + pre;
    size_t pt = get32(nonce + NONCE);
    if(pt == 0 || pt != len - pre - NONCE - 4 - TAG)
        return GDS_EINVAL;
    uint8_t cek[GDS_SEAL_KEY_LEN];
    gds_status r = unwrap(blob, nr, priv, cek);
    if(r != GDS_OK)
        return r;
    uint8_t *plain = OPENSSL_secure_malloc(pt);
    if(!plain) {
        OPENSSL_cleanse(cek, sizeof(cek));
        return GDS_ENOMEM;
    }
    const uint8_t *ct = nonce + NONCE + 4;
    uint8_t tag[TAG];
    memcpy(tag, ct + pt, TAG);
    r = gcm(false, cek, nonce, blob, pre, ct, pt, plain, tag) ? GDS_OK : GDS_EDENIED;
    OPENSSL_cleanse(cek, sizeof(cek));
    out->created = (int64_t)get64(blob + 8);
    if(r == GDS_OK)
        r = read_plain(plain, pt, out);
    OPENSSL_cleanse(plain, pt);
    OPENSSL_secure_free(plain);
    if(r != GDS_OK)
        gds_seal_contents_clear(out);
    return r;
}

static int hexval(char c) {
    if(c >= '0' && c <= '9')
        return c - '0';
    if(c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

/* The key on one trimmed, non-comment line: 64 hex digits, optionally
 * after one word and spaces. */
static gds_status parse_line(const char *s, const char *e, uint8_t k[32]) {
    if(e - s > 64) {
        const char *sp = memchr(s, ' ', (size_t)(e - s));
        if(!sp)
            return GDS_EINVAL;
        s = sp + 1;
        while(s < e && *s == ' ')
            s++;
    }
    if(e - s != 64)
        return GDS_EINVAL;
    for(size_t i = 0; i < 32; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if(hi < 0 || lo < 0)
            return GDS_EINVAL;
        k[i] = (uint8_t)(hi << 4 | lo);
    }
    return GDS_OK;
}

static bool blank(char c) {
    return c == ' ' || c == '\t' || c == '\r';
}

gds_status gds_seal_recipients_parse(const char *text, size_t len, uint8_t (*out)[32], size_t cap,
                                     size_t *n) {
    *n = 0;
    if(!text || memchr(text, 0, len))
        return GDS_EINVAL;
    const char *p = text, *end = text + len;
    while(p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *s = p, *e = nl ? nl : end;
        p = nl ? nl + 1 : end;
        while(s < e && blank(*s))
            s++;
        while(e > s && blank(e[-1]))
            e--;
        if(s == e || *s == '#')
            continue;
        if(*n == cap)
            return GDS_ETOOBIG;
        gds_status r = parse_line(s, e, out[*n]);
        if(r != GDS_OK)
            return r;
        if(repeated((const uint8_t (*)[32])out, *n))
            return GDS_EINVAL;
        (*n)++;
    }
    return *n ? GDS_OK : GDS_EINVAL;
}

gds_status gds_seal_recipients_read(const char *path, uint8_t (*out)[32], size_t cap, size_t *n) {
    *n = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if(fd < 0)
        return errno == ENOENT ? GDS_ENOTFOUND : errno == ELOOP ? GDS_EDENIED : GDS_EIO;
    struct stat st;
    char buf[RECIPIENTS_FILE_MAX];
    if(fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022) ||
       st.st_size > (off_t)sizeof(buf)) {
        close(fd);
        return GDS_EDENIED;
    }
    size_t len = 0;
    while(len < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + len, (size_t)st.st_size - len);
        if(r < 0 && errno == EINTR)
            continue;
        if(r <= 0)
            break;
        len += (size_t)r;
    }
    close(fd);
    if(len != (size_t)st.st_size)
        return GDS_EIO;
    return gds_seal_recipients_parse(buf, len, out, cap, n);
}
