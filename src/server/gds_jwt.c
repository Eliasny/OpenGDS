/* OpenGDS - JSON Web Tokens for the AuthorizationService (gds_jwt.h).
 *
 * The token is a JWS in compact serialization (RFC 7515 §7.1): base64url
 * of the header, '.', base64url of the claims, '.', base64url of the
 * signature over the first two parts. The claims are those of OPC 10000-6
 * §6.5.2.3 Table 56 (sub, iss, aud, exp, nbf, roles, cnf) plus iat and jti
 * of RFC 7519 §4.1. Every string is escaped as RFC 8259 §7 asks.
 * SPDX-License-Identifier: MPL-2.0 */
#include "gds_jwt.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/banned.h"

#define MAX_TOKEN ((size_t)16384)
#define MAX_PART  ((size_t)8192)

static const char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

gds_status gds_b64url(const uint8_t *in, size_t n, gds_buf *out) {
    memset(out, 0, sizeof(*out));
    if(n > MAX_TOKEN)
        return GDS_ETOOBIG;
    size_t len = (n / 3) * 4 + (n % 3 ? n % 3 + 1 : 0);
    out->data = malloc(len + 1);
    if(!out->data)
        return GDS_ENOMEM;
    size_t o = 0, i = 0;
    for(; i + 3 <= n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8 | in[i + 2];
        out->data[o++] = (uint8_t)alphabet[v >> 18 & 63];
        out->data[o++] = (uint8_t)alphabet[v >> 12 & 63];
        out->data[o++] = (uint8_t)alphabet[v >> 6 & 63];
        out->data[o++] = (uint8_t)alphabet[v & 63];
    }
    if(n - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out->data[o++] = (uint8_t)alphabet[v >> 18 & 63];
        out->data[o++] = (uint8_t)alphabet[v >> 12 & 63];
    } else if(n - i == 2) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8;
        out->data[o++] = (uint8_t)alphabet[v >> 18 & 63];
        out->data[o++] = (uint8_t)alphabet[v >> 12 & 63];
        out->data[o++] = (uint8_t)alphabet[v >> 6 & 63];
    }
    out->data[o] = 0;
    out->len = o;
    return GDS_OK;
}

static int unb64(char c) {
    if(c >= 'A' && c <= 'Z')
        return c - 'A';
    if(c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if(c >= '0' && c <= '9')
        return c - '0' + 52;
    if(c == '-')
        return 62;
    if(c == '_')
        return 63;
    return -1;
}

gds_status gds_b64url_decode(const char *in, size_t n, gds_buf *out) {
    memset(out, 0, sizeof(*out));
    if(n > MAX_TOKEN)
        return GDS_ETOOBIG;
    if(n % 4 == 1)
        return GDS_EINVAL;
    out->data = malloc(n / 4 * 3 + 3);
    if(!out->data)
        return GDS_ENOMEM;
    uint32_t acc = 0;
    unsigned bits = 0;
    size_t o = 0;
    for(size_t i = 0; i < n; i++) {
        int v = unb64(in[i]);
        if(v < 0) {
            gds_buf_free(out);
            return GDS_EINVAL;
        }
        acc = acc << 6 | (uint32_t)v;
        bits += 6;
        if(bits >= 8) {
            bits -= 8;
            out->data[o++] = (uint8_t)(acc >> bits);
            acc &= (1u << bits) - 1;
        }
    }
    if(acc != 0) { /* non-canonical trailing bits */
        gds_buf_free(out);
        return GDS_EINVAL;
    }
    out->len = o;
    return GDS_OK;
}

/* ---- a small JSON writer ---- */

typedef struct {
    gds_buf b;
    gds_status st;
} jw;

static void put(jw *w, const char *s, size_t n) {
    if(w->st == GDS_OK)
        w->st = gds_buf_append(&w->b, s, n, MAX_PART);
}

static void puts_(jw *w, const char *s) {
    put(w, s, strlen(s));
}

static void put_str(jw *w, const char *s) {
    puts_(w, "\"");
    for(const unsigned char *p = (const unsigned char *)s; *p && w->st == GDS_OK; p++) {
        char esc[8];
        if(*p == '"' || *p == '\\') {
            esc[0] = '\\';
            esc[1] = (char)*p;
            put(w, esc, 2);
        } else if(*p < 0x20) {
            int k = snprintf(esc, sizeof(esc), "\\u%04x", (unsigned)*p);
            put(w, esc, (size_t)k);
        } else {
            put(w, (const char *)p, 1);
        }
    }
    puts_(w, "\"");
}

static void put_member(jw *w, bool *first, const char *name) {
    puts_(w, *first ? "" : ",");
    *first = false;
    put_str(w, name);
    puts_(w, ":");
}

static void put_num(jw *w, int64_t v) {
    char n[32];
    int k = snprintf(n, sizeof(n), "%" PRId64, v);
    put(w, n, (size_t)k);
}

static void put_b64(jw *w, const uint8_t *d, size_t n) {
    gds_buf e = {0};
    if(w->st == GDS_OK)
        w->st = gds_b64url(d, n, &e);
    if(w->st == GDS_OK) {
        puts_(w, "\"");
        put(w, (const char *)e.data, e.len);
        puts_(w, "\"");
    }
    gds_buf_free(&e);
}

static gds_status header_json(const char *alg, const uint8_t *x5t, gds_buf *out) {
    jw w = {{0}, GDS_OK};
    bool first = true;
    puts_(&w, "{");
    put_member(&w, &first, "alg");
    put_str(&w, alg);
    put_member(&w, &first, "typ");
    put_str(&w, "JWT");
    put_member(&w, &first, "x5t#S256");
    put_b64(&w, x5t, GDS_JWT_THUMBPRINT);
    puts_(&w, "}");
    if(w.st != GDS_OK)
        gds_buf_free(&w.b);
    *out = w.b;
    return w.st;
}

static gds_status claims_json(const gds_jwt_claims *c, gds_buf *out) {
    jw w = {{0}, GDS_OK};
    bool first = true;
    puts_(&w, "{");
    put_member(&w, &first, "iss");
    put_str(&w, c->iss);
    put_member(&w, &first, "sub");
    put_str(&w, c->sub);
    put_member(&w, &first, "aud");
    put_str(&w, c->aud);
    put_member(&w, &first, "iat");
    put_num(&w, c->iat);
    put_member(&w, &first, "nbf");
    put_num(&w, c->nbf);
    put_member(&w, &first, "exp");
    put_num(&w, c->exp);
    put_member(&w, &first, "jti");
    put_str(&w, c->jti);
    put_member(&w, &first, "roles");
    puts_(&w, "[");
    for(size_t i = 0; i < c->nRoles; i++) {
        puts_(&w, i ? "," : "");
        put_str(&w, c->roles[i]);
    }
    puts_(&w, "]");
    if(c->cnfThumbprint) {
        put_member(&w, &first, "cnf");
        puts_(&w, "{");
        put_str(&w, "x5t#S256");
        puts_(&w, ":");
        put_b64(&w, c->cnfThumbprint, GDS_JWT_THUMBPRINT);
        puts_(&w, "}");
    }
    puts_(&w, "}");
    if(w.st != GDS_OK)
        gds_buf_free(&w.b);
    *out = w.b;
    return w.st;
}

static bool claims_ok(const gds_jwt_claims *c) {
    if(!c || !c->iss || !*c->iss || !c->sub || !*c->sub || !c->aud || !*c->aud || !c->jti ||
       c->nRoles > GDS_JWT_MAX_ROLES || (c->nRoles && !c->roles) || c->exp <= c->nbf)
        return false;
    for(size_t i = 0; i < c->nRoles; i++)
        if(!c->roles[i] || !*c->roles[i])
            return false;
    return true;
}

gds_status gds_jwt_make(const char *alg, const uint8_t x5t[GDS_JWT_THUMBPRINT],
                        const gds_jwt_claims *c, gds_jwt_sign_fn sign, void *signCtx,
                        gds_buf *out) {
    memset(out, 0, sizeof(*out));
    if(!alg || !*alg || !x5t || !sign || !claims_ok(c))
        return GDS_EINVAL;
    gds_buf h = {0}, p = {0}, hb = {0}, pb = {0}, sig = {0}, sb = {0}, input = {0};
    gds_status st = header_json(alg, x5t, &h);
    if(st == GDS_OK)
        st = claims_json(c, &p);
    if(st == GDS_OK)
        st = gds_b64url(h.data, h.len, &hb);
    if(st == GDS_OK)
        st = gds_b64url(p.data, p.len, &pb);
    if(st == GDS_OK)
        st = gds_buf_append(&input, hb.data, hb.len, MAX_TOKEN);
    if(st == GDS_OK)
        st = gds_buf_append(&input, ".", 1, MAX_TOKEN);
    if(st == GDS_OK)
        st = gds_buf_append(&input, pb.data, pb.len, MAX_TOKEN);
    if(st == GDS_OK)
        st = sign(signCtx, input.data, input.len, &sig);
    if(st == GDS_OK)
        st = gds_b64url(sig.data, sig.len, &sb);
    if(st == GDS_OK)
        st = gds_buf_append(&input, ".", 1, MAX_TOKEN);
    if(st == GDS_OK)
        st = gds_buf_append(&input, sb.data, sb.len, MAX_TOKEN);
    if(st == GDS_OK)
        st = gds_buf_append(&input, "", 1, MAX_TOKEN + 1); /* NUL, not counted */
    if(st == GDS_OK) {
        input.len--;
        *out = input;
        input = (gds_buf){0};
    }
    gds_buf_free(&input);
    gds_buf_free(&h);
    gds_buf_free(&p);
    gds_buf_free(&hb);
    gds_buf_free(&pb);
    gds_buf_free(&sig);
    gds_buf_free(&sb);
    return st;
}

/* ---- an in-process signer ---- */

struct gds_jwt_key {
    EVP_PKEY *pkey;
    const EVP_MD *md;
    size_t coord; /* ECDSA: bytes of R and of S; 0 for RSA */
};

gds_status gds_jwt_key_new(const gds_buf *der, gds_jwt_key **out, const char **alg) {
    *out = NULL;
    if(!der || !der->data || der->len == 0 || der->len > MAX_PART)
        return GDS_EINVAL;
    const unsigned char *p = der->data;
    EVP_PKEY *pk = d2i_AutoPrivateKey(NULL, &p, (long)der->len);
    if(!pk)
        return GDS_ECRYPTO;
    gds_jwt_key *k = calloc(1, sizeof(*k));
    if(!k) {
        EVP_PKEY_free(pk);
        return GDS_ENOMEM;
    }
    k->pkey = pk;
    if(EVP_PKEY_is_a(pk, "RSA") && EVP_PKEY_get_bits(pk) >= 2048) {
        k->md = EVP_sha256();
        *alg = "RS256";
    } else if(EVP_PKEY_is_a(pk, "EC")) {
        char group[32] = "";
        size_t gl = 0;
        if(EVP_PKEY_get_utf8_string_param(pk, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group),
                                          &gl) == 1 &&
           strcmp(group, "prime256v1") == 0) {
            k->md = EVP_sha256();
            k->coord = 32;
            *alg = "ES256";
        } else if(strcmp(group, "secp384r1") == 0) {
            k->md = EVP_sha384();
            k->coord = 48;
            *alg = "ES384";
        }
    }
    if(!k->md) {
        gds_jwt_key_free(k);
        return GDS_EUNSUPPORTED;
    }
    *out = k;
    return GDS_OK;
}

void gds_jwt_key_free(gds_jwt_key *k) {
    if(!k)
        return;
    EVP_PKEY_free(k->pkey);
    free(k);
}

/* DER ECDSA-Sig-Value to the fixed R || S of RFC 7518 §3.4. */
static gds_status ecdsa_raw(const unsigned char *der, size_t len, size_t coord, gds_buf *out) {
    const unsigned char *p = der;
    ECDSA_SIG *es = d2i_ECDSA_SIG(NULL, &p, (long)len);
    if(!es)
        return GDS_ECRYPTO;
    const BIGNUM *r = NULL, *s = NULL;
    ECDSA_SIG_get0(es, &r, &s);
    gds_status st = GDS_ENOMEM;
    out->data = malloc(2 * coord);
    if(out->data) {
        out->len = 2 * coord;
        st = BN_bn2binpad(r, out->data, (int)coord) == (int)coord &&
                     BN_bn2binpad(s, out->data + coord, (int)coord) == (int)coord
                 ? GDS_OK
                 : GDS_ECRYPTO;
        if(st != GDS_OK)
            gds_buf_free(out);
    }
    ECDSA_SIG_free(es);
    return st;
}

gds_status gds_jwt_key_sign(void *ctx, const uint8_t *data, size_t len, gds_buf *sig) {
    memset(sig, 0, sizeof(*sig));
    gds_jwt_key *k = ctx;
    if(!k || !data)
        return GDS_EINVAL;
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    size_t sl = 0;
    unsigned char *buf = NULL;
    gds_status st = GDS_ECRYPTO;
    if(mc && EVP_DigestSignInit(mc, NULL, k->md, NULL, k->pkey) == 1 &&
       EVP_DigestSign(mc, NULL, &sl, data, len) == 1 && (buf = malloc(sl)) != NULL &&
       EVP_DigestSign(mc, buf, &sl, data, len) == 1)
        st = k->coord ? ecdsa_raw(buf, sl, k->coord, sig) : gds_buf_dup(buf, sl, sig);
    free(buf);
    EVP_MD_CTX_free(mc);
    return st;
}
