/* OpenGDS - opengdsd <-> opengds-signer messages (see proto.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include "proto.h"

#include <openssl/crypto.h>

#include <string.h>

#include "common/limits.h"
#include "common/banned.h"

/* ---- writer ---- */

static gds_status put(gds_buf *b, const void *d, size_t n) {
    return gds_buf_append(b, d, n, GDS_SIGP_MAX_MSG);
}

static gds_status put_u16(gds_buf *b, uint16_t v) {
    uint8_t x[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    return put(b, x, sizeof(x));
}

static gds_status put_u32(gds_buf *b, uint32_t v) {
    uint8_t x[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    return put(b, x, sizeof(x));
}

static gds_status put_i64(gds_buf *b, int64_t v) {
    uint64_t u = (uint64_t)v;
    gds_status r = put_u32(b, (uint32_t)(u >> 32));
    return r == GDS_OK ? put_u32(b, (uint32_t)u) : r;
}

static gds_status put_guid(gds_buf *b, const UA_Guid *g) {
    gds_status r = put_u32(b, g->data1);
    if(r == GDS_OK)
        r = put_u16(b, g->data2);
    if(r == GDS_OK)
        r = put_u16(b, g->data3);
    if(r == GDS_OK)
        r = put(b, g->data4, sizeof(g->data4));
    return r;
}

/* Header with a zero body length, patched by finish(). */
static gds_status begin(gds_buf *b, gds_sigp_op op) {
    memset(b, 0, sizeof(*b));
    gds_status r = put_u32(b, GDS_SIGP_MAGIC);
    if(r == GDS_OK)
        r = put_u16(b, (uint16_t)GDS_SIGP_VERSION);
    if(r == GDS_OK)
        r = put_u16(b, (uint16_t)op);
    if(r == GDS_OK)
        r = put_u32(b, 0);
    return r;
}

static gds_status finish(gds_buf *b, gds_status r) {
    if(r != GDS_OK) {
        gds_buf_free(b);
        return r;
    }
    size_t body = b->len - GDS_SIGP_HEADER;
    b->data[8] = (uint8_t)(body >> 24);
    b->data[9] = (uint8_t)(body >> 16);
    b->data[10] = (uint8_t)(body >> 8);
    b->data[11] = (uint8_t)body;
    return GDS_OK;
}

/* ---- reader ---- */

typedef struct {
    const uint8_t *p;
    size_t len, pos;
} rd;

static bool get(rd *r, void *out, size_t n) {
    if(n > r->len - r->pos)
        return false;
    memcpy(out, r->p + r->pos, n);
    r->pos += n;
    return true;
}

static bool get_u16(rd *r, uint16_t *v) {
    uint8_t x[2];
    if(!get(r, x, sizeof(x)))
        return false;
    *v = (uint16_t)((unsigned)x[0] << 8 | x[1]);
    return true;
}

static bool get_u32(rd *r, uint32_t *v) {
    uint8_t x[4];
    if(!get(r, x, sizeof(x)))
        return false;
    *v = (uint32_t)x[0] << 24 | (uint32_t)x[1] << 16 | (uint32_t)x[2] << 8 | x[3];
    return true;
}

static bool get_i64(rd *r, int64_t *v) {
    uint32_t hi, lo;
    if(!get_u32(r, &hi) || !get_u32(r, &lo))
        return false;
    *v = (int64_t)((uint64_t)hi << 32 | lo);
    return true;
}

static bool get_guid(rd *r, UA_Guid *g) {
    return get_u32(r, &g->data1) && get_u16(r, &g->data2) && get_u16(r, &g->data3) &&
           get(r, g->data4, sizeof(g->data4));
}

static gds_status get_blob(rd *r, size_t lenField, size_t max, gds_buf *out) {
    uint32_t n32 = 0;
    uint16_t n16 = 0;
    size_t n;
    if(lenField == 2) {
        if(!get_u16(r, &n16))
            return GDS_EINVAL;
        n = n16;
    } else {
        if(!get_u32(r, &n32))
            return GDS_EINVAL;
        n = n32;
    }
    if(n == 0 || n > max || n > r->len - r->pos)
        return GDS_EINVAL;
    gds_status s = gds_buf_dup(r->p + r->pos, n, out);
    if(s == GDS_OK)
        r->pos += n;
    return s;
}

/* Header check: magic, version, op, and a body length equal to the rest. */
static gds_status read_header(rd *r, gds_sigp_op *op) {
    uint32_t magic = 0, body = 0;
    uint16_t version = 0, o = 0;
    if(r->len < GDS_SIGP_HEADER || r->len > GDS_SIGP_MAX_MSG || !get_u32(r, &magic) ||
       !get_u16(r, &version) || !get_u16(r, &o) || !get_u32(r, &body))
        return GDS_EINVAL;
    if(magic != GDS_SIGP_MAGIC || version != GDS_SIGP_VERSION || body != r->len - GDS_SIGP_HEADER)
        return GDS_EINVAL;
    if(o != GDS_SIGP_SIGN_CSR && o != GDS_SIGP_GET_CHAIN && o != GDS_SIGP_ISSUE_CRL &&
       o != GDS_SIGP_REVOKE && o != GDS_SIGP_NEW_KEY_PAIR && o != GDS_SIGP_TOKEN_CHAIN &&
       o != GDS_SIGP_TOKEN_SIGN && o != GDS_SIGP_EXPORT_KEYS)
        return GDS_EUNSUPPORTED;
    *op = (gds_sigp_op)o;
    return GDS_OK;
}

/* ---- requests ---- */

gds_status gds_sigp_encode_request(gds_sigp_op op, const UA_Guid *requestId, gds_buf *out) {
    if((op == GDS_SIGP_SIGN_CSR && !requestId) || op == GDS_SIGP_REVOKE ||
       op == GDS_SIGP_NEW_KEY_PAIR || op == GDS_SIGP_TOKEN_CHAIN || op == GDS_SIGP_TOKEN_SIGN) {
        memset(out, 0, sizeof(*out));
        return GDS_EINVAL; /* gds_sigp_encode_revoke, gds_sigp_encode_new_key_pair */
    }
    gds_status r = begin(out, op);
    if(r == GDS_OK && op == GDS_SIGP_SIGN_CSR)
        r = put_guid(out, requestId);
    return finish(out, r);
}

static bool issuer_ok(gds_ca_issuer issuer) {
    return (unsigned)issuer < GDS_CA_ISSUERS;
}

gds_status gds_sigp_encode_revoke_issuer(gds_ca_issuer issuer, const gds_buf *serial,
                                         gds_buf *out) {
    if(!issuer_ok(issuer) || !serial || !serial->data || serial->len == 0 ||
       serial->len > GDS_SIGP_MAX_SERIAL) {
        memset(out, 0, sizeof(*out));
        return GDS_EINVAL;
    }
    uint8_t i = (uint8_t)issuer;
    gds_status r = begin(out, GDS_SIGP_REVOKE);
    if(r == GDS_OK)
        r = put_u16(out, (uint16_t)serial->len);
    if(r == GDS_OK)
        r = put(out, serial->data, serial->len);
    if(r == GDS_OK && issuer != GDS_CA_ISSUER_RSA)
        r = put(out, &i, 1);
    return finish(out, r);
}

gds_status gds_sigp_encode_revoke(const gds_buf *serial, gds_buf *out) {
    return gds_sigp_encode_revoke_issuer(GDS_CA_ISSUER_RSA, serial, out);
}

gds_status gds_sigp_encode_issuer_request(gds_sigp_op op, gds_ca_issuer issuer, gds_buf *out) {
    if((op != GDS_SIGP_GET_CHAIN && op != GDS_SIGP_ISSUE_CRL) || !issuer_ok(issuer)) {
        memset(out, 0, sizeof(*out));
        return GDS_EINVAL;
    }
    uint8_t i = (uint8_t)issuer;
    gds_status r = begin(out, op);
    if(r == GDS_OK && issuer != GDS_CA_ISSUER_RSA)
        r = put(out, &i, 1);
    return finish(out, r);
}

gds_status gds_sigp_encode_new_key_pair(const UA_Guid *requestId, gds_ca_key_format format,
                                       const gds_buf *password, gds_buf *out) {
    size_t pwLen = password ? password->len : 0;
    if(!requestId || (format != GDS_CA_KEY_PFX && format != GDS_CA_KEY_PEM) ||
       pwLen > GDS_MAX_KEY_PASSWORD || (pwLen && !password->data)) {
        memset(out, 0, sizeof(*out));
        return GDS_EINVAL;
    }
    uint8_t f = (uint8_t)format;
    gds_status r = begin(out, GDS_SIGP_NEW_KEY_PAIR);
    if(r == GDS_OK)
        r = put_guid(out, requestId);
    if(r == GDS_OK)
        r = put(out, &f, 1);
    if(r == GDS_OK)
        r = put_u16(out, (uint16_t)pwLen);
    if(r == GDS_OK && pwLen)
        r = put(out, password->data, pwLen);
    if(r != GDS_OK && out->data)
        OPENSSL_cleanse(out->data, out->len);
    return finish(out, r);
}

static size_t token_max(gds_sigp_op op) {
    return op == GDS_SIGP_TOKEN_CHAIN ? GDS_MAX_APPLICATION_URI : GDS_CA_MAX_JWS_INPUT;
}

gds_status gds_sigp_encode_token(gds_sigp_op op, const gds_buf *data, gds_buf *out) {
    if((op != GDS_SIGP_TOKEN_CHAIN && op != GDS_SIGP_TOKEN_SIGN) || !data || !data->data ||
       data->len == 0 || data->len > token_max(op)) {
        memset(out, 0, sizeof(*out));
        return GDS_EINVAL;
    }
    gds_status r = begin(out, op);
    if(r == GDS_OK)
        r = op == GDS_SIGP_TOKEN_CHAIN ? put_u16(out, (uint16_t)data->len)
                                       : put_u32(out, (uint32_t)data->len);
    if(r == GDS_OK)
        r = put(out, data->data, data->len);
    return finish(out, r);
}

/* The URI gets a terminating NUL and may hold no other. */
static gds_status decode_token(rd *r, gds_sigp_request *out) {
    bool uri = out->op == GDS_SIGP_TOKEN_CHAIN;
    gds_status s = get_blob(r, uri ? 2 : 4, token_max(out->op), &out->data);
    if(s != GDS_OK || !uri)
        return s;
    if(memchr(out->data.data, 0, out->data.len))
        return GDS_EINVAL;
    uint8_t nul = 0;
    s = gds_buf_append(&out->data, &nul, 1, GDS_MAX_APPLICATION_URI + 1);
    if(s == GDS_OK)
        out->data.len--; /* the NUL stays after the bytes */
    return s;
}

void gds_sigp_request_clear(gds_sigp_request *r) {
    gds_buf_free(&r->data);
    gds_buf_free(&r->serial);
    gds_buf_free_secret(&r->password);
}

static gds_status decode_key_pair(rd *r, gds_sigp_request *out) {
    uint8_t f = 0;
    uint16_t n = 0;
    if(!get_guid(r, &out->requestId) || !get(r, &f, 1) || !get_u16(r, &n))
        return GDS_EINVAL;
    if((f != GDS_CA_KEY_PFX && f != GDS_CA_KEY_PEM) || n > GDS_MAX_KEY_PASSWORD ||
       n != r->len - r->pos)
        return GDS_EINVAL;
    out->format = (gds_ca_key_format)f;
    if(n == 0)
        return GDS_OK;
    gds_status s = gds_buf_dup(r->p + r->pos, n, &out->password);
    if(s == GDS_OK)
        r->pos += n;
    return s;
}

/* Optional trailing issuer byte; none means the RSA issuer. */
static gds_status decode_issuer(rd *r, gds_sigp_request *out) {
    out->issuer = GDS_CA_ISSUER_RSA;
    if(r->pos == r->len)
        return GDS_OK;
    uint8_t i = 0;
    if(!get(r, &i, 1) || i == GDS_CA_ISSUER_RSA || !issuer_ok((gds_ca_issuer)i))
        return GDS_EINVAL; /* RSA is never sent explicitly: one encoding per message */
    out->issuer = (gds_ca_issuer)i;
    return GDS_OK;
}

gds_status gds_sigp_decode(const uint8_t *msg, size_t len, gds_sigp_request *out) {
    rd r = {msg, len, 0};
    memset(out, 0, sizeof(*out));
    gds_status s = read_header(&r, &out->op);
    if(s != GDS_OK)
        return s;
    switch(out->op) {
    case GDS_SIGP_SIGN_CSR:
        s = get_guid(&r, &out->requestId) ? GDS_OK : GDS_EINVAL;
        break;
    case GDS_SIGP_REVOKE:
        s = get_blob(&r, 2, GDS_SIGP_MAX_SERIAL, &out->serial);
        if(s == GDS_OK)
            s = decode_issuer(&r, out);
        break;
    case GDS_SIGP_NEW_KEY_PAIR:
        s = decode_key_pair(&r, out);
        break;
    case GDS_SIGP_GET_CHAIN:
    case GDS_SIGP_ISSUE_CRL:
        s = decode_issuer(&r, out);
        break;
    case GDS_SIGP_TOKEN_CHAIN:
    case GDS_SIGP_TOKEN_SIGN:
        s = decode_token(&r, out);
        break;
    case GDS_SIGP_EXPORT_KEYS: /* no body: the signer picks the recipients */
        break;
    }
    if(s == GDS_OK && r.pos != r.len)
        s = GDS_EINVAL;
    if(s != GDS_OK)
        gds_sigp_request_clear(out);
    return s;
}

gds_status gds_sigp_decode_request_ex(const uint8_t *msg, size_t len, gds_sigp_op *op,
                                      UA_Guid *requestId, gds_buf *serial) {
    if(serial)
        memset(serial, 0, sizeof(*serial));
    gds_sigp_request q;
    gds_status s = gds_sigp_decode(msg, len, &q);
    *op = q.op;
    *requestId = q.requestId;
    if(s == GDS_OK && serial) {
        *serial = q.serial;
        q.serial = (gds_buf){0};
    }
    gds_sigp_request_clear(&q);
    return s;
}

gds_status gds_sigp_decode_request(const uint8_t *msg, size_t len, gds_sigp_op *op,
                                   UA_Guid *requestId) {
    return gds_sigp_decode_request_ex(msg, len, op, requestId, NULL);
}

/* ---- replies ---- */

static bool status_valid(uint32_t s) {
    return s <= (uint32_t)GDS_EUNSUPPORTED;
}

static bool issues_cert(gds_sigp_op op) {
    return op == GDS_SIGP_SIGN_CSR || op == GDS_SIGP_NEW_KEY_PAIR;
}

static gds_status put_issued(gds_buf *out, const gds_ca_issued *issued) {
    if(!issued || issued->serial.len == 0 || issued->serial.len > GDS_SIGP_MAX_SERIAL ||
       issued->der.len == 0 || issued->der.len > GDS_MAX_CERT_SIZE)
        return GDS_EINVAL;
    gds_status r = put_i64(out, issued->notBefore);
    if(r == GDS_OK)
        r = put_i64(out, issued->notAfter);
    if(r == GDS_OK)
        r = put_u16(out, (uint16_t)issued->serial.len);
    if(r == GDS_OK)
        r = put(out, issued->serial.data, issued->serial.len);
    return r;
}

static gds_status put_blob32(gds_buf *out, const gds_buf *b) {
    if(!b || !b->data || b->len == 0 || b->len > UINT32_MAX)
        return GDS_EINVAL;
    gds_status r = put_u32(out, (uint32_t)b->len);
    return r == GDS_OK ? put(out, b->data, b->len) : r;
}

/* The body after the status, on GDS_OK */
static gds_status put_result(gds_buf *out, gds_sigp_op op, const gds_ca_issued *issued,
                             const gds_buf *der, const gds_buf *key) {
    if(!issues_cert(op))
        return put_blob32(out, der);
    gds_status r = put_issued(out, issued);
    if(r == GDS_OK)
        r = put_blob32(out, &issued->der);
    if(r == GDS_OK && op == GDS_SIGP_NEW_KEY_PAIR)
        r = key && key->len <= GDS_MAX_KEY_SIZE ? put_blob32(out, key) : GDS_EINVAL;
    return r;
}

static gds_status encode_any(gds_sigp_op op, gds_status status, const gds_ca_issued *issued,
                             const gds_buf *der, const gds_buf *key, gds_buf *out) {
    gds_status r = begin(out, op);
    if(r == GDS_OK)
        r = put_u32(out, (uint32_t)status);
    if(r == GDS_OK && status == GDS_OK)
        r = put_result(out, op, issued, der, key);
    if(r != GDS_OK && out->data)
        OPENSSL_cleanse(out->data, out->len);
    return finish(out, r);
}

gds_status gds_sigp_encode_reply(gds_sigp_op op, gds_status status, const gds_ca_issued *issued,
                                 const gds_buf *der, gds_buf *out) {
    if(op == GDS_SIGP_NEW_KEY_PAIR && status == GDS_OK) {
        memset(out, 0, sizeof(*out));
        return GDS_EINVAL; /* gds_sigp_encode_key_reply */
    }
    return encode_any(op, status, issued, der, NULL, out);
}

gds_status gds_sigp_encode_key_reply(gds_status status, const gds_ca_issued *issued,
                                     const gds_buf *key, gds_buf *out) {
    return encode_any(GDS_SIGP_NEW_KEY_PAIR, status, issued, NULL, key, out);
}

static gds_status get_result(rd *r, gds_sigp_op op, gds_ca_issued *issued, gds_buf *der,
                             gds_buf *key) {
    if(!issues_cert(op))
        return der ? get_blob(r, 4, GDS_SIGP_MAX_MSG, der) : GDS_EINVAL;
    if(!issued || !get_i64(r, &issued->notBefore) || !get_i64(r, &issued->notAfter))
        return GDS_EINVAL;
    gds_status s = get_blob(r, 2, GDS_SIGP_MAX_SERIAL, &issued->serial);
    if(s == GDS_OK)
        s = get_blob(r, 4, GDS_MAX_CERT_SIZE, &issued->der);
    if(s == GDS_OK && op == GDS_SIGP_NEW_KEY_PAIR)
        s = key ? get_blob(r, 4, GDS_MAX_KEY_SIZE, key) : GDS_EINVAL;
    return s;
}

static gds_status decode_any(gds_sigp_op op, const uint8_t *msg, size_t len, gds_status *status,
                             gds_ca_issued *issued, gds_buf *der, gds_buf *key) {
    if(issued)
        memset(issued, 0, sizeof(*issued));
    if(der)
        memset(der, 0, sizeof(*der));
    if(key)
        memset(key, 0, sizeof(*key));
    rd r = {msg, len, 0};
    gds_sigp_op got;
    uint32_t st = 0;
    if(read_header(&r, &got) != GDS_OK || got != op || !get_u32(&r, &st) || !status_valid(st))
        return GDS_EREMOTE;
    *status = (gds_status)st;
    if(st != GDS_OK)
        return r.pos == r.len ? GDS_OK : GDS_EREMOTE;
    gds_status s = get_result(&r, op, issued, der, key);
    if(s == GDS_OK && r.pos != r.len)
        s = GDS_EINVAL;
    if(s != GDS_OK) {
        if(issued)
            gds_ca_issued_clear(issued);
        if(der)
            gds_buf_free(der);
        if(key)
            gds_buf_free_secret(key);
        return GDS_EREMOTE;
    }
    return GDS_OK;
}

gds_status gds_sigp_decode_reply(gds_sigp_op op, const uint8_t *msg, size_t len,
                                 gds_status *status, gds_ca_issued *issued, gds_buf *der) {
    return decode_any(op, msg, len, status, issued, der, NULL);
}

gds_status gds_sigp_decode_key_reply(const uint8_t *msg, size_t len, gds_status *status,
                                     gds_ca_issued *issued, gds_buf *key) {
    return decode_any(GDS_SIGP_NEW_KEY_PAIR, msg, len, status, issued, NULL, key);
}
