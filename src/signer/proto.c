/* OpenGDS - opengdsd <-> opengds-signer messages (see proto.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include "proto.h"

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
    if(o != GDS_SIGP_SIGN_CSR && o != GDS_SIGP_GET_CHAIN && o != GDS_SIGP_ISSUE_CRL)
        return GDS_EUNSUPPORTED;
    *op = (gds_sigp_op)o;
    return GDS_OK;
}

/* ---- requests ---- */

gds_status gds_sigp_encode_request(gds_sigp_op op, const UA_Guid *requestId, gds_buf *out) {
    if(op == GDS_SIGP_SIGN_CSR && !requestId)
        return GDS_EINVAL;
    gds_status r = begin(out, op);
    if(r == GDS_OK && op == GDS_SIGP_SIGN_CSR)
        r = put_guid(out, requestId);
    return finish(out, r);
}

gds_status gds_sigp_decode_request(const uint8_t *msg, size_t len, gds_sigp_op *op,
                                   UA_Guid *requestId) {
    rd r = {msg, len, 0};
    gds_status s = read_header(&r, op);
    if(s != GDS_OK)
        return s;
    UA_Guid_init(requestId);
    if(*op == GDS_SIGP_SIGN_CSR && !get_guid(&r, requestId))
        return GDS_EINVAL;
    return r.pos == r.len ? GDS_OK : GDS_EINVAL;
}

/* ---- replies ---- */

static bool status_valid(uint32_t s) {
    return s <= (uint32_t)GDS_EUNSUPPORTED;
}

gds_status gds_sigp_encode_reply(gds_sigp_op op, gds_status status, const gds_ca_issued *issued,
                                 const gds_buf *der, gds_buf *out) {
    gds_status r = begin(out, op);
    if(r == GDS_OK)
        r = put_u32(out, (uint32_t)status);
    if(r != GDS_OK || status != GDS_OK)
        return finish(out, r);
    if(op == GDS_SIGP_SIGN_CSR) {
        if(!issued || issued->serial.len == 0 || issued->serial.len > GDS_SIGP_MAX_SERIAL ||
           issued->der.len == 0)
            return finish(out, GDS_EINVAL);
        r = put_i64(out, issued->notBefore);
        if(r == GDS_OK)
            r = put_i64(out, issued->notAfter);
        if(r == GDS_OK)
            r = put_u16(out, (uint16_t)issued->serial.len);
        if(r == GDS_OK)
            r = put(out, issued->serial.data, issued->serial.len);
        der = &issued->der;
    } else if(!der || der->len == 0) {
        return finish(out, GDS_EINVAL);
    }
    if(r == GDS_OK && der->len > UINT32_MAX)
        r = GDS_ETOOBIG;
    if(r == GDS_OK)
        r = put_u32(out, (uint32_t)der->len);
    if(r == GDS_OK)
        r = put(out, der->data, der->len);
    return finish(out, r);
}

gds_status gds_sigp_decode_reply(gds_sigp_op op, const uint8_t *msg, size_t len,
                                 gds_status *status, gds_ca_issued *issued, gds_buf *der) {
    if(issued)
        memset(issued, 0, sizeof(*issued));
    if(der)
        memset(der, 0, sizeof(*der));
    rd r = {msg, len, 0};
    gds_sigp_op got;
    uint32_t st = 0;
    if(read_header(&r, &got) != GDS_OK || got != op || !get_u32(&r, &st) || !status_valid(st))
        return GDS_EREMOTE;
    *status = (gds_status)st;
    if(st != GDS_OK)
        return r.pos == r.len ? GDS_OK : GDS_EREMOTE;
    gds_status s = GDS_OK;
    if(op == GDS_SIGP_SIGN_CSR) {
        if(!issued || !get_i64(&r, &issued->notBefore) || !get_i64(&r, &issued->notAfter))
            return GDS_EREMOTE;
        s = get_blob(&r, 2, GDS_SIGP_MAX_SERIAL, &issued->serial);
        if(s == GDS_OK)
            s = get_blob(&r, 4, GDS_MAX_CERT_SIZE, &issued->der);
    } else {
        s = der ? get_blob(&r, 4, GDS_SIGP_MAX_MSG, der) : GDS_EINVAL;
    }
    if(s == GDS_OK && r.pos != r.len)
        s = GDS_EINVAL;
    if(s != GDS_OK) {
        if(issued)
            gds_ca_issued_clear(issued);
        if(der)
            gds_buf_free(der);
        return GDS_EREMOTE;
    }
    return GDS_OK;
}
