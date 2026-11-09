/* OpenGDS - the store front: every gds_store_* call dispatches to the
 * backend (UASM ask A4, issue #15).
 * SPDX-License-Identifier: MPL-2.0 */
#include "store.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "common/limits.h"
#include "store_backend.h"
#include "common/banned.h"

struct gds_store {
    gds_store_backend be;
    void *ctx;
};

static bool complete(const gds_store_backend *be) {
    return be->close && be->schema_version && be->app_insert && be->app_get &&
           be->app_find_uri && be->app_update && be->app_delete && be->app_scan &&
           be->req_insert && be->req_get && be->req_next_received && be->req_set_state &&
           be->cert_add && be->cert_latest;
}

#define MINOR0_SIZE (offsetof(gds_store_backend, cert_latest) + sizeof(void (*)(void)))

gds_status gds_store_open_backend(const gds_store_backend *be, void *ctx, gds_store **out) {
    *out = NULL;
    if(!be || be->abi_major != GDS_STORE_ABI_MAJOR || be->struct_size < MINOR0_SIZE ||
       !complete(be)) {
        if(be && be->abi_major == GDS_STORE_ABI_MAJOR && be->close)
            be->close(ctx);
        return GDS_EINVAL;
    }
    gds_store *s = calloc(1, sizeof(*s));
    if(!s) {
        be->close(ctx);
        return GDS_ENOMEM;
    }
    /* only the fields the backend's version has; later ones stay NULL */
    memcpy(&s->be, be, be->struct_size < sizeof(s->be) ? be->struct_size : sizeof(s->be));
    s->be.struct_size = sizeof(s->be);
    s->ctx = ctx;
    *out = s;
    return GDS_OK;
}

static gds_status open_sqlite(const char *path, bool readonly, gds_store **out) {
    *out = NULL;
    void *ctx = NULL;
    gds_status r = gds_store_sqlite_open(path, readonly, &ctx);
    if(r != GDS_OK)
        return r;
    return gds_store_open_backend(&gds_store_sqlite_backend, ctx, out);
}

gds_status gds_store_open(const char *path, gds_store **out) {
    return open_sqlite(path, false, out);
}

gds_status gds_store_open_readonly(const char *path, gds_store **out) {
    return open_sqlite(path, true, out);
}

void gds_store_close(gds_store *s) {
    if(!s)
        return;
    s->be.close(s->ctx);
    free(s);
}

int gds_store_schema_version(gds_store *s) {
    return s->be.schema_version(s->ctx);
}

gds_status gds_store_app_insert(gds_store *s, const UA_Guid *id,
                                const UA_ApplicationRecordDataType *rec) {
    return s->be.app_insert(s->ctx, id, rec);
}

gds_status gds_store_app_get(gds_store *s, const UA_Guid *id, UA_ApplicationRecordDataType *out) {
    return s->be.app_get(s->ctx, id, out);
}

gds_status gds_store_app_find_uri(gds_store *s, const UA_String *uri, size_t max,
                                  UA_ApplicationRecordDataType **out, size_t *n) {
    return s->be.app_find_uri(s->ctx, uri, max, out, n);
}

gds_status gds_store_app_update(gds_store *s, const UA_Guid *id,
                                const UA_ApplicationRecordDataType *rec) {
    return s->be.app_update(s->ctx, id, rec);
}

gds_status gds_store_app_delete(gds_store *s, const UA_Guid *id) {
    return s->be.app_delete(s->ctx, id);
}

gds_status gds_store_app_scan(gds_store *s, int64_t afterRecordId, gds_store_scan_cb cb,
                              void *ctx) {
    return s->be.app_scan(s->ctx, afterRecordId, cb, ctx);
}

gds_status gds_store_req_insert(gds_store *s, const gds_request *r) {
    return s->be.req_insert(s->ctx, r);
}

gds_status gds_store_req_get(gds_store *s, const UA_Guid *id, gds_request *out) {
    return s->be.req_get(s->ctx, id, out);
}

gds_status gds_store_req_next_received(gds_store *s, gds_request *out) {
    return s->be.req_next_received(s->ctx, out);
}

gds_status gds_store_req_scan(gds_store *s, gds_req_state state, gds_store_req_cb cb,
                              void *ctx) {
    if(!s->be.req_scan)
        return GDS_EUNSUPPORTED; /* a backend before minor 2 */
    return s->be.req_scan(s->ctx, state, cb, ctx);
}

gds_status gds_store_req_set_state(gds_store *s, const UA_Guid *id, gds_req_state state,
                                   const gds_buf *cert, UA_StatusCode error) {
    return s->be.req_set_state(s->ctx, id, state, cert, error);
}

gds_status gds_store_cert_add(gds_store *s, const UA_Guid *appId, uint32_t groupId,
                              uint32_t certType, const gds_buf *serial, const gds_buf *der,
                              int64_t notBefore, int64_t notAfter) {
    return s->be.cert_add(s->ctx, appId, groupId, certType, serial, der, notBefore, notAfter);
}

gds_status gds_store_cert_issue(gds_store *s, const UA_Guid *reqId, const UA_Guid *appId,
                                uint32_t groupId, uint32_t certType, const gds_buf *serial,
                                const gds_buf *der, int64_t notBefore, int64_t notAfter) {
    if(!reqId || !appId || !serial || !der)
        return GDS_EINVAL;
    if(s->be.cert_issue)
        return s->be.cert_issue(s->ctx, reqId, appId, groupId, certType, serial, der, notBefore,
                                notAfter);
    /* A backend before minor 7: two transactions, as before A24. */
    gds_request q;
    memset(&q, 0, sizeof(q));
    gds_status r = s->be.req_get(s->ctx, reqId, &q);
    if(r != GDS_OK)
        return r;
    bool received = q.state == GDS_REQ_RECEIVED;
    gds_request_clear(&q);
    if(!received)
        return GDS_ESTATE;
    r = s->be.cert_add(s->ctx, appId, groupId, certType, serial, der, notBefore, notAfter);
    if(r == GDS_OK)
        r = s->be.req_set_state(s->ctx, reqId, GDS_REQ_ISSUED, der, UA_STATUSCODE_GOOD);
    return r;
}

gds_status gds_store_cert_latest(gds_store *s, const UA_Guid *appId, uint32_t groupId,
                                 uint32_t certType, gds_buf *der, int64_t *notAfter) {
    return s->be.cert_latest(s->ctx, appId, groupId, certType, der, notAfter);
}

bool gds_store_has_audit(const gds_store *s) {
    return s && s->be.audit_append != NULL;
}

gds_status gds_store_audit_append(gds_store *s, int64_t time, const gds_buf *body, int64_t *seq) {
    if(!s->be.audit_append)
        return GDS_EUNSUPPORTED;
    if(!body || body->len == 0 || body->len > GDS_MAX_AUDIT_BODY)
        return body && body->len ? GDS_ETOOBIG : GDS_EINVAL;
    return s->be.audit_append(s->ctx, time, body, seq);
}

gds_status gds_store_cert_scan(gds_store *s, gds_cert_scan_cb cb, void *ctx) {
    if(!s->be.cert_scan)
        return GDS_EUNSUPPORTED;
    return s->be.cert_scan(s->ctx, cb, ctx);
}

gds_status gds_store_tl_get(gds_store *s, uint32_t groupId, gds_buf *data, int64_t *lastUpdate) {
    data->data = NULL;
    data->len = 0;
    *lastUpdate = 0;
    if(!s->be.tl_get)
        return GDS_EUNSUPPORTED; /* a backend before minor 5 */
    gds_status r = s->be.tl_get(s->ctx, groupId, data, lastUpdate);
    if(r == GDS_OK && data->len > GDS_MAX_TRUSTLIST_SIZE) {
        gds_buf_free(data);
        r = GDS_ETOOBIG;
    }
    return r;
}

gds_status gds_store_tl_put(gds_store *s, uint32_t groupId, const gds_buf *data,
                            int64_t lastUpdate) {
    if(!s->be.tl_put)
        return GDS_EUNSUPPORTED;
    if(!data || !data->data || data->len == 0)
        return GDS_EINVAL;
    if(data->len > GDS_MAX_TRUSTLIST_SIZE)
        return GDS_ETOOBIG;
    return s->be.tl_put(s->ctx, groupId, data, lastUpdate);
}

static bool endpoint_ok(const char *e) {
    if(!e)
        return false;
    size_t n = strnlen(e, GDS_MAX_PUSH_ENDPOINT);
    if(n <= 10 || n >= GDS_MAX_PUSH_ENDPOINT || strncmp(e, "opc.tcp://", 10) != 0)
        return false;
    for(size_t i = 0; i < n; i++)
        if((unsigned char)e[i] <= 0x20 || (unsigned char)e[i] == 0x7f)
            return false;
    return true;
}

gds_status gds_store_push_target_put(gds_store *s, const UA_Guid *appId, const char *endpoint,
                                     bool enabled) {
    if(!s->be.push_target_put)
        return GDS_EUNSUPPORTED; /* a backend before minor 6 */
    if(!appId || !endpoint_ok(endpoint))
        return GDS_EINVAL;
    return s->be.push_target_put(s->ctx, appId, endpoint, enabled);
}

gds_status gds_store_push_target_delete(gds_store *s, const UA_Guid *appId) {
    if(!s->be.push_target_delete)
        return GDS_EUNSUPPORTED;
    if(!appId)
        return GDS_EINVAL;
    return s->be.push_target_delete(s->ctx, appId);
}

gds_status gds_store_push_target_scan(gds_store *s, gds_push_target_cb cb, void *ctx) {
    if(!s->be.push_target_scan)
        return GDS_EUNSUPPORTED;
    if(!cb)
        return GDS_EINVAL;
    return s->be.push_target_scan(s->ctx, cb, ctx);
}

gds_status gds_store_audit_scan(gds_store *s, int64_t fromSeq, gds_audit_scan_cb cb, void *ctx) {
    if(!s->be.audit_scan)
        return GDS_EUNSUPPORTED;
    return s->be.audit_scan(s->ctx, fromSeq, cb, ctx);
}

typedef struct {
    int64_t next;
    uint8_t prev[GDS_AUDIT_HASH];
    int64_t bad;
} verify_state;

static bool verify_row(void *ctx, const gds_audit_row *row) {
    verify_state *v = ctx;
    uint8_t h[GDS_AUDIT_HASH];
    if(row->seq != v->next || memcmp(row->prevHash, v->prev, GDS_AUDIT_HASH) != 0 ||
       gds_audit_hash(v->prev, row->seq, row->time, &row->body, h) != GDS_OK ||
       memcmp(h, row->hash, GDS_AUDIT_HASH) != 0) {
        v->bad = row->seq != v->next ? v->next : row->seq;
        return false;
    }
    memcpy(v->prev, h, GDS_AUDIT_HASH);
    v->next++;
    return true;
}

gds_status gds_store_audit_verify(gds_store *s, int64_t *rows, int64_t *badSeq) {
    verify_state v;
    memset(&v, 0, sizeof(v));
    v.next = 1;
    *badSeq = 0;
    *rows = 0;
    gds_status r = gds_store_audit_scan(s, 1, verify_row, &v);
    *rows = v.next - 1;
    if(r != GDS_OK)
        return r;
    if(v.bad) {
        *badSeq = v.bad;
        return GDS_ESTATE;
    }
    return GDS_OK;
}

gds_status gds_store_cert_revoke(gds_store *s, const UA_Guid *appId, const gds_buf *der,
                                 gds_buf *serial) {
    serial->data = NULL;
    serial->len = 0;
    if(!der || !der->data || der->len == 0)
        return GDS_EINVAL;
    if(!s->be.cert_revoke)
        return GDS_EUNSUPPORTED; /* a backend before minor 3 */
    return s->be.cert_revoke(s->ctx, appId, der, serial);
}

gds_status gds_store_cert_revoke_app(gds_store *s, const UA_Guid *appId, gds_store_serial_cb cb,
                                     void *ctx) {
    if(!s->be.cert_revoke_app)
        return GDS_EUNSUPPORTED;
    return s->be.cert_revoke_app(s->ctx, appId, cb, ctx);
}

gds_status gds_store_cert_is_revoked(gds_store *s, const gds_buf *serial, bool *revoked) {
    *revoked = false;
    if(!serial || !serial->data || serial->len == 0)
        return GDS_EINVAL;
    if(!s->be.cert_is_revoked)
        return GDS_EUNSUPPORTED;
    return s->be.cert_is_revoked(s->ctx, serial, revoked);
}
