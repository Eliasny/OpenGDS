/* OpenGDS - the store front: every gds_store_* call dispatches to the
 * backend (UASM ask A4, issue #15).
 * SPDX-License-Identifier: MPL-2.0 */
#include "store.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

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

gds_status gds_store_open_backend(const gds_store_backend *be, void *ctx, gds_store **out) {
    *out = NULL;
    if(!be || be->abi_major != GDS_STORE_ABI_MAJOR || be->struct_size < sizeof(*be) ||
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
    memcpy(&s->be, be, sizeof(s->be));
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

gds_status gds_store_app_scan(gds_store *s, int64_t fromRecordId, gds_store_scan_cb cb,
                              void *ctx) {
    return s->be.app_scan(s->ctx, fromRecordId, cb, ctx);
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

gds_status gds_store_req_set_state(gds_store *s, const UA_Guid *id, gds_req_state state,
                                   const gds_buf *cert, UA_StatusCode error) {
    return s->be.req_set_state(s->ctx, id, state, cert, error);
}

gds_status gds_store_cert_add(gds_store *s, const UA_Guid *appId, uint32_t groupId,
                              uint32_t certType, const gds_buf *serial, const gds_buf *der,
                              int64_t notBefore, int64_t notAfter) {
    return s->be.cert_add(s->ctx, appId, groupId, certType, serial, der, notBefore, notAfter);
}

gds_status gds_store_cert_latest(gds_store *s, const UA_Guid *appId, uint32_t groupId,
                                 uint32_t certType, gds_buf *der, int64_t *notAfter) {
    return s->be.cert_latest(s->ctx, appId, groupId, certType, der, notAfter);
}
