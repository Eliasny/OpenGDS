/* OpenGDS - the push-scheduling slot and the push target list for the push
 * engine (OpenGDS plan W3, push.h "next_jobs(now, budget)"; gds_plugin.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include <stdlib.h>
#include <string.h>

#include "common/limits.h"
#include "gds_internal.h"
#include "common/banned.h"

#define SCHED_MINOR0_SIZE (offsetof(gds_push_scheduler, ctx) + sizeof(void *))

gds_status gds_server_set_push_scheduler(gds_server *s, const gds_push_scheduler *sched) {
    if(!s)
        return GDS_EINVAL;
    if(__atomic_load_n(&s->started, __ATOMIC_ACQUIRE))
        return GDS_ESTATE;
    if(!sched) {
        memset(&s->pushSched, 0, sizeof(s->pushSched));
        s->pushSchedSet = false;
        return GDS_OK;
    }
    if(sched->abi_major != GDS_PLUGIN_ABI_MAJOR || sched->struct_size < SCHED_MINOR0_SIZE ||
       !sched->next_jobs)
        return GDS_EINVAL;
    memset(&s->pushSched, 0, sizeof(s->pushSched));
    memcpy(&s->pushSched, sched,
           sched->struct_size < sizeof(s->pushSched) ? sched->struct_size : sizeof(s->pushSched));
    s->pushSched.struct_size = sizeof(s->pushSched);
    s->pushSchedSet = true;
    return GDS_OK;
}

bool gds_server_push_scheduler(gds_server *s, gds_push_scheduler *out) {
    if(!s || !s->pushSchedSet)
        return false;
    if(out)
        *out = s->pushSched;
    return true;
}

/* The engine passes the due jobs earliest first, so the first budget of
 * them are the earliest. */
size_t gds_push_next_jobs_default(void *ctx, UA_DateTime now, size_t budget,
                                  const gds_push_job *due, size_t nDue, size_t *picked) {
    (void)ctx, (void)now, (void)due;
    size_t n = nDue < budget ? nDue : budget;
    for(size_t i = 0; i < n; i++)
        picked[i] = i;
    return n;
}

/* ---- the push target list ---- */

typedef struct {
    UA_Guid appId;
    char endpoint[GDS_MAX_PUSH_ENDPOINT];
    bool enabled;
} target_row;

typedef struct {
    target_row *rows;
    size_t n, cap;
    gds_status err;
} target_rows;

static bool collect(void *ctx, const gds_push_target_row *row) {
    target_rows *t = ctx;
    if(t->n == t->cap) {
        size_t cap = t->cap ? 2 * t->cap : 16;
        if(cap > GDS_MAX_PUSH_TARGETS) {
            t->err = GDS_ETOOBIG;
            return false;
        }
        target_row *r = realloc(t->rows, cap * sizeof(*r));
        if(!r) {
            t->err = GDS_ENOMEM;
            return false;
        }
        t->rows = r;
        t->cap = cap;
    }
    target_row *r = &t->rows[t->n];
    size_t len = strnlen(row->endpoint, GDS_MAX_PUSH_ENDPOINT);
    if(len >= GDS_MAX_PUSH_ENDPOINT)
        return true; /* the store checks this; skip a damaged row */
    r->appId = row->appId;
    memcpy(r->endpoint, row->endpoint, len + 1);
    r->enabled = row->enabled;
    t->n++;
    return true;
}

gds_status gds_server_push_targets(gds_server *s, gds_push_target_fn cb, void *ctx) {
    if(!s || !cb)
        return GDS_EINVAL;
    target_rows t;
    memset(&t, 0, sizeof(t));
    gds_lock(s);
    gds_status st = gds_store_push_target_scan(s->store, collect, &t);
    gds_unlock(s);
    if(st == GDS_OK)
        st = t.err;
    char uri[GDS_MAX_APPLICATION_URI + 1];
    for(size_t i = 0; st == GDS_OK && i < t.n; i++) {
        UA_ApplicationRecordDataType rec;
        UA_ApplicationRecordDataType_init(&rec);
        UA_StatusCode r = gds_load_app(s, &t.rows[i].appId, &rec);
        bool keep = r == UA_STATUSCODE_GOOD && rec.applicationUri.length > 0 &&
                    rec.applicationUri.length <= GDS_MAX_APPLICATION_URI;
        if(keep) {
            memcpy(uri, rec.applicationUri.data, rec.applicationUri.length);
            uri[rec.applicationUri.length] = '\0';
        }
        UA_ApplicationRecordDataType_clear(&rec);
        if(!keep)
            continue; /* the record is gone (the row goes with it) */
        UA_NodeId id = UA_NODEID_GUID(s->ns, t.rows[i].appId);
        if(!cb(ctx, &id, uri, t.rows[i].endpoint, t.rows[i].enabled))
            break;
    }
    free(t.rows);
    return st;
}
