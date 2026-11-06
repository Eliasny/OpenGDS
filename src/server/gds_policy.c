/* OpenGDS - the built-in approval policy: which certificate requests are
 * approved on arrival (gds_server_config.approval, opengds.conf
 * `approval`). The rest wait for an administrator (gds_approvals.c).
 * SPDX-License-Identifier: MPL-2.0 */
#include <time.h>

#include "gds_internal.h"
#include "common/banned.h"

/* A renewal by the holder of the prior certificate (docs/architecture.md):
 * the application's newest unrevoked certificate of this group and type has
 * not expired, and the caller's secure channel uses it. A request made by
 * an administrator, or over an older or revoked certificate, waits. */
static gds_status is_renewal(gds_server *s, const void *sessionContext, const gds_request *q,
                             bool *out) {
    gds_buf der = {0};
    int64_t notAfter = 0;
    gds_status r = gds_store_cert_latest(s->store, &q->appId, q->groupId, q->certType, &der,
                                         &notAfter);
    *out = r == GDS_OK && notAfter > (int64_t)time(NULL) &&
           gds_session_holds_cert(sessionContext, &der);
    gds_buf_free(&der);
    return r == GDS_ENOTFOUND ? GDS_OK : r;
}

gds_status gds_policy_initial_state(gds_server *s, const void *sessionContext, const gds_request *q,
                                    gds_req_state *out) {
    *out = GDS_REQ_PENDING;
    switch(s->approval) {
    case GDS_APPROVE_ALL:
        *out = GDS_REQ_RECEIVED;
        return GDS_OK;
    case GDS_APPROVE_RENEWALS: {
        bool renewal = false;
        gds_lock(s);
        gds_status r = is_renewal(s, sessionContext, q, &renewal);
        gds_unlock(s);
        if(renewal)
            *out = GDS_REQ_RECEIVED;
        return r;
    }
    case GDS_APPROVE_MANUAL:
        return GDS_OK;
    default:
        return GDS_EINVAL;
    }
}
