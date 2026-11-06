/* OpenGDS Auditor server profile: transactions (srv_transaction.c).
 * ConformanceUnit: Server PushManagement Transactions; SRV-TXN-03: Push
 * Model for Global Certificate and TrustList Management.
 * Catalogue: docs/auditor/server-profile.md, "Transactions".
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <string.h>
#include <time.h>

#include "srv_target.h"
#include "srv_tests.h"
#include "common/banned.h"

#define APPLY_WAIT_MS 10000

static bool same(const gds_buf *a, const gds_buf *b) {
    return a->len == b->len && a->len && memcmp(a->data, b->data, a->len) == 0;
}

static void nap_ms(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

/* SRV-TXN-03 (12 §7.10.9): with t-good queued by SRV-UPD-01, queue a new
 * trust list in the same session (the applied list plus peer-good), call
 * ApplyChanges, then check on a fresh connection that trusts only the test
 * CA: the endpoint presents t-good and the new list is read back. */
static void t_apply_both(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->certQueued || !t->client) {
        ga_not_tested(ctx, "builds on SRV-UPD-01 (a queued certificate in the admin session)");
        return;
    }
    UA_SecureChannelState cs;
    UA_SessionState ss;
    UA_StatusCode st;
    UA_Client_getState(t->client, &cs, &ss, &st);
    if(ss != UA_SESSIONSTATE_ACTIVATED) {
        ga_not_tested(ctx, "the admin session that queued t-good was lost");
        return;
    }
    UA_TrustListDataType_clear(&t->queued);
    UA_StatusCode r = st_list_copy_add(&t->pushed, &t->peerCert, NULL, &t->queued);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: building the new list -> %s", UA_StatusCode_name(r));
        return;
    }
    bool acr = false;
    r = st_write_trustlist(t->client, &t->queued, 4096, &acr, ctx);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: queueing the new trust list -> %s (SRV-TL-02 checks it)",
                      UA_StatusCode_name(r));
        return;
    }
    r = st_apply(t->client);
    ga_note(ctx, "ApplyChanges -> %s", UA_StatusCode_name(r));
    /* the server closes channels after a certificate change (§7.10.9) */
    st_close(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "ApplyChanges with a queued certificate and trust list -> %s",
                UA_StatusCode_name(r));
        return;
    }
    gds_buf now = {0};
    long waited = 0;
    for(;;) {
        gds_buf_free(&now);
        r = st_presented(t, &now);
        if((r == UA_STATUSCODE_GOOD && same(&now, &t->tGood)) || waited >= APPLY_WAIT_MS)
            break;
        nap_ms(200);
        waited += 200;
    }
    bool certInUse = r == UA_STATUSCODE_GOOD && same(&now, &t->tGood);
    char tp[X509_THUMBPRINT_LEN] = "?";
    if(now.len && x509_thumbprint(&now, tp) != GDS_OK)
        tp[0] = '\0';
    gds_buf_free(&now);
    if(!certInUse) {
        ga_fail(ctx, "after ApplyChanges the endpoint presents %s, not t-good (waited %ld ms)", tp,
                waited);
        return;
    }
    UA_Client *c = NULL;
    r = st_admin_fresh(t, false, &c);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "a fresh connection trusting only the test CA failed: %s",
                UA_StatusCode_name(r));
        return;
    }
    UA_TrustListDataType back;
    r = st_read_trustlist(c, ST_MASK_ALL, &back);
    st_client_free(c);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "trust list read-back on the fresh connection -> %s", UA_StatusCode_name(r));
        return;
    }
    char why[160];
    if(st_lists_equal(&t->queued, &back, why, sizeof(why))) {
        t->applied = true;
        ga_pass(ctx, "t-good presented (%s) and the new trust list in use", tp);
    } else {
        ga_fail(ctx, "t-good presented, but the trust list is not the one queued: %s", why);
    }
    UA_TrustListDataType_clear(&back);
}

const ga_test srv_transaction_tests[] = {
    {"SRV-TXN-03", "12 §7.10.9",
     "ApplyChanges puts the queued certificate and trust list in use together", true, false,
     t_apply_both},
};
const size_t srv_transaction_count = GDS_ARRAY_SIZE(srv_transaction_tests);
