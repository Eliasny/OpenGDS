/* OpenGDS Auditor server profile: trust list write (srv_trustlist.c).
 * ConformanceUnit: Push Model for Global Certificate and TrustList Management.
 * Catalogue: docs/auditor/server-profile.md, "Trust list write".
 * SPDX-License-Identifier: MPL-2.0 */
#include "srv_target.h"
#include "srv_tests.h"
#include "common/banned.h"

/* SRV-TL-02 (12 §7.8.2.1, §7.8.2.5, §7.10.9): Open(0x06), Write the new list
 * in 512-byte chunks, CloseAndUpdate, ApplyChanges if ApplyChangesRequired,
 * then OpenWithMasks(All) and Read back. The new list is the snapshot plus
 * the run's test CA and its CRL, so the Auditor keeps its own access. */
static void t_tl_write_readback(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    UA_StatusCode r = st_snapshot(t, ctx);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: snapshot of the trust list -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_TrustListDataType_clear(&t->pushed);
    if((r = st_list_copy_add(&t->snap, &t->caDer, &t->caCrl, &t->pushed)) != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: building the new list -> %s", UA_StatusCode_name(r));
        return;
    }
    bool acr = false;
    r = st_write_trustlist(t->client, &t->pushed, 512, &acr, ctx);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "a valid trust list was not accepted: %s", UA_StatusCode_name(r));
        return;
    }
    if(acr) {
        r = st_apply(t->client);
        ga_note(ctx, "ApplyChangesRequired TRUE; ApplyChanges -> %s", UA_StatusCode_name(r));
        if(r != UA_STATUSCODE_GOOD) {
            ga_fail(ctx, "ApplyChanges after CloseAndUpdate -> %s", UA_StatusCode_name(r));
            return;
        }
    }
    UA_TrustListDataType back;
    r = st_admin(t);
    if(r == UA_STATUSCODE_GOOD)
        r = st_read_trustlist(t->client, ST_MASK_ALL, &back);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "OpenWithMasks(All) read-back -> %s", UA_StatusCode_name(r));
        return;
    }
    char why[160];
    if(st_lists_equal(&t->pushed, &back, why, sizeof(why))) {
        t->tlPushed = true;
        ga_pass(ctx, "list read back equals the list written (%zu trusted, %zu CRL)",
                back.trustedCertificatesSize, back.trustedCrlsSize);
    } else {
        ga_fail(ctx, "list read back differs from the list written: %s", why);
    }
    UA_TrustListDataType_clear(&back);
}

const ga_test srv_trustlist_tests[] = {
    {"SRV-TL-02", "12 §7.8.2.1, §7.8.2.5, §7.10.9",
     "A trust list written in chunks and applied is read back unchanged", true, false,
     t_tl_write_readback},
};
const size_t srv_trustlist_count = GDS_ARRAY_SIZE(srv_trustlist_tests);
