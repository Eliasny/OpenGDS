/* OpenGDS Auditor server profile: certificate update (srv_update.c).
 * ConformanceUnit: Push Model for Global Certificate and TrustList Management.
 * Catalogue: docs/auditor/server-profile.md, "Certificate update".
 * SPDX-License-Identifier: MPL-2.0 */
#include "srv_target.h"
#include "srv_tests.h"
#include "common/banned.h"

/* SRV-UPD-01 (12 §7.10.5): UpdateCertificate(DefaultApplicationGroup, type,
 * t-good). t-good is issued by the test CA for the target's ApplicationUri
 * and the key of its CSR (RegeneratePrivateKey FALSE). The change stays
 * queued in the admin session for SRV-TXN-03. */
static void t_update_valid(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->tlPushed) {
        ga_not_tested(ctx, "builds on SRV-TL-02 (the test CA must be in the applied trust list)");
        return;
    }
    UA_StatusCode r = st_learn(t, ctx);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: ApplicationUri and CertificateTypes -> %s", UA_StatusCode_name(r));
        return;
    }
    gds_buf csr = {0};
    if((r = st_csr(t, t->client, false, NULL, &csr)) != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: CreateSigningRequest -> %s (SRV-CSR-01 checks it)",
                      UA_StatusCode_name(r));
        return;
    }
    gds_buf_free(&t->tGood);
    gds_status gs = testca_sign_csr(&t->ca, &csr, t->targetUri, TESTCA_MAX_DAYS, &t->tGood);
    gds_buf_free(&csr);
    if(gs != GDS_OK) {
        ga_not_tested(ctx, "setup: the test CA cannot sign the target's CSR: %s",
                      gds_status_name(gs));
        return;
    }
    bool acr = false;
    r = st_update_cert(t, t->client, &t->tGood, &t->caDer, 1, &acr);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "UpdateCertificate refused a valid certificate: %s", UA_StatusCode_name(r));
        return;
    }
    t->certQueued = true;
    bool present = false, txn = false;
    st_supports_transactions(t->client, &present, &txn);
    if(present && txn && !acr) {
        ga_fail(ctx, "SupportsTransactions is TRUE but ApplyChangesRequired is FALSE");
        return;
    }
    char tp[X509_THUMBPRINT_LEN] = "?";
    if(x509_thumbprint(&t->tGood, tp) != GDS_OK)
        tp[0] = '\0';
    ga_pass(ctx, "Good, ApplyChangesRequired %s (SupportsTransactions %s); t-good %s",
            acr ? "TRUE" : "FALSE", present ? (txn ? "TRUE" : "FALSE") : "absent", tp);
}

const ga_test srv_update_tests[] = {
    {"SRV-UPD-01", "12 §7.10.5", "UpdateCertificate accepts a valid CA-issued certificate", true,
     false, t_update_valid},
};
const size_t srv_update_count = GDS_ARRAY_SIZE(srv_update_tests);
