/* OpenGDS push engine - the Part 12 push workflows (OPC 10000-12 v1.05.07
 * §7.7.2-§7.7.4, §7.10.2).
 * SPDX-License-Identifier: MPL-2.0 */
#include "push_workflows.h"

#include <string.h>

#include "client/gdsc_push.h"
#include "common/banned.h"

void push_report_clear(push_report *r) {
    gds_buf_free(&r->issued);
    memset(r, 0, sizeof(*r));
}

const char *push_step_name(push_step s) {
    switch(s) {
    case PUSH_STEP_NONE: return "none";
    case PUSH_STEP_TRUSTLIST: return "Update TrustList";
    case PUSH_STEP_CSR: return "CreateSigningRequest";
    case PUSH_STEP_SIGN: return "sign";
    case PUSH_STEP_UPDATE_CERT: return "UpdateCertificate";
    case PUSH_STEP_APPLY: return "ApplyChanges";
    }
    return "?";
}

static gds_status failed(push_report *rep, push_step step, UA_StatusCode code) {
    rep->failedStep = step;
    rep->failedCode = code;
    return GDS_EREMOTE;
}

/* §7.7.3 */
static gds_status run_trustlist(UA_Client *c, const push_job *job, push_report *rep,
                                bool *acr) {
    UA_UInt32 max = 0;
    /* MaxTrustListSize is Mandatory (§7.10.3); a Server that does not expose
     * it still gets the push and answers Bad_RequestTooLarge itself */
    if(gdsc_read_max_trustlist_size(c, &max) != UA_STATUSCODE_GOOD)
        max = 0;
    bool a = false;
    UA_StatusCode r = gdsc_trustlist_write(c, &job->trustListNode, job->trustList, max, &a);
    if(r != UA_STATUSCODE_GOOD)
        return failed(rep, PUSH_STEP_TRUSTLIST, r);
    rep->trustListUpdated = true;
    *acr = *acr || a;
    return GDS_OK;
}

/* §7.7.4: CreateSigningRequest -> sign -> UpdateCertificate */
static gds_status run_certificate(UA_Client *c, const push_job *job, push_report *rep,
                                  bool *acr) {
    gds_buf csr = {0};
    UA_StatusCode r =
        gdsc_create_signing_request(c, &job->certificateGroup, &job->certificateType, &csr);
    if(r != UA_STATUSCODE_GOOD)
        return failed(rep, PUSH_STEP_CSR, r);
    gds_status s = job->sign(job->signCtx, &csr, &rep->issued);
    gds_buf_free(&csr);
    if(s != GDS_OK) {
        rep->failedStep = PUSH_STEP_SIGN;
        rep->failedCode = UA_STATUSCODE_GOOD; /* nothing was refused remotely */
        gds_buf_free(&rep->issued);
        return s;
    }
    bool a = false;
    r = gdsc_update_certificate(c, &job->certificateGroup, &job->certificateType, &rep->issued,
                                job->issuers, job->issuersN, &a);
    if(r != UA_STATUSCODE_GOOD)
        return failed(rep, PUSH_STEP_UPDATE_CERT, r);
    rep->certificateUpdated = true;
    *acr = *acr || a;
    return GDS_OK;
}

gds_status push_run(UA_Client *c, const push_job *job, push_report *rep) {
    memset(rep, 0, sizeof(*rep));
    if(!c || !job || (!job->trustList && !job->sign) || (job->issuersN > 0 && !job->issuers))
        return GDS_EINVAL;
    bool acr = false;
    gds_status s = GDS_OK;
    if(job->trustList)
        s = run_trustlist(c, job, rep, &acr);
    if(s == GDS_OK && job->sign)
        s = run_certificate(c, job, rep, &acr);
    if(s == GDS_OK && acr) {
        UA_StatusCode r = gdsc_apply_changes(c);
        if(r == UA_STATUSCODE_GOOD)
            rep->applied = true;
        else
            s = failed(rep, PUSH_STEP_APPLY, r);
    }
    /* §7.10.2: discard the open transaction, whatever step failed. A
     * failure before the Server accepted anything leaves nothing to cancel. */
    if(s != GDS_OK && (rep->trustListUpdated || rep->certificateUpdated)) {
        rep->cancelled = true;
        rep->cancelCode = gdsc_cancel_changes(c);
    }
    return s;
}
