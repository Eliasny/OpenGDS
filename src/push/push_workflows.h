/* OpenGDS push engine - the Part 12 push workflows on one open session
 * (OPC 10000-12 v1.05.07 §7.7.2 Update Certificates, §7.7.3 Update TrustList,
 * §7.7.4 Update Single Certificate; §7.10.2 transactions).
 * SPDX-License-Identifier: MPL-2.0
 *
 * Order (§7.7.2): the TrustList of the group first, so that CRLs and the
 * issuer arrive before the certificate that depends on them, then the
 * certificate (CreateSigningRequest -> sign -> UpdateCertificate), then
 * ApplyChanges if any step returned applyChangesRequired = TRUE. If a step
 * fails after the Server accepted an earlier one, CancelChanges discards the
 * transaction (§7.10.2) and nothing is applied. */
#ifndef OPENGDS_PUSH_WORKFLOWS_H
#define OPENGDS_PUSH_WORKFLOWS_H

#include <open62541/client.h>
#include <open62541/types_gds_generated.h>

#include <stdbool.h>

#include "common/buf.h"
#include "common/compiler.h"
#include "common/limits.h"

/* Signs the Server's CSR: gdsadm sends it to the GDS (StartSigningRequest,
 * FinishRequest); inside opengdsd it would record a store request and call
 * gds_ca_sign_csr. Either way every field comes from the registered record
 * (decision G5). The callback may also return the issuer chain
 * (issuersOut has GDS_MAX_CHAIN_LEN slots); when it returns none, the job's
 * issuers are sent. Outputs are owned by the caller (the report). */
typedef gds_status (*push_sign_fn)(void *ctx, const gds_buf *csrDer, gds_buf *certOut,
                                   gds_buf *issuersOut, size_t *issuersN);

typedef struct {
    UA_NodeId certificateGroup; /* e.g. GDSC_DEFAULT_APP_GROUP */
    UA_NodeId trustListNode;    /* that group's TrustList */
    UA_NodeId certificateType;  /* e.g. GDSC_RSA_SHA256_APP_CERT */
    /* NULL: leave the TrustList as it is */
    const UA_TrustListDataType *trustList;
    /* NULL: leave the certificate as it is */
    push_sign_fn sign;
    void *signCtx;
    const gds_buf *issuers; /* CA chain sent with UpdateCertificate */
    size_t issuersN;
} push_job;

typedef enum {
    PUSH_STEP_NONE = 0,
    PUSH_STEP_TRUSTLIST,
    PUSH_STEP_CSR,
    PUSH_STEP_SIGN,
    PUSH_STEP_UPDATE_CERT,
    PUSH_STEP_APPLY
} push_step;

typedef struct {
    push_step failedStep;      /* PUSH_STEP_NONE on success */
    UA_StatusCode failedCode;  /* status of the failed step */
    bool trustListUpdated;     /* CloseAndUpdate returned Good */
    bool certificateUpdated;   /* UpdateCertificate returned Good */
    bool applied;              /* ApplyChanges returned Good */
    bool cancelled;            /* CancelChanges was called after a failure */
    UA_StatusCode cancelCode;  /* its result (Bad_MethodInvalid: Server has no transactions) */
    gds_buf issued;            /* the certificate sent, DER; freed by push_report_clear */
    gds_buf issuers[GDS_MAX_CHAIN_LEN]; /* issuer chain from the sign callback */
    size_t issuersN;
} push_report;

void push_report_clear(push_report *r);
const char *push_step_name(push_step s);

/* Run the job on an open, activated session. GDS_OK when every requested
 * step succeeded; GDS_EREMOTE when the Server refused one (see report),
 * GDS_ECRYPTO/other when signing failed. */
GDS_MUST_CHECK gds_status push_run(UA_Client *c, const push_job *job, push_report *report);

#endif
