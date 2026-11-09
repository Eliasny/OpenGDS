/* OpenGDS push - KeyCredentials to a managed Server (OPC 10000-12 v1.05.07
 * §8.4, §8.6) on one open session.
 * SPDX-License-Identifier: MPL-2.0
 *
 * push_keycred_run, as the administration component of §8.4:
 *   1. find the KeyCredentialConfiguration Object for the ResourceUri, or
 *      make one with CreateCredential (§8.6.3);
 *   2. get the credential (CredentialId and secret) from the issue
 *      callback: gdsadm asks the GDS (StartRequest/FinishRequest, §8.5);
 *      the GDS keeps only a hash of the secret;
 *   3. GetEncryptingKey (§8.6.6) for an RSA SecurityPolicy;
 *   4. encrypt the secret for the Server's certificate as an
 *      RsaEncryptedSecret (OPC 10000-4 §7.40.2.4). The PublicKey of step 3
 *      is that certificate; when it is not one, the certificate the Server
 *      presented on the channel is used (§8.4: "uses the GetEndpoints
 *      Service to read the Certificate"). A secret is never sent in plain
 *      text, although §8.6.7 would allow it inside the encrypted channel;
 *   5. UpdateCredential (§8.6.7).
 * Steps 1 and 3 come before and after 2 so that the GDS issues a new
 * credential (which replaces the application's earlier one, §8.5.6) only
 * when the Server is reachable and lets the caller manage credentials.
 *
 * push_keycred_delete: DeleteCredential (§8.6.8) on the Object for the
 * ResourceUri; its CredentialId is returned so the caller can Revoke it
 * on the GDS (§8.5.7). */
#ifndef OPENGDS_PUSH_KEYCRED_H
#define OPENGDS_PUSH_KEYCRED_H

#include <open62541/client.h>

#include <stdbool.h>

#include "client/gdsc_keycred.h"
#include "common/buf.h"
#include "common/compiler.h"
#include "common/errors.h"

/* Issues the credential the Server is to hold. credentialId is
 * NUL-terminated; *secret is the plain secret (wiped by the caller with
 * gds_buf_free_secret). */
typedef gds_status (*push_kc_issue_fn)(void *ctx, char credentialId[GDSC_KC_ID_MAX + 1],
                                       gds_buf *secret);

typedef struct {
    const char *name;        /* BrowseName of a new Object (CreateCredential) */
    const char *resourceUri; /* of the KeyCredentialService */
    const char *profileUri;
    const char *const *endpointUrls; /* the resource's URLs, for a new Object */
    size_t endpointUrlsN;
    push_kc_issue_fn issue;
    void *issueCtx;
    /* the certificate the Server presented on this session's channel
     * (DER), used when GetEncryptingKey returns no certificate; may be NULL */
    const gds_buf *serverCert;
} push_kc_job;

typedef enum {
    PUSH_KC_STEP_NONE = 0,
    PUSH_KC_STEP_FIND,
    PUSH_KC_STEP_CREATE,
    PUSH_KC_STEP_ISSUE,
    PUSH_KC_STEP_KEY,
    PUSH_KC_STEP_ENCRYPT,
    PUSH_KC_STEP_UPDATE,
    PUSH_KC_STEP_DELETE
} push_kc_step;

typedef struct {
    push_kc_step failedStep;  /* PUSH_KC_STEP_NONE on success */
    UA_StatusCode failedCode; /* status of the failed step */
    bool created;             /* CreateCredential made the Object */
    bool updated;             /* UpdateCredential returned Good */
    bool deleted;             /* DeleteCredential returned Good */
    char credentialId[GDSC_KC_ID_MAX + 1]; /* the one pushed, or the deleted one's */
    char policy[GDSC_KC_URI_MAX + 1];      /* the SecurityPolicy the secret used */
} push_kc_report;

GDS_MUST_CHECK gds_status push_keycred_run(UA_Client *c, const push_kc_job *job,
                                           push_kc_report *rep);
GDS_MUST_CHECK gds_status push_keycred_delete(UA_Client *c, const char *resourceUri,
                                              push_kc_report *rep);
const char *push_kc_step_name(push_kc_step s);

#endif
