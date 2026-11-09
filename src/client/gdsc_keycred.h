/* OpenGDS libgdsclient - KeyCredential wrappers (OPC 10000-12 v1.05.07 §8).
 * SPDX-License-Identifier: MPL-2.0
 *
 * Two sides:
 *   - the GDS (§8.5, pull): find a KeyCredentialService by name, request a
 *     credential for an application (StartRequest, FinishRequest) and
 *     revoke one (Revoke). The caller needs KeyCredentialAdmin, or is the
 *     application itself (§8.2);
 *   - a managed Server (§8.6, push): the KeyCredentialConfiguration
 *     Objects (find by ResourceUri, CreateCredential, GetEncryptingKey,
 *     UpdateCredential, DeleteCredential). The caller needs SecurityAdmin
 *     and an encrypted channel.
 *
 * Every function returns the OPC UA status of the call. Results are
 * checked (type, shape, length) before use: the peer may be hostile
 * (docs/architecture.md, "Input validation and limits"). Inputs are
 * borrowed; outputs are initialised by the callee and owned by the caller. */
#ifndef OPENGDS_CLIENT_GDSC_KEYCRED_H
#define OPENGDS_CLIENT_GDSC_KEYCRED_H

#include <open62541/client.h>

#include <stdbool.h>
#include <stddef.h>

#include "common/buf.h"
#include "common/compiler.h"

/* Bounds of what a peer may return */
#define GDSC_KC_ID_MAX 128          /* CredentialId */
#define GDSC_KC_URI_MAX 1024        /* ResourceUri, ProfileUri, SecurityPolicyUri */
#define GDSC_KC_SECRET_MAX 4096     /* a plaintext secret */
#define GDSC_KC_MAX_OBJECTS 64      /* KeyCredentialConfiguration Objects looked at */

/* ---- The GDS (§8.5) ---- */

/* A KeyCredentialService Object under KeyCredentialManagement (§8.5.3) */
typedef struct {
    UA_NodeId node;
    UA_UInt16 ns; /* the GDS namespace */
    char resourceUri[GDSC_KC_URI_MAX + 1];
    char profileUri[GDSC_KC_URI_MAX + 1]; /* the first of its ProfileUris */
} gdsc_kc_service;

/* The service with BrowseName ns:name. Bad_NotFound: no such service. */
GDS_MUST_CHECK UA_StatusCode gdsc_kc_service_find(UA_Client *c, UA_UInt16 ns, const char *name,
                                                  gdsc_kc_service *out);
void gdsc_kc_service_clear(gdsc_kc_service *s);

/* StartRequest(applicationUri, no PublicKey, no SecurityPolicyUri, no
 * roles) and FinishRequest until the GDS has an answer, polling for up to
 * pollSeconds while it answers Bad_RequestNotComplete (§8.5.6, approval).
 * The secret comes back in plain text inside the encrypted session; wipe
 * it with gds_buf_free_secret. */
GDS_MUST_CHECK UA_StatusCode gdsc_kc_request(UA_Client *c, const gdsc_kc_service *svc,
                                             const char *applicationUri, unsigned pollSeconds,
                                             char credentialId[GDSC_KC_ID_MAX + 1],
                                             gds_buf *secret);

/* Revoke(CredentialId) (§8.5.7) */
GDS_MUST_CHECK UA_StatusCode gdsc_kc_revoke(UA_Client *c, const gdsc_kc_service *svc,
                                            const char *credentialId);

/* ---- A managed Server (§8.6) ---- */

/* The KeyCredentialConfiguration Object whose ResourceUri is resourceUri.
 * Bad_NotFound: none; Bad_NotSupported: the Server has no
 * KeyCredentialConfiguration Object (§8.6.4). */
GDS_MUST_CHECK UA_StatusCode gdsc_kc_config_find(UA_Client *c, const char *resourceUri,
                                                 UA_NodeId *out);

/* CreateCredential (§8.6.3) */
GDS_MUST_CHECK UA_StatusCode gdsc_kc_config_create(UA_Client *c, const char *name,
                                                   const char *resourceUri,
                                                   const char *profileUri,
                                                   const char *const *endpointUrls,
                                                   size_t endpointUrlsN, UA_NodeId *out);

/* GetEncryptingKey (§8.6.6): *key is the PublicKey (bounded by
 * GDS_MAX_CERT_SIZE), policy the RevisedSecurityPolicyUri. */
GDS_MUST_CHECK UA_StatusCode gdsc_kc_config_key(UA_Client *c, const UA_NodeId *obj,
                                                const char *credentialId,
                                                const char *requestedPolicy, gds_buf *key,
                                                char policy[GDSC_KC_URI_MAX + 1]);

/* UpdateCredential (§8.6.7). thumbprint and policy "" for a plaintext
 * secret. */
GDS_MUST_CHECK UA_StatusCode gdsc_kc_config_update(UA_Client *c, const UA_NodeId *obj,
                                                   const char *credentialId,
                                                   const gds_buf *secret, const char *thumbprint,
                                                   const char *policy);

/* DeleteCredential (§8.6.8) */
GDS_MUST_CHECK UA_StatusCode gdsc_kc_config_delete(UA_Client *c, const UA_NodeId *obj);

/* The CredentialId Property of the Object (Optional, §8.6.5): "" when the
 * Server has none or leaves it empty. */
GDS_MUST_CHECK UA_StatusCode gdsc_kc_config_id(UA_Client *c, const UA_NodeId *obj,
                                               char id[GDSC_KC_ID_MAX + 1]);

#endif
