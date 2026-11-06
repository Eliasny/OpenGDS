/* OpenGDS push engine - sessions to managed Servers (OpenGDS plan,
 * src/push/push_session.c).
 * SPDX-License-Identifier: MPL-2.0
 *
 * A push session is SignAndEncrypt with the strongest non-deprecated
 * SecurityPolicy the Server offers that our certificate can use (12 §7.4:
 * push management requires an encrypted channel). The Server certificate is
 * checked against an explicit trust list: no trust on first use
 * (docs/architecture.md, "Secure by default"). The CertificateManager
 * authenticates with its ApplicationInstance Certificate, or with an
 * X509IdentityToken of the same certificate (12 §7.7.2, Connect step); the
 * Server maps either to SecurityAdmin. */
#ifndef OPENGDS_PUSH_SESSION_H
#define OPENGDS_PUSH_SESSION_H

#include <open62541/client.h>

#include "common/buf.h"
#include "common/compiler.h"

typedef enum {
    /* Anonymous UserIdentityToken: the SecureChannel's ApplicationInstance
     * Certificate carries the role (Annex G.3) */
    PUSH_IDENTITY_APP_CERT = 0,
    /* X509IdentityToken with the same certificate and key */
    PUSH_IDENTITY_X509 = 1
} push_identity;

typedef struct {
    const char *endpointUrl;    /* opc.tcp://host:port of the managed Server */
    const char *serverUri;      /* expected ApplicationUri of the Server; NULL = no check */
    const char *applicationUri; /* our own (the GDS's) ApplicationUri */
    const gds_buf *cert;        /* our ApplicationInstance Certificate (DER) */
    const gds_buf *key;         /* its private key (DER) */
    const gds_buf *trust;       /* certificates that may vouch for the Server: CA, or its pinned certificate */
    size_t trustN;
    const gds_buf *crls;
    size_t crlN;
    push_identity identity;
    UA_UInt32 timeoutMs; /* per request; 0 = 10 s */
} push_session_cfg;

typedef struct push_session push_session;

/* Rank of a SecurityPolicy URI for push: higher is stronger; 0 = refused
 * (None, deprecated Basic128Rsa15 and Basic256, unknown). */
int push_policy_rank(const UA_String *policyUri);

/* Pick the SignAndEncrypt endpoint with the highest-ranked policy among
 * those `usable` names (the policies our certificate supports) that offers
 * the UserTokenType the identity needs (Anonymous or Certificate, OPC
 * 10000-4 §7.41). Returns Bad_SecurityPolicyRejected if no endpoint has a
 * usable policy, Bad_IdentityTokenInvalid if none of those offers the token.
 * Pure: no I/O. */
GDS_MUST_CHECK UA_StatusCode push_select_endpoint(const UA_EndpointDescription *eps, size_t n,
                                                  const UA_String *usable, size_t usableN,
                                                  push_identity identity, size_t *idx);

/* GetEndpoints, select, check the Server's ApplicationUri, connect and
 * activate the session. *out is freed with push_session_close. */
GDS_MUST_CHECK UA_StatusCode push_session_open(const push_session_cfg *cfg, push_session **out);
UA_Client *push_session_client(push_session *s);
/* SecurityPolicy URI of the open channel (borrowed) */
const UA_String *push_session_policy(const push_session *s);
void push_session_close(push_session *s);

/* After ApplyChanges: the Server's SignAndEncrypt endpoints present `cert`
 * as their leaf certificate (12 §7.7.2: ApplyChanges may close the
 * endpoints, so this uses a fresh discovery connection, retried until
 * timeoutMs passes). */
GDS_MUST_CHECK UA_StatusCode push_wait_presents(const char *endpointUrl, const gds_buf *cert,
                                                UA_UInt32 timeoutMs);

#endif
