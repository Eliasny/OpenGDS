/* OpenGDS libgdsclient - secure sessions to a GDS or to a push-managed
 * Server (OpenGDS plan, push_session.c; used by the push engine and gdsadm).
 * SPDX-License-Identifier: MPL-2.0
 *
 * A session is SignAndEncrypt with the strongest non-deprecated
 * SecurityPolicy the Server offers that our certificate can use (12 §7.4:
 * push management requires an encrypted channel; §7.3 the same for pull).
 * The Server certificate is checked against an explicit trust list: no trust
 * on first use (docs/architecture.md, "Secure by default").
 *
 * Identity (12 §7.7.2, Connect step): the ApplicationInstance Certificate
 * with an Anonymous token, an X509IdentityToken of the same certificate, or
 * a user name and password (an administrator, 12 §7.4). */
#ifndef OPENGDS_CLIENT_GDSC_SESSION_H
#define OPENGDS_CLIENT_GDSC_SESSION_H

#include <open62541/client.h>

#include "common/buf.h"
#include "common/compiler.h"

typedef enum {
    /* Anonymous UserIdentityToken: the SecureChannel's ApplicationInstance
     * Certificate carries the role (Annex G.3) */
    GDSC_IDENTITY_APP_CERT = 0,
    /* X509IdentityToken: identityCert and identityKey below, or else the
     * same certificate and key as the SecureChannel */
    GDSC_IDENTITY_X509 = 1,
    /* UserNameIdentityToken (userName, password below) */
    GDSC_IDENTITY_USERNAME = 2
} gdsc_identity;

typedef struct {
    const char *endpointUrl;    /* opc.tcp://host:port of the managed Server */
    const char *serverUri;      /* expected ApplicationUri of the Server; NULL = no check */
    const char *applicationUri; /* our own ApplicationUri; NULL = from cert's SAN URI */
    const gds_buf *cert;        /* our ApplicationInstance Certificate (DER) */
    const gds_buf *key;         /* its private key (DER) */
    const gds_buf *trust;       /* certificates that may vouch for the Server: CA, or its pinned certificate */
    size_t trustN;
    const gds_buf *crls;
    size_t crlN;
    gdsc_identity identity;
    /* GDSC_IDENTITY_X509 only, both or neither: a user certificate (DER)
     * and its private key (DER) for the X509IdentityToken (OPC 10000-4
     * §7.41.5), e.g. one an administrator maps to SecurityAdmin on the
     * managed Server, apart from the ApplicationInstance Certificate */
    const gds_buf *identityCert;
    const gds_buf *identityKey;
    const char *userName;    /* GDSC_IDENTITY_USERNAME only */
    const gds_buf *password; /* GDSC_IDENTITY_USERNAME only; no NUL bytes */
    UA_UInt32 timeoutMs; /* per request; 0 = 10 s */
} gdsc_session_cfg;

typedef struct gdsc_session gdsc_session;

/* The URI SubjectAltName of a DER certificate (the ApplicationUri, OPC
 * 10000-6 §6.2.2), NUL-terminated into out. */
GDS_MUST_CHECK gds_status gdsc_cert_uri(const gds_buf *certDer, char *out, size_t outLen);

/* Rank of a SecurityPolicy URI for push: higher is stronger; 0 = refused
 * (None, deprecated Basic128Rsa15 and Basic256, unknown). */
int gdsc_policy_rank(const UA_String *policyUri);

/* The CertificateType whose certificate an endpoint with this
 * SecurityPolicy presents (12 §7.8.4.8 - §7.8.4.16); NULL NodeId for None
 * and unknown policies. */
UA_NodeId gdsc_policy_cert_type(const UA_String *policyUri);

/* Pick the SignAndEncrypt endpoint with the highest-ranked policy among
 * those `usable` names (the policies our certificate supports) that offers
 * the UserTokenType the identity needs (Anonymous, Certificate or UserName, OPC
 * 10000-4 §7.41). Returns Bad_SecurityPolicyRejected if no endpoint has a
 * usable policy, Bad_IdentityTokenInvalid if none of those offers the token.
 * Pure: no I/O. */
GDS_MUST_CHECK UA_StatusCode gdsc_select_endpoint(const UA_EndpointDescription *eps, size_t n,
                                                  const UA_String *usable, size_t usableN,
                                                  gdsc_identity identity, size_t *idx);

/* GetEndpoints, select, check the Server's ApplicationUri, connect and
 * activate the session. *out is freed with gdsc_session_close. */
GDS_MUST_CHECK UA_StatusCode gdsc_session_open(const gdsc_session_cfg *cfg, gdsc_session **out);
UA_Client *gdsc_session_client(gdsc_session *s);
/* SecurityPolicy URI of the open channel (borrowed) */
const UA_String *gdsc_session_policy(const gdsc_session *s);
/* The Server certificate the SecureChannel was opened with, as the client
 * verified it (DER, a copy; free with gds_buf_free). GDS_ENOTFOUND if none
 * was seen. */
GDS_MUST_CHECK gds_status gdsc_session_server_cert(const gdsc_session *s, gds_buf *out);
void gdsc_session_close(gdsc_session *s);

/* After ApplyChanges: the Server's SignAndEncrypt endpoints whose
 * SecurityPolicy uses `certType` present `cert` as their leaf certificate.
 * UpdateCertificate replaces only that CertificateType's certificate
 * (12 §7.8.4), so endpoints of other types keep theirs. 12 §7.7.2:
 * ApplyChanges may close the endpoints, so this uses a fresh discovery
 * connection, retried until timeoutMs passes. */
GDS_MUST_CHECK UA_StatusCode gdsc_wait_presents(const char *endpointUrl, const UA_NodeId *certType,
                                                const gds_buf *cert, UA_UInt32 timeoutMs);

#endif
