/* OpenGDS Auditor server profile - the push-managed Server under test, seen
 * only through standard OPC UA (black box). The Auditor plays the
 * CertificateManager (OPC 10000-12 §7.10, Annex G.2).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_SRV_TARGET_H
#define GDSAUDIT_SRV_TARGET_H

#include <open62541/client.h>

#include "common/limits.h"
#include "harness.h"
#include "test_ca.h"
#include "uaclient.h"

/* TrustListMasks (12 §7.8.2.9) */
#define ST_MASK_ALL 15u
/* FileType Open modes (OPC 10000-5 Annex C.2.1) */
#define ST_OPEN_READ 0x01
#define ST_OPEN_WRITE_ERASE 0x06

typedef struct {
    /* configuration */
    const char *url;
    const char *adminUser;     /* SecurityAdmin user (NULL: adminCert is the identity) */
    const char *userName;      /* the `user` fixture: authenticated, no SecurityAdmin (NULL: none) */
    const char *appUri;        /* ApplicationUri in cert */
    UA_Client *client;         /* the admin session; it holds the transaction across tests */
    gds_buf cert, key;         /* the Auditor's plain application identity (no SecurityAdmin) */
    gds_buf adminCert, adminKey; /* the application identity the target maps to SecurityAdmin */
    gds_buf pinned;            /* the target's certificate, trusted at the start of the run */
    testca_t ca;               /* the run's test CA ("OpenGDS Auditor TEST") */
    gds_buf caDer, caCrl;
    gds_buf peerCert, peerKey; /* peer-good: client certificate from ca */
    gds_buf snapCert;          /* snapshot: the certificate the endpoint presented */
    gds_buf tGood;             /* t-good, queued by SRV-UPD-01 */
    UA_NodeId certType;        /* the DefaultApplicationGroup CertificateType under test */
    UA_TrustListDataType snap;   /* snapshot before the first write (README, "Safety") */
    UA_TrustListDataType pushed; /* applied by SRV-TL-02 */
    UA_TrustListDataType queued; /* queued and applied by SRV-TXN-03 */
    /* state handed from test to test, in catalogue order */
    bool snapTaken;
    bool tlPushed;             /* SRV-TL-02 passed: ca is in the applied trust list */
    bool certQueued;           /* SRV-UPD-01 queued t-good in the admin session */
    bool applied;              /* SRV-TXN-03 passed: t-good and the queued list are in use */
    bool restored;             /* the snapshot was pushed back */
    char adminPassword[256];
    char userPassword[256];
    char targetUri[GDS_MAX_APPLICATION_URI + 1]; /* learned from GetEndpoints */
} srv_target;

/* Status of the target's verdict-relevant calls is always noted with ga_note. */

/* Who a connection acts as (catalogue fixtures admin, user, anon) */
typedef enum { ST_ADMIN, ST_USER, ST_ANON } st_role;

/* A fresh client. ST_ADMIN uses the admin application identity (unless an
 * admin user is configured), the others the plain one. It trusts the pinned
 * target certificate (only if withPinned), the test CA and its CRL. */
UA_Client *st_new_client(const srv_target *t, st_role role, bool withPinned,
                         const char *policyUri, UA_MessageSecurityMode mode);
/* Connect a client from st_new_client with the role's identity token. */
GDS_MUST_CHECK UA_StatusCode st_connect(const srv_target *t, st_role role, UA_Client *c);
/* st_new_client + st_connect; *out is NULL on error. */
GDS_MUST_CHECK UA_StatusCode st_open(const srv_target *t, st_role role, const char *policyUri,
                                     UA_MessageSecurityMode mode, UA_Client **out);
/* Connect as SecurityAdmin over SignAndEncrypt, or reuse the open session. */
GDS_MUST_CHECK UA_StatusCode st_admin(srv_target *t);
/* A second admin session on its own connection (fresh read-back). */
GDS_MUST_CHECK UA_StatusCode st_admin_fresh(const srv_target *t, bool withPinned, UA_Client **out);
void st_close(srv_target *t);
void st_client_free(UA_Client *c);
void st_clear(srv_target *t);

/* GetEndpoints over the discovery channel. Endpoint certificates are bounded
 * by GDS_MAX_CERT_SIZE; the caller frees with UA_Array_delete. */
GDS_MUST_CHECK UA_StatusCode st_endpoints(const srv_target *t, UA_EndpointDescription **eps,
                                          size_t *n);
/* The certificate of the first SignAndEncrypt endpoint (owned by caller). */
GDS_MUST_CHECK UA_StatusCode st_presented(const srv_target *t, gds_buf *out);

/* Open(0x06) -> Write in chunks -> CloseAndUpdate on the DefaultApplicationGroup
 * TrustList. *applyRequired is the CloseAndUpdate output. */
GDS_MUST_CHECK UA_StatusCode st_write_trustlist(UA_Client *c, const UA_TrustListDataType *tl,
                                                size_t chunk, bool *applyRequired,
                                                ga_ctx *ctx);
/* OpenWithMasks -> Read until empty -> Close, decoded and bounded. */
GDS_MUST_CHECK UA_StatusCode st_read_trustlist(UA_Client *c, UA_UInt32 masks,
                                               UA_TrustListDataType *out);
GDS_MUST_CHECK UA_StatusCode st_apply(UA_Client *c);
/* CreateSigningRequest on the DefaultApplicationGroup for t->certType. */
GDS_MUST_CHECK UA_StatusCode st_csr(const srv_target *t, UA_Client *c, bool regen,
                                    const UA_ByteString *nonce, gds_buf *csr);
/* CreateSigningRequest(group, type, no subject, regen, nonce). */
GDS_MUST_CHECK UA_StatusCode st_csr_for(UA_Client *c, UA_NodeId group, UA_NodeId type, bool regen,
                                        const UA_ByteString *nonce, gds_buf *csr);
/* UpdateCertificate(DefaultApplicationGroup, t->certType, cert, issuers). */
GDS_MUST_CHECK UA_StatusCode st_update_cert(const srv_target *t, UA_Client *c,
                                            const gds_buf *cert, const gds_buf *issuers,
                                            size_t issuersN, bool *applyRequired);
/* st_update_cert with a PrivateKeyFormat and PrivateKey (NULL: none). */
GDS_MUST_CHECK UA_StatusCode st_update_cert_key(const srv_target *t, UA_Client *c,
                                                const gds_buf *cert, const gds_buf *issuers,
                                                size_t issuersN, const char *keyFormat,
                                                const gds_buf *key, bool *applyRequired);
/* Read ServerConfiguration.SupportsTransactions; *present false if absent. */
void st_supports_transactions(UA_Client *c, bool *present, bool *value);

/* Set equality of the four lists (order ignored). On a difference, why
 * names the first list that differs. */
bool st_lists_equal(const UA_TrustListDataType *a, const UA_TrustListDataType *b, char *why,
                    size_t whyLen);
/* dst = src plus the certificate/CRL (deep copy). */
GDS_MUST_CHECK UA_StatusCode st_list_copy_add(const UA_TrustListDataType *src,
                                              const gds_buf *trustedCert,
                                              const gds_buf *trustedCrl,
                                              UA_TrustListDataType *dst);

/* Learn targetUri (GetEndpoints) and certType (DefaultApplicationGroup
 * CertificateTypes, RsaSha256 preferred). Idempotent. */
GDS_MUST_CHECK UA_StatusCode st_learn(srv_target *t, ga_ctx *ctx);

/* Read the snapshot before the first write (idempotent). */
GDS_MUST_CHECK UA_StatusCode st_snapshot(srv_target *t, ga_ctx *ctx);

/* The certificate type a SecurityPolicy uses (12 §7.8.4.8, §7.8.4.9 and the
 * ECC types of §7.8.4.10ff). NULL NodeId if the policy is unknown or None. */
UA_NodeId st_policy_cert_type(const UA_String *policyUri);

/* Push the snapshot back and apply (README, "Safety, snapshot and restore").
 * On a problem, why says what is left changed. */
GDS_MUST_CHECK UA_StatusCode st_restore(srv_target *t, char *why, size_t whyLen);

const char *st_short_policy(const UA_String *policyUri);

#endif
