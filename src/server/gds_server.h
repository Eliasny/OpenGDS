/* OpenGDS - the GDS server: Directory, CertificateManager and the
 * DefaultApplicationGroup trust list on the standard GDS nodes of
 * open62541 v1.5.10 (OPC 10000-12 §6, §7).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_GDS_SERVER_H
#define OPENGDS_GDS_SERVER_H

#include <open62541/server.h>

#include <stdbool.h>

#include "ca.h"
#include "common/buf.h"
#include "gds_access.h"
#include "gds_jwt.h"
#include "gds_plugin.h"
#include "store.h"

/* GDS_APPROVE_RENEWALS: a request from an application that holds a valid
 * certificate in that group and of that type is approved on arrival;
 * other requests wait. Zero is not a policy, so a config that forgets it
 * is refused. */
typedef enum {
    GDS_APPROVE_ALL = 1,
    GDS_APPROVE_RENEWALS = 2,
    GDS_APPROVE_MANUAL = 3
} gds_approval_policy;

/* A KeyCredentialService (OPC 10000-12 §8.5.4) that the GDS offers: an
 * Object <name> under KeyCredentialManagement. resourceUri names the
 * resource (an MQTT broker, an authorization server ...) that accepts the
 * credentials; profileUris (1 .. GDS_MAX_KC_PROFILES) its authentication
 * mechanisms (OPC 10000-7). The GDS issues each application a random
 * CredentialId and secret for it and stores only a hash of the secret
 * (gds_keycred.c). name: 1 .. 64 of [A-Za-z0-9._-]. */
#define GDS_MAX_KC_SERVICES 8
#define GDS_MAX_KC_PROFILES 8
typedef struct {
    const char *name;
    const char *resourceUri;
    const char *const *profileUris;
    size_t profileUrisSize;
} gds_keycred_service;
/* The AuthorizationService (OPC 10000-12 §9.6, gds_authz.c): a GDS
 * object under AuthorizationServices that issues JWT AccessTokens (OPC
 * 10000-6 §6.5.2). The signer is a callback, so the key may live outside
 * opengdsd. Every buffer and string is copied by gds_server_new. */
typedef struct {
    /* the ServiceUri (§9.6.4), globally unique; NULL or "": the GDS's
     * ApplicationUri followed by "/AuthorizationService" */
    const char *serviceUri;
    /* the ServiceCertificate (§9.6.4): DER certificates back to back, the
     * one whose key signs the tokens first, then its issuers */
    gds_buf serviceCertificate;
    /* signs the JWS signing input with that key, for alg (RS256, ES256 or
     * ES384; gds_jwt.h) */
    gds_jwt_sign_fn sign;
    void *signCtx;
    const char *alg;
    /* Optional, in place of serviceCertificate: fetches the chain for the
     * ServiceUri (signCtx as ctx), at start and again when fewer than 30
     * days remain on the certificate (at most once an hour), so a renewed
     * certificate takes over without a restart (gds_ca_token_chain). */
    gds_status (*chain)(void *ctx, const char *serviceUri, gds_buf *out);
    /* AccessToken and RefreshToken lifetimes in seconds; refresh 0: no
     * RefreshTokens are issued */
    uint32_t accessLifetime;
    uint32_t refreshLifetime;
} gds_authz_config;

typedef struct {
    UA_UInt16 port;
    /* Host name in the endpoint URLs; NULL lets open62541 choose. When
     * loopbackOnly is set the server listens on 127.0.0.1 only. */
    const char *hostname;
    bool loopbackOnly;
    const char *applicationUri;
    const char *productUri;
    const char *applicationName;
    gds_buf ownCert; /* DER application instance certificate */
    gds_buf ownKey;  /* DER private key */
    /* User certificates (UASM ask A11): the PKI folder of the
     * DefaultUserTokenGroup (OPC 10000-12 §7.8.3.3; layout of Annex F.1,
     * UserTokenCerts/trusted, issuer, crl). X509IdentityTokens are offered
     * and checked against it only when set; the users file then maps each
     * certificate to a user. SecurityAdmin may change it over
     * ServerConfiguration. NULL: no X.509 user tokens. */
    const char *userPkiDir;
    gds_store *store; /* borrowed, read-write */
    gds_ca *ca;       /* borrowed: ca_ipc (signer) or in-process */
    const gds_users *users;
    /* Which certificate requests are approved on arrival; the others wait
     * for a RegistrationAuthorityAdmin (gds_approvals.c). */
    gds_approval_policy approval;
    /* KeyCredentialServices (0 .. GDS_MAX_KC_SERVICES); copied. They need
     * a store with the KeyCredential calls (store backend minor 8). The
     * approval policy applies to their requests as well. */
    const gds_keycred_service *keyCredServices;
    size_t keyCredServicesSize;
    /* NULL: no AuthorizationService (§9.6 is Optional) */
    const gds_authz_config *authz;
} gds_server_config;

typedef struct gds_server gds_server;

GDS_MUST_CHECK gds_status gds_server_new(const gds_server_config *cfg, gds_server **out);
/* Runs until *running is false. */
GDS_MUST_CHECK gds_status gds_server_run(gds_server *s, volatile UA_Boolean *running);
void gds_server_delete(gds_server *s);

/* ---- node role and ServiceLevel (cluster slot, UASM ask A3, issue #14) ----
 * OPC 10000-4 §6.6.2.4.2 fixes the ServiceLevel bands; every server of a
 * redundant set must use the same algorithm inside them, which only the
 * cluster plugin knows, so the plugin sets the exact value. The core only
 * keeps it inside the band its role allows:
 *   STANDALONE (no cluster plugin; the default, level 255): 0..255
 *   PRIMARY: 0..255
 *   STANDBY: 0..199 (never Healthy: clients must prefer the primary)
 * EstimatedReturnTime (OPC 10000-5 §6.3.1) is published for Maintenance
 * (level 0) only; for every other level it must be 0 (unknown) and reads
 * as the null DateTime. Both are safe to call from any thread. */
typedef enum {
    GDS_NODE_STANDALONE = 0,
    GDS_NODE_PRIMARY = 1,
    GDS_NODE_STANDBY = 2
} gds_node_role;

#define GDS_SERVICE_LEVEL_MAINTENANCE 0
#define GDS_SERVICE_LEVEL_NO_DATA 1
#define GDS_SERVICE_LEVEL_DEGRADED_MIN 2
#define GDS_SERVICE_LEVEL_HEALTHY_MIN 200

/* Changes the role and the level together. GDS_EINVAL: unknown role, a
 * level outside the role's band, or a return time with a level above 0. */
GDS_MUST_CHECK gds_status gds_server_set_role(gds_server *s, gds_node_role role, UA_Byte level,
                                              UA_DateTime estimatedReturnTime);
/* Same, keeping the current role. */
GDS_MUST_CHECK gds_status gds_server_set_service_level(gds_server *s, UA_Byte level,
                                                       UA_DateTime estimatedReturnTime);
gds_node_role gds_server_role(gds_server *s);

/* The other servers of a non-transparent redundant server set, which
 * FindServers returns after this server, each with its own DiscoveryUrls
 * (OPC 10000-4 §6.6.2.4.5.1; the serverUris filter of §5.5.2.2 applies to
 * them; UASM ask A15). Replaces the list atomically; n == 0 clears it.
 * Each needs an ApplicationUri other than this server's, a server
 * ApplicationType and at least one DiscoveryUrl. Copied; any thread.
 * GDS_EINVAL for a bad entry or a repeated ApplicationUri, GDS_ETOOBIG
 * above GDS_MAX_PEER_SERVERS. */
#define GDS_MAX_PEER_SERVERS 16
GDS_MUST_CHECK gds_status gds_server_set_peer_servers(gds_server *s,
                                                      const UA_ApplicationDescription *peers,
                                                      size_t n);

/* ---- plugin privileges (UASM ask A6, issue #17) ----
 * Adds a privilege provider (gds_plugin.h); the struct is copied, ctx is
 * borrowed. Call before gds_server_run. GDS_EINVAL for another ABI major
 * or a missing grant; GDS_ETOOBIG above 8 providers. */
GDS_MUST_CHECK gds_status gds_server_add_privilege_provider(gds_server *s,
                                                            const gds_privilege_provider *p);

/* The underlying open62541 server (tests). */
UA_Server *gds_server_ua(gds_server *s);

#endif
