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

/* ---- plugin privileges (UASM ask A6, issue #17) ----
 * Adds a privilege provider (gds_plugin.h); the struct is copied, ctx is
 * borrowed. Call before gds_server_run. GDS_EINVAL for another ABI major
 * or a missing grant; GDS_ETOOBIG above 8 providers. */
GDS_MUST_CHECK gds_status gds_server_add_privilege_provider(gds_server *s,
                                                            const gds_privilege_provider *p);

/* The underlying open62541 server (tests). */
UA_Server *gds_server_ua(gds_server *s);

#endif
