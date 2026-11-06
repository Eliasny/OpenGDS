/* OpenGDS - users, roles and sessions (OPC 10000-12 §6.2, §7.2; OPC
 * 10000-3 well-known roles). Every GDS method checks the caller's session
 * here before it touches any input.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_GDS_ACCESS_H
#define OPENGDS_GDS_ACCESS_H

#include <open62541/server.h>

#include <stdbool.h>
#include <stdint.h>

#include "common/buf.h"
#include "common/compiler.h"
#include "common/limits.h"

/* Roles a users file can grant (OPC 10000-3 well-known Roles, OPC 10000-18
 * §4.3, OPC 10000-12 §6.2 Table 1 and §7.2, OPC 10000-14 SKS Roles). The
 * GDS methods use the first three; the rest are for plugins, which see
 * them as Role NodeIds in their gds_caller (gds_plugin.h). Anonymous and
 * AuthenticatedUser are never granted by the file: every session has
 * Anonymous, and every session with user credentials AuthenticatedUser. */
typedef enum {
    GDS_ROLE_DISCOVERY_ADMIN = 1u << 0,             /* Directory changes */
    GDS_ROLE_CERTIFICATE_AUTHORITY_ADMIN = 1u << 1, /* CertificateManager for any application */
    GDS_ROLE_SECURITY_ADMIN = 1u << 2,              /* write the GDS trust lists */
    GDS_ROLE_OBSERVER = 1u << 3,
    GDS_ROLE_OPERATOR = 1u << 4,
    GDS_ROLE_ENGINEER = 1u << 5,
    GDS_ROLE_SUPERVISOR = 1u << 6,
    GDS_ROLE_CONFIGURE_ADMIN = 1u << 7,
    GDS_ROLE_REGISTRATION_AUTHORITY_ADMIN = 1u << 8,
    GDS_ROLE_KEY_CREDENTIAL_ADMIN = 1u << 9,
    GDS_ROLE_AUTHORIZATION_SERVICE_ADMIN = 1u << 10,
    GDS_ROLE_SKS_ADMIN = 1u << 11,  /* SecurityKeyServerAdmin */
    GDS_ROLE_SKS_PUSH = 1u << 12,   /* SecurityKeyServerPush */
    GDS_ROLE_SKS_ACCESS = 1u << 13  /* SecurityKeyServerAccess */
} gds_role;

/* One grantable Role: its users-file name and its NodeId (namespace 0, or
 * the GDS namespace when gdsNamespace is set). */
typedef struct {
    const char *name;
    unsigned bit;
    bool gdsNamespace;
    UA_UInt32 id;
} gds_role_info;
/* The table of built-in grantable Roles, in bit order. */
const gds_role_info *gds_role_table(size_t *n);

/* Embedder Roles (UASM ask A10, issue #63): Roles an embedder defines with
 * gds_server_add_role before the server runs, such as the OPC 10000-21
 * RegistrarAdmin. They take the bits from GDS_ROLE_EMBED_FIRST_BIT up, in
 * the order they were added. */
#define GDS_ROLE_BUILTIN_COUNT 14u
#define GDS_ROLE_EMBED_FIRST_BIT GDS_ROLE_BUILTIN_COUNT
#define GDS_MAX_EMBED_ROLES 16u
#define GDS_MAX_ROLE_NAME 64
/* Every grantable Role, built-in first: there are gds_role_count() of
 * them. gds_role_at gives the i-th one's NodeId (gdsNs is the GDS
 * namespace index; the NodeId is shallow and valid until the server is
 * deleted), bit and users-file name. */
size_t gds_role_count(void);
void gds_role_at(size_t i, UA_UInt16 gdsNs, UA_NodeId *id, unsigned *bit, const char **name);
/* The bit of a grantable Role NodeId, 0 if it is none. */
unsigned gds_role_bit(UA_UInt16 gdsNs, const UA_NodeId *id);
/* Add an embedder Role (gds_server_add_role does the server part).
 * GDS_EEXISTS for a name or NodeId that is taken (built-in, embedder, or
 * Anonymous/AuthenticatedUser), GDS_EINVAL for a bad name or a null
 * NodeId, GDS_ETOOBIG past GDS_MAX_EMBED_ROLES. */
GDS_MUST_CHECK gds_status gds_access_add_role(const char *name, const UA_NodeId *id,
                                              UA_UInt16 gdsNs);
/* Undo the last gds_access_add_role. */
void gds_access_drop_last_role(void);
/* Every Role name in the installed users file is a Role by now:
 * GDS_EINVAL (and a line on stderr) for the first that is not. */
GDS_MUST_CHECK gds_status gds_access_check_users(void);

#define GDS_PBKDF2_SALT 16
#define GDS_PBKDF2_HASH 32
#define GDS_PBKDF2_DEFAULT_ITER 100000
#define GDS_MAX_USERS 64
#define GDS_MAX_USER_NAME 64

typedef struct {
    char name[GDS_MAX_USER_NAME + 1];
    unsigned roles; /* the built-in Roles */
    /* Names that are not built-in Roles: embedder Roles (A10), which are
     * resolved when the user logs in. gds_server_run refuses to start if
     * one names no Role. */
    char embedRoles[GDS_MAX_EMBED_ROLES][GDS_MAX_ROLE_NAME + 1];
    size_t nEmbedRoles;
    uint32_t iterations;
    uint8_t salt[GDS_PBKDF2_SALT];
    uint8_t hash[GDS_PBKDF2_HASH];
} gds_user;

typedef struct {
    gds_user users[GDS_MAX_USERS];
    size_t n;
} gds_users;

/* Users file: one user per line, '#' comments:
 *   <name> <Role[,Role...]|-> pbkdf2-sha256:<iterations>:<salt hex>:<hash hex>
 * Roles: the names in gds_role_table (DiscoveryAdmin, SecurityAdmin,
 * SecurityKeyServerAdmin, ...) and embedder Role names, which are checked
 * when the server starts (gds_server_add_role may come after this load).
 * Anonymous and AuthenticatedUser are refused. The file must not be
 * readable by others (mode 0600 or 0640). */
GDS_MUST_CHECK gds_status gds_users_load(const char *path, gds_users *out);
/* The users-file credential for a password (gdsadm hash-password). */
GDS_MUST_CHECK gds_status gds_password_hash(const uint8_t *pw, size_t len, uint32_t iterations,
                                            char *out, size_t outLen);
/* NULL if unknown or wrong; constant time in the password. */
const gds_user *gds_users_check(const gds_users *u, const UA_String *name, const UA_ByteString *pw);

/* Per-session state, the open62541 session context. */
#define GDS_SESSION_TL_HANDLES GDS_MAX_TL_HANDLES
typedef struct {
    UA_UInt32 handle; /* 0 = free */
    UA_ByteString file;
    size_t pos;
} gds_tl_handle;

typedef struct {
    bool anonymous;
    char user[GDS_MAX_USER_NAME + 1];
    unsigned roles;
    UA_String clientAppUri; /* SAN URI of the channel's client certificate */
    UA_ByteString clientCert; /* the channel's client certificate (DER), any issuer */
    /* Set only on a job's copy (gds_embed.c): the embedder's may_manage
     * hook (A14) allowed this ApplicationId. */
    bool managedGranted;
    UA_Guid managedApp;
    UA_MessageSecurityMode securityMode; /* of the session's endpoint */
    UA_String securityPolicyUri;
    gds_tl_handle tl[GDS_SESSION_TL_HANDLES];
} gds_session;

/* Replace config->accessControl: anonymous and user name tokens over
 * encrypted channels only; sessionContext becomes a gds_session. The users
 * table must outlive the server. caCertDer is the GDS CA: only a client
 * certificate it issued gives a session the application's own rights.
 * One GDS server per process. */
GDS_MUST_CHECK gds_status gds_access_install(UA_ServerConfig *config, const gds_users *users,
                                             const gds_buf *caCertDer);
void gds_access_uninstall(void);

static inline const gds_session *gds_session_get(const void *sessionContext) {
    return (const gds_session *)sessionContext;
}
static inline bool gds_session_has(const void *sessionContext, unsigned roles) {
    const gds_session *s = sessionContext;
    return s && (s->roles & roles) != 0;
}
/* The application itself (ApplicationSelfAdmin, OPC 10000-12 §7.2): the
 * session's client certificate carries this ApplicationUri. */
bool gds_session_is_app(const void *sessionContext, const UA_String *applicationUri);
/* The session's secure channel uses exactly this certificate (DER), which
 * the GDS CA issued: the caller holds its private key. */
bool gds_session_holds_cert(const void *sessionContext, const gds_buf *der);

/* May this session Call on the node (RolePermissions of embedder nodes,
 * gds_nodes.c)? True when the node has none. Thread safe. */
struct gds_server;
bool gds_node_call_allowed(struct gds_server *s, const void *sessionContext,
                           const UA_NodeId *nodeId);

/* The activated sessions with any of these Roles (or every session when
 * anonymous, every non-anonymous one when authenticated): their ids are
 * copied to out (at most max; the caller clears them). Thread safe. */
size_t gds_access_sessions_with(unsigned roles, bool anonymous, bool authenticated,
                                UA_NodeId *out, size_t max);

/* getUserExecutable: may this session call this method? Namespace 0:
 * the open methods, the ServerConfiguration methods for SecurityAdmin, and
 * DialogConditionType Respond/Respond2 (approvals) for
 * RegistrationAuthorityAdmin.
 * The GDS namespace: yes, its methods check rights themselves. Methods
 * that an embedder bound (gds_plugin.h): their Roles and security mode.
 * Any other method: no. */
struct gds_server;
bool gds_method_executable(const struct gds_server *s, const void *sessionContext,
                           const UA_NodeId *methodId);
/* The embedder part of that answer (gds_embed.c): 1 yes, 0 no, -1 a
 * namespace 0 method that no embedder bound. */
int gds_embed_decide(const struct gds_server *s, const void *sessionContext,
                     const UA_NodeId *methodId);

#endif
