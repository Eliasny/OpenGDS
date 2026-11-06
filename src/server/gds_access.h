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

typedef enum {
    GDS_ROLE_DISCOVERY_ADMIN = 1u << 0,             /* Directory changes */
    GDS_ROLE_CERTIFICATE_AUTHORITY_ADMIN = 1u << 1, /* CertificateManager for any application */
    GDS_ROLE_SECURITY_ADMIN = 1u << 2               /* write the GDS trust lists */
} gds_role;

#define GDS_PBKDF2_SALT 16
#define GDS_PBKDF2_HASH 32
#define GDS_PBKDF2_DEFAULT_ITER 100000
#define GDS_MAX_USERS 64
#define GDS_MAX_USER_NAME 64

typedef struct {
    char name[GDS_MAX_USER_NAME + 1];
    unsigned roles;
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
 * Roles: DiscoveryAdmin, CertificateAuthorityAdmin, SecurityAdmin. The file
 * must not be readable by others (mode 0600 or 0640). */
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

/* getUserExecutable: may this session call this method? (tests) */
bool gds_method_executable(const void *sessionContext, const UA_NodeId *methodId);

#endif
