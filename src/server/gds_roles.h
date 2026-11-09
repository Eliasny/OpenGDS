/* OpenGDS - OPC 10000-18 Role mapping rules (gds_roles.c) and managed
 * users (gds_users.c): the part the access control layer (gds_access.c)
 * calls. The rules and users live in the store (schema 6) and in a cache
 * here, one GDS server per process like gds_access.c.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_GDS_ROLES_H
#define OPENGDS_GDS_ROLES_H

#include <open62541/types.h>

#include <stdbool.h>

#include "gds_access.h"

/* The Roles of a session (OPC 10000-18 §4.4.1): fileRoles (users file)
 * plus every Role whose Identities match the session's identity, each
 * kept only if the session's client application and Endpoint pass the
 * Role's Applications and Endpoints lists. Any thread. */
unsigned gds_roles_evaluate(const gds_session *s, unsigned fileRoles);
/* Fill the X.509 user facts of s (thumbprints, X509Subject criteria of
 * the subject and of the issuer, §4.4.3) from a DER certificate. */
void gds_roles_cert_facts(const UA_ByteString *der, gds_session *s);
/* A RoleType or UserManagement method that OpenGDS bound? Any thread. */
bool gds_roles_is_method(const UA_NodeId *methodId);
/* A Property readable by administrators only (Identities, Applications,
 * Endpoints of a Role; UserManagement Users)? Any thread. */
bool gds_roles_is_secret(const UA_NodeId *nodeId);
/* SecurityAdmin over a SignAndEncrypt channel: may configure Roles and
 * users (§4.4.5 - §4.4.10, §5.2.5 - §5.2.7). */
bool gds_roles_admin(const void *sessionContext);
/* A managed user's password login (§5.2): false for an unknown or
 * disabled user, at the cost of one PBKDF2 like a known one. */
bool gds_musers_login(const UA_String *name, const UA_ByteString *password);
/* Forget every rule, user and bound node (gds_access_uninstall). */
void gds_roles_reset(void);

/* UserConfigurationMask bits (OPC 10000-18 §5.2.3) */
#define GDS_USER_NO_DELETE 0x1u
#define GDS_USER_DISABLED 0x2u
#define GDS_USER_NO_CHANGE_BY_USER 0x4u
#define GDS_USER_MUST_CHANGE_PASSWORD 0x8u
/* PasswordOptionsMask bits (§5.2.2) OpenGDS supports */
#define GDS_PWOPT_SUPPORT_DISABLE_USER 0x2u
#define GDS_PWOPT_SUPPORT_DISABLE_DELETE 0x4u
#define GDS_PWOPT_SUPPORT_NO_CHANGE 0x8u
#define GDS_PWOPT_SUPPORT_DESCRIPTION 0x10u

#define GDS_MAX_ROLE_RULES 1024
#define GDS_MAX_MANAGED_USERS 256
#define GDS_PASSWORD_MAX_LENGTH 256 /* characters */
/* NIST SP 800-63B-4 §3.1.1.2: at least 15 characters when the password
 * is the only authenticator */
#define GDS_PASSWORD_DEFAULT_MIN_LENGTH 15

#endif
