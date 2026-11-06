/* OpenGDS - plugin API: who is calling (UASM ask A6, issue #17).
 *
 * Every plugin callback gets a gds_caller: a const, borrowed view of the
 * session behind the call. It holds
 *   - the granted Roles as NodeIds: the well-known Roles of OPC 10000-3 /
 *     10000-18 §4.3 (namespace 0), of OPC 10000-12 §6.2 Table 1 and §7.2
 *     (GDS namespace) and of OPC 10000-14 (SecurityKeyServer*), as the
 *     users file grants them. Anonymous is in every view and
 *     AuthenticatedUser in every view with user credentials (the default
 *     identity mappings of OPC 10000-18 §4.3);
 *   - the application behind the SecureChannel: its ApplicationUri and,
 *     when it is registered, its ApplicationId. Only a client certificate
 *     the GDS CA issued names an application (OPC 10000-12 §6.2 Table 2:
 *     the Certificate used to create the SecureChannel identifies it);
 *   - Privileges, which OPC 10000-12 §6.2 says are "assigned to Sessions
 *     using mechanisms other than the well-known Roles": the core grants
 *     ApplicationSelfAdmin when the channel names an application, and
 *     privilege providers (below) add others, for example the DCA
 *     privilege of OPC 10000-21;
 *   - the SecureChannel's MessageSecurityMode and SecurityPolicyUri.
 *
 * Ownership: the view and everything it points to is borrowed and valid
 * only during the callback that receives it. Copy what you keep.
 *
 * ABI (docs/architecture.md, "Plugin API rules"): structs start with
 * abi_major, abi_minor, struct_size. The core refuses another major and
 * reads only the fields struct_size covers; plugins must check
 * struct_size before reading a field added in a later minor version.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_GDS_PLUGIN_H
#define OPENGDS_GDS_PLUGIN_H

#include <open62541/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/compiler.h"
#include "common/errors.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GDS_PLUGIN_ABI_MAJOR 1u
#define GDS_PLUGIN_ABI_MINOR 0u

/* The values of MessageSecurityMode (OPC 10000-4 §7.20). */
typedef enum {
    GDS_SECURITY_MODE_INVALID = 0,
    GDS_SECURITY_MODE_NONE = 1,
    GDS_SECURITY_MODE_SIGN = 2,
    GDS_SECURITY_MODE_SIGN_AND_ENCRYPT = 3
} gds_security_mode;

/* Privileges have no NodeIds; OpenGDS names them "<namespace URI>#<name>".
 * Plugins name their own the same way, with their own namespace URI. */
#define GDS_PRIVILEGE_APPLICATION_SELF_ADMIN "http://opcfoundation.org/UA/GDS/#ApplicationSelfAdmin"
#define GDS_MAX_PRIVILEGES 32
#define GDS_MAX_PRIVILEGE_NAME 256

typedef struct {
    uint32_t abi_major;
    uint32_t abi_minor;
    size_t struct_size;
    /* The session (OPC 10000-4 §5.7.2 sessionId). */
    const UA_NodeId *sessionId;
    /* NULL for an anonymous session. NUL-terminated. */
    const char *userName;
    /* Granted Roles, no duplicates, Anonymous first. */
    const UA_NodeId *roles;
    size_t rolesSize;
    /* The application behind the SecureChannel, NULL if none. */
    const char *applicationUri;
    /* Its ApplicationId in the GDS namespace; null NodeId if it is not
     * registered (or applicationUri is NULL). */
    const UA_NodeId *applicationId;
    /* Granted Privileges, no duplicates. */
    const char *const *privileges;
    size_t privilegesSize;
    gds_security_mode securityMode;
    const char *securityPolicyUri; /* NUL-terminated */
} gds_caller;

bool gds_caller_has_role(const gds_caller *c, const UA_NodeId *role);
/* A well-known Role of namespace 0 (UA_NS0ID_WELLKNOWNROLE_*). */
bool gds_caller_has_ns0_role(const gds_caller *c, UA_UInt32 ns0RoleId);
bool gds_caller_has_privilege(const gds_caller *c, const char *privilege);

/* ---- privilege providers ----
 * A provider adds Privileges to a caller's view. It runs on a worker
 * thread, once for each view the core builds, after the core's own
 * Privileges; it may read the view so far. It must not block for long:
 * the call it serves waits for it. An error refuses the call (plugin
 * errors fail closed). */
typedef struct gds_privilege_set gds_privilege_set;

/* Adds a Privilege (copied). GDS_EINVAL for an empty or overlong name or
 * one with bytes outside printable ASCII; GDS_ETOOBIG above
 * GDS_MAX_PRIVILEGES. Adding one twice is GDS_OK. */
GDS_MUST_CHECK gds_status gds_privilege_set_add(gds_privilege_set *set, const char *privilege);

typedef struct {
    uint32_t abi_major;
    uint32_t abi_minor;
    size_t struct_size;
    void *ctx; /* borrowed: outlives the server */
    gds_status (*grant)(void *ctx, const gds_caller *caller, gds_privilege_set *set);
} gds_privilege_provider;

#ifdef __cplusplus
}
#endif

#endif
