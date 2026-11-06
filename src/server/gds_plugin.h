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

#include <open62541/server.h>
#include <open62541/types_gds_generated.h>

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

/* ---- embedder address space and methods (UASM ask A5, issue #16) ----
 * An application that embeds OpenGDS adds its own standard address space
 * next to the GDS (OPC 10000-14 SKS, OPC 10000-21, OPC 10000-100 ...):
 * namespaces, compiled NodeSets, objects and methods. Namespaces and
 * NodeSets are added before gds_server_run, from the thread that created
 * the server; objects and methods may also change while it runs (A9,
 * below).
 *
 * The address space stays read-only to clients (no AddNodes, DeleteNodes
 * or attribute writes). A method in another namespace than the GDS one is
 * executable only once it is added or bound here; namespace 0 methods are
 * offered only when bound. A bound method's callback:
 *   - runs on the OpenGDS plugin worker pool, never on the network thread;
 *   - runs only when the caller has one of the method's Roles or one of
 *     its Privileges (none listed: nobody), and a SecureChannel at least
 *     as secure as minSecurityMode; otherwise the call returns
 *     Bad_UserAccessDenied (OPC 10000-4 §7.38.2) and the callback never
 *     runs. UserExecutable reads false when no Role of the session
 *     matches and the method has no Privileges;
 *   - on a STANDBY node (gds_server_set_role) is refused with
 *     Bad_InvalidState unless the method is GDS_METHOD_READ_ONLY
 *     (docs/architecture.md, "Plugin API rules");
 *   - gets its inputs after open62541 has checked their count and types
 *     against InputArguments (OPC 10000-4 §5.11.2: Bad_ArgumentsMissing,
 *     Bad_TooManyArguments, Bad_InvalidArgument / Bad_TypeMismatch); the
 *     callback checks shapes and limits with gds_arg_scalar, gds_arg_array,
 *     gds_arg_bytes and gds_arg_string (common/ua_args.h);
 *   - is completed within GDS_PLUGIN_CALL_TIMEOUT_MS or answered with
 *     Bad_Timeout; when GDS_PLUGIN_QUEUE calls wait, more are answered
 *     with Bad_ServerTooBusy (OPC 10000-4 §7.38.2, decision G9).
 * Inputs, outputs and the caller are owned by the call. The callback fills
 * output[0..outputSize) with values it allocates (UA_Variant_setScalarCopy
 * and similar); the core frees them, also when the call was cancelled. */
#define GDS_PLUGIN_QUEUE 256
#define GDS_PLUGIN_CALL_TIMEOUT_MS 30000
#define GDS_PLUGIN_WORKERS 4
#define GDS_MAX_PLUGIN_METHODS 1024
#define GDS_MAX_METHOD_ROLES 16
#define GDS_MAX_METHOD_ARGS 32

struct gds_server;
typedef UA_StatusCode (*gds_nodeset_fn)(UA_Server *server);

typedef UA_StatusCode (*gds_method_fn)(void *ctx, const gds_caller *caller,
                                       const UA_NodeId *objectId, size_t inputSize,
                                       const UA_Variant *input, size_t outputSize,
                                       UA_Variant *output);

/* The method changes nothing: allowed on a standby node. */
#define GDS_METHOD_READ_ONLY 0x1u

typedef struct {
    uint32_t abi_major;
    uint32_t abi_minor;
    size_t struct_size;
    /* gds_server_add_method: the new node, its parent object and its
     * BrowseName (in the NodeId's namespace) and DisplayName (NULL: the
     * BrowseName). gds_server_bind_method: only methodId is used. */
    UA_NodeId methodId;
    UA_NodeId parentId;
    const char *browseName;
    const char *displayName;
    const UA_Argument *inputArguments; /* copied */
    size_t inputArgumentsSize;
    const UA_Argument *outputArguments; /* copied */
    size_t outputArgumentsSize;
    /* Who may call: a caller with any of these Roles or Privileges. Roles
     * are the well-known Roles a gds_caller can hold. Copied. */
    const UA_NodeId *roles;
    size_t rolesSize;
    const char *const *privileges;
    size_t privilegesSize;
    gds_security_mode minSecurityMode; /* INVALID: SIGN_AND_ENCRYPT */
    uint32_t flags;                    /* GDS_METHOD_* */
    gds_method_fn fn;
    void *ctx; /* borrowed: outlives the server */
} gds_method_def;

/* The namespace's index, adding it if needed. */
GDS_MUST_CHECK gds_status gds_server_add_namespace(struct gds_server *s, const char *uri,
                                                   UA_UInt16 *nsIndex);
/* Runs a NodeSet compiled by open62541's nodeset_compiler (the generated
 * namespace_<name>_generated function). */
GDS_MUST_CHECK gds_status gds_server_load_nodeset(struct gds_server *s, gds_nodeset_fn fn);
/* Adds an object (type BaseObjectType when typeDefinition is null) under
 * parentId with a HasComponent reference (Organizes under Objects). The
 * NodeId may be in namespace 0: this open62541 build leaves out standard
 * nodes of features it does not build, such as PublishSubscribe (i=14443)
 * and its OPC 10000-14 SKS methods, and the embedder adds them. Never in
 * the GDS namespace (GDS_EINVAL). */
GDS_MUST_CHECK gds_status gds_server_add_object(struct gds_server *s, const UA_NodeId *nodeId,
                                                const UA_NodeId *parentId,
                                                const char *browseName,
                                                const UA_NodeId *typeDefinition);
/* Adds a method node and binds def->fn to it. */
GDS_MUST_CHECK gds_status gds_server_add_method(struct gds_server *s, const gds_method_def *def);
/* Binds def->fn to an existing method node (from a NodeSet, or a
 * namespace 0 method such as the OPC 10000-14 GetSecurityKeys once it is
 * added). The GDS namespace's own methods cannot be bound (GDS_EDENIED). */
GDS_MUST_CHECK gds_status gds_server_bind_method(struct gds_server *s, const gds_method_def *def);

/* ---- runtime changes (UASM ask A9, issue #49) ----
 * gds_server_add_object, gds_server_add_method, gds_server_bind_method,
 * gds_server_set_role_permissions and gds_server_remove_node may be called
 * while the server runs, from any thread, including the plugin worker that
 * runs a method callback (for example AddSecurityGroup creating one
 * SecurityGroupType object, OPC 10000-14 §8.3). A call that is running
 * when its method is removed finishes normally; later calls fail with
 * Bad_NodeIdUnknown or Bad_MethodInvalid. */

/* RolePermissions of a node (OPC 10000-3 §5.2.9, §8.55 PermissionType):
 * which Roles get which permissions. Enforced by OpenGDS for Call: a
 * method called on an object (or a method node) that has RolePermissions
 * runs only for a session that holds a Role granted UA_PERMISSIONTYPE_CALL
 * there, in addition to the method's own Roles and Privileges. Other
 * permissions are kept for the plugin to check with gds_caller_permitted. */
#define GDS_MAX_ROLE_PERMISSIONS 16

typedef struct {
    UA_NodeId roleId;     /* a Role a gds_caller can hold, as for gds_method_def */
    uint32_t permissions; /* UA_PERMISSIONTYPE_* bits */
} gds_role_permission;

/* Replaces the node's RolePermissions; n == 0 removes them (the node then
 * has none, and only the method checks apply). The node must exist and
 * must not be in the GDS namespace. */
GDS_MUST_CHECK gds_status gds_server_set_role_permissions(struct gds_server *s,
                                                          const UA_NodeId *nodeId,
                                                          const gds_role_permission *perms,
                                                          size_t n);
/* True when the caller holds a Role granted all of `permissions` on the
 * node, or when the node has no RolePermissions. */
bool gds_caller_permitted(struct gds_server *s, const gds_caller *caller,
                          const UA_NodeId *nodeId, uint32_t permissions);
/* Deletes an embedder node with its references and the children open62541
 * deletes with it, unbinds the plugin methods among them and drops their
 * RolePermissions. Namespace 0 and the GDS namespace: GDS_EDENIED. */
GDS_MUST_CHECK gds_status gds_server_remove_node(struct gds_server *s, const UA_NodeId *nodeId);

/* ---- embedder Roles (UASM ask A10, issue #63) ----
 * Roles that OpenGDS does not define, such as the OPC 10000-21
 * RegistrarAdmin (§9.2.10, §9.2.12) and SoftwareUpdateAdmin (§9.2.5).
 * gds_server_add_role must come before gds_server_run, on the thread that
 * runs the server; afterwards it fails with GDS_ESTATE. Once added:
 *   - the users file grants the Role by name (the file may be loaded
 *     before the Role is added; gds_server_run refuses to start with
 *     GDS_EINVAL while a name in it is no Role);
 *   - gds_caller.roles carries roleId for the sessions that hold it;
 *   - gds_method_def.roles and gds_role_permission.roleId may name it;
 *   - the Role is a component of Server/ServerCapabilities/RoleSet (OPC
 *     10000-18 §4.2): an existing Object with roleId (from a NodeSet) is
 *     linked there, otherwise a RoleType object named `name` is created.
 * name: letters, digits, '.', '_', '-', at most 64 characters. A name or
 * NodeId that is taken (a built-in Role, Anonymous, AuthenticatedUser or
 * an earlier embedder Role): GDS_EEXISTS. A NodeId in the GDS namespace:
 * GDS_EDENIED. More than 16 embedder Roles: GDS_ETOOBIG. */
GDS_MUST_CHECK gds_status gds_server_add_role(struct gds_server *s, const char *name,
                                              const UA_NodeId *roleId);

/* ---- audit events of other parts (UASM ask A7, issue #18) ----
 * gds_server_raise_audit_event appends the event to the store's
 * hash-chained audit log (store.h) and then, only once that committed,
 * raises it as an OPC UA event on its source node, delivered only to the
 * sessions that hold one of visibleTo (for example SecurityAdmin, as
 * OPC 10000-21 §9.2.13 requires for its audit events). A refused commit
 * (GDS_ENOTLEADER) raises nothing.
 *
 * The event type must be a subtype of AuditEventType (i=2052) already in
 * the address space (load its NodeSet first). The core fills the
 * AuditEventType fields of OPC 10000-5 §6.4.3: ActionTimeStamp (now),
 * Status, ServerId (the GDS's ApplicationUri) and ClientUserId (the
 * caller's user name; empty when anonymous or without a caller); fields
 * adds the type's own fields by BrowseName. Values are copied. Safe from
 * any thread; the plugin worker that runs a method callback may call it. */
#define GDS_MAX_AUDIT_FIELDS 32

typedef struct {
    UA_UInt16 nsIndex; /* of the field's BrowseName */
    const char *name;  /* BrowseName, a direct child of the event type */
    UA_Variant value;
} gds_event_field;

typedef struct {
    uint32_t abi_major;
    uint32_t abi_minor;
    size_t struct_size;
    UA_NodeId eventType;
    UA_NodeId sourceNode; /* null: the Server object */
    UA_UInt16 severity;   /* 1 (lowest) .. 1000 */
    const char *message;  /* UTF-8, NULL for none */
    bool status;          /* AuditEventType.Status: the action succeeded */
    const gds_event_field *fields;
    size_t fieldsSize;
    /* Roles whose sessions receive the event; at least one. */
    const UA_NodeId *visibleTo;
    size_t visibleToSize;
} gds_audit_event;

/* *seq (may be NULL) gets the event's place in the audit log. GDS_EINVAL
 * for a type that is not an AuditEventType, a bad field or no visibleTo;
 * GDS_EUNSUPPORTED when the store backend has no audit log. */
GDS_MUST_CHECK gds_status gds_server_raise_audit_event(struct gds_server *s,
                                                       const gds_caller *caller,
                                                       const gds_audit_event *ev, int64_t *seq);


/* ---- Directory and CertificateManager for embedders (UASM ask A13,
 * issue #81) ----
 *
 * What a Part 21 Registrar (OPC 10000-21 §7.2, §7.3, §9.2.8) does inside
 * the GDS without going through the Part 12 methods. Every call:
 *   - refuses with GDS_ENOTLEADER on a STANDBY node, as the store does
 *     (A4), so the embedder answers Bad_InvalidState;
 *   - names actor (NUL-terminated, non-empty, e.g. "uasm-registrar" or
 *     the user of the session it acts for) as the ClientUserId of the
 *     audit events it writes; they go through the hash-chained audit log
 *     first, as gds_server_raise_audit_event does (A7), and are visible to
 *     SecurityAdmin and the GDS Role of the matching Part 12 method;
 *   - is safe from any thread except the server thread; the plugin worker
 *     that runs a method callback may call it. */

/* Registers rec (its applicationId is ignored) after the checks of
 * RegisterApplication (OPC 10000-12 §6.5.6). Idempotent per
 * ApplicationUri: when a record with rec's ApplicationUri exists, *appId
 * is that record's and *created false, and nothing is changed; otherwise
 * the record is added, *created is true and an
 * ApplicationRegistrationChangedAuditEventType event (§6.5.12) is written.
 * *appId: a GUID NodeId in the GDS namespace. GDS_EINVAL: the record
 * fails the checks. */
GDS_MUST_CHECK gds_status gds_server_register_application(struct gds_server *s, const char *actor,
                                                          const UA_ApplicationRecordDataType *rec,
                                                          UA_NodeId *appId, bool *created);

/* Holds back (allowed false) or releases the issuance of certificates to
 * one application, e.g. until its software is updated (OPC 10000-21 §7.2).
 * While held, StartSigningRequest for it answers Bad_RequestNotAllowed,
 * a request of it already waiting for the signer fails with that code,
 * and gds_server_sign_request refuses with GDS_EDENIED. Holds live in
 * memory only: after a failover the embedder sets them again on the new
 * primary before it leaves STANDBY (gds_server_set_role). GDS_ENOTFOUND:
 * no such application (releasing one is always GDS_OK). */
GDS_MUST_CHECK gds_status gds_server_set_issuance_allowed(struct gds_server *s,
                                                          const UA_NodeId *appId, bool allowed);

/* Signs a CSR for an application, as StartSigningRequest followed by
 * FinishRequest would (OPC 10000-12 §7.9.3, §7.9.5; the push model of
 * §7.10, OPC 10000-21 §7.3), and waits for the result. The request is
 * stored already approved (the embedder is the approver, so the approval
 * policy is not asked), signed by the signing worker through the signer
 * with its checks and issuance journal, and delivered. groupId and typeId
 * may be NULL or null NodeIds: the DefaultApplicationGroup and its
 * RsaSha256ApplicationCertificateType. It writes
 * CertificateRequestedAuditEventType and CertificateDeliveredAuditEventType
 * events (§7.9.12, §7.9.13). Returns the certificate and the issuer chain
 * (*issuers: an array of *nIssuers, free with UA_Array_delete).
 * GDS_EINVAL: a malformed CSR or an unknown group or type; GDS_ENOTFOUND:
 * no such application; GDS_EDENIED: issuance is held, or the signer
 * refused (the request is then Failed); GDS_EREMOTE: no answer within
 * timeoutMs (the request stays
 * queued and may still be signed; its certificate then appears in the
 * directory as usual). */
GDS_MUST_CHECK gds_status gds_server_sign_request(struct gds_server *s, const char *actor,
                                                  const UA_NodeId *appId, const UA_NodeId *groupId,
                                                  const UA_NodeId *typeId, const UA_ByteString *csr,
                                                  uint32_t timeoutMs, UA_ByteString *cert,
                                                  UA_ByteString **issuers, size_t *nIssuers);

/* The trust list of a CertificateGroup (NULL or a null NodeId: the
 * DefaultApplicationGroup), as GetTrustList and the TrustList file give it
 * (OPC 10000-12 §7.9.9, §7.8.2.1): every list, a deep copy. */
GDS_MUST_CHECK gds_status gds_server_get_trust_list(struct gds_server *s, const UA_NodeId *groupId,
                                                    UA_TrustListDataType *out);

#ifdef __cplusplus
}
#endif

#endif
