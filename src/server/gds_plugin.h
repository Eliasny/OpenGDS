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
#define GDS_PLUGIN_ABI_MINOR 3u /* 1: gds_caller.clientCertificate (A14); 2: push scheduling;
                                  3: gds_keycred_source */

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
    /* minor 1 (UASM ask A14): the SecureChannel's client certificate
     * (DER), whoever issued it, for every Sign or SignAndEncrypt session;
     * NULL and 0 otherwise. A privilege provider can recognise e.g. an
     * OPC 10000-21 DeviceIdentity certificate by it. Check struct_size
     * before reading. */
    const uint8_t *clientCertificate;
    size_t clientCertificateSize;
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

/* A Boolean variable whose value depends on who reads it (UASM ask A17):
 * TRUE for a session that holds any of these Roles, FALSE for any other
 * session, as OpenGDS decides UserExecutable. For example the
 * UserWritable Property of an OPC 10000-20 FileType (§4.2.1) that only
 * RegistrarAdmin may write (OPC 10000-21 §9.2.10). Roles are as for
 * gds_method_def.roles; Anonymous makes it TRUE for every session and
 * AuthenticatedUser for every session with user credentials. The node
 * must be an existing Boolean variable outside namespace 0 and the GDS
 * namespace (GDS_EDENIED); its value is computed from now on and writes
 * are refused. Calling again replaces the Roles. Thread safe. */
GDS_MUST_CHECK gds_status gds_server_set_role_boolean(struct gds_server *s,
                                                      const UA_NodeId *nodeId,
                                                      const UA_NodeId *roles, size_t n);

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

/* ---- alarms (UASM ask A16) ----
 * A plugin raises and clears Part 9 alarms on its own objects, for example
 * the SKS out of pre-generated keys without a majority, or a cluster node
 * that lost its majority. gds_server_add_alarm creates an
 * AlarmConditionType instance (OPC 10000-9 §5.8.2; OffNormalAlarmType,
 * §5.8.23, by default) as a HasComponent child of sourceNode, which
 * becomes an event source of the Server object: subscribers of the Server
 * object get its events, and ConditionRefresh (§5.5.7) replays it while
 * it is retained. It starts Enabled, Inactive, Acknowledged, Retain false,
 * Severity 1 and fires no event.
 *
 * gds_server_set_alarm sets ActiveState, LastSeverity, Severity and
 * Message, and Retain (TRUE while Active or unacknowledged), and fires the
 * alarm's event (§5.8). It is queued: the server thread applies the calls
 * in order, shortly after; GDS_ETOOBIG while 64 are waiting. Calling it
 * with an unchanged state reports a new Severity or Message.
 *
 * With ackRoles, each activation also sets AckedState Unacknowledged, and
 * a session holding one of the Roles over SignAndEncrypt may Acknowledge
 * (§5.7.3) with the alarm's last EventId; the acknowledgement is audited as
 * AuditConditionAcknowledgeEventType (§5.10.4), visible to ackRoles.
 * Without ackRoles the alarm needs no acknowledgement: AckedState stays
 * Acknowledged and nobody may call Acknowledge.
 *
 * Both functions are safe from any thread, while the server runs too.
 * Alarms live until gds_server_delete; the handle is borrowed. */
#define GDS_MAX_ALARMS 64

typedef struct gds_alarm gds_alarm;

typedef struct {
    uint32_t abi_major;
    uint32_t abi_minor;
    size_t struct_size;
    /* The condition's NodeId; null: a new numeric one in sourceNode's
     * namespace. Never in the GDS namespace (GDS_EDENIED). */
    UA_NodeId alarmId;
    /* An existing object outside the GDS namespace (SourceNode,
     * SourceName = its BrowseName). */
    UA_NodeId sourceNode;
    /* BrowseName (in sourceNode's namespace) and ConditionName. */
    const char *name;
    /* null: OffNormalAlarmType; otherwise a subtype of AlarmConditionType
     * in the address space. */
    UA_NodeId alarmType;
    /* Who may Acknowledge, as gds_method_def.roles; copied. */
    const UA_NodeId *ackRoles;
    size_t ackRolesSize;
    /* Since A19 (older plugins pass a shorter struct_size): who receives
     * the alarm's events, live and from ConditionRefresh, as
     * gds_audit_event.visibleTo; 0: every subscriber. */
    const UA_NodeId *visibleTo;
    size_t visibleToSize;
} gds_alarm_def;

/* GDS_ENOTFOUND: no such source object; GDS_EEXISTS: the NodeId is taken;
 * GDS_EINVAL: a bad def, a Role no session can hold, or a type that is
 * no AlarmConditionType; GDS_ETOOBIG: 64 alarms already. */
GDS_MUST_CHECK gds_status gds_server_add_alarm(struct gds_server *s, const gds_alarm_def *def,
                                               gds_alarm **alarm);
/* severity 1 (lowest) .. 1000; message UTF-8, NULL for none, copied. */
GDS_MUST_CHECK gds_status gds_server_set_alarm(gds_alarm *alarm, bool active, uint16_t severity,
                                               const char *message);

/* ---- dialogs (UASM ask A19) ----
 * A plugin asks an operator a question, e.g. "Register and manage this
 * server?" for a server that fleet discovery found. gds_server_add_dialog
 * creates a DialogConditionType instance (OPC 10000-9 §5.6.2) as a
 * HasComponent child of sourceNode, active (DialogState Active, Retain
 * true) with its Prompt, ResponseOptionSet and Ok/Cancel/DefaultResponse,
 * and fires its event; ConditionRefresh (§5.5.7) replays it while active.
 * With visibleTo, only sessions holding one of those Roles receive its
 * events (live and replayed) and the audit events about it.
 *
 * Respond (§5.6.3) and Respond2 (§5.6.4, with a Comment) need one of
 * respondRoles over SignAndEncrypt; the core checks the response index
 * (Bad_DialogResponseInvalid), the Comment length and that the dialog is
 * active (Bad_DialogNotActive; also while another response is being
 * handled), then calls respond on a plugin worker, never on the network
 * thread. respond returns Good to accept the response, or
 * Bad_DialogNotActive / Bad_DialogResponseInvalid (or another Bad code) to
 * refuse it; the caller gets that code. On Good the core sets LastResponse,
 * Comment and ClientUserId, makes DialogState Inactive and Retain false and
 * fires the event. Every call is audited as AuditConditionRespondEventType
 * (§5.10.6). The dialog stays in the address space until
 * gds_server_remove_dialog, which closes it first if it is still active
 * (Retain false, an event). A response already being handled may still
 * reach respond after remove returned.
 *
 * Both functions are safe from any thread except the server thread; on a
 * STANDBY node Respond answers Bad_InvalidState. */
#define GDS_MAX_DIALOGS 256
#define GDS_MAX_DIALOG_OPTIONS 16

/* Accept (Good) or refuse (Bad) a response; may block for a while. */
typedef UA_StatusCode (*gds_dialog_fn)(void *ctx, const gds_caller *caller,
                                       const UA_NodeId *dialogId, int32_t selectedResponse,
                                       const UA_LocalizedText *comment);

typedef struct {
    uint32_t abi_major;
    uint32_t abi_minor;
    size_t struct_size;
    /* The dialog's NodeId; null: a new numeric one in sourceNode's
     * namespace. Never in namespace 0 or the GDS namespace. */
    UA_NodeId dialogId;
    /* An existing object outside the GDS namespace (SourceNode). */
    UA_NodeId sourceNode;
    /* BrowseName (in sourceNode's namespace) and ConditionName. */
    const char *name;
    /* Message and Prompt, UTF-8; message may be NULL. Copied. */
    const char *message;
    const char *prompt;
    /* 1 .. GDS_MAX_DIALOG_OPTIONS response texts, UTF-8; copied. */
    const char *const *responseOptions;
    size_t responseOptionsSize;
    /* Indexes into responseOptions, or -1 for none. */
    int32_t defaultResponse;
    int32_t okResponse;
    int32_t cancelResponse;
    /* 1 (lowest) .. 1000. */
    uint16_t severity;
    /* Who may Respond, as gds_method_def.roles; at least one. Copied. */
    const UA_NodeId *respondRoles;
    size_t respondRolesSize;
    /* Who receives its events; 0: every subscriber. Copied. */
    const UA_NodeId *visibleTo;
    size_t visibleToSize;
    gds_dialog_fn respond;
    void *ctx;
} gds_dialog_def;

/* *dialogId: the dialog's NodeId (free with UA_NodeId_clear).
 * GDS_ENOTFOUND: no such source object; GDS_EEXISTS: the NodeId is taken;
 * GDS_EDENIED: namespace 0 or the GDS namespace; GDS_EINVAL: a bad def or
 * a Role no session can hold; GDS_ETOOBIG: GDS_MAX_DIALOGS already. */
GDS_MUST_CHECK gds_status gds_server_add_dialog(struct gds_server *s, const gds_dialog_def *def,
                                                UA_NodeId *dialogId);
/* GDS_ENOTFOUND: no such plugin dialog. */
GDS_MUST_CHECK gds_status gds_server_remove_dialog(struct gds_server *s,
                                                   const UA_NodeId *dialogId);

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
 * DefaultApplicationGroup; or a group from gds_server_add_trust_list), as
 * GetTrustList and the TrustList file give it (OPC 10000-12 §7.9.9,
 * §7.8.2.1): every list, a deep copy. */
GDS_MUST_CHECK gds_status gds_server_get_trust_list(struct gds_server *s, const UA_NodeId *groupId,
                                                    UA_TrustListDataType *out);


/* ---- CertificateManager rights for embedders (UASM ask A14, issue #87) ----
 * may_manage answers one question: may this caller act for this
 * ApplicationId in the CertificateManager methods (StartSigningRequest,
 * FinishRequest, GetCertificateGroups, GetTrustList,
 * GetCertificateStatus; OPC 10000-12 §7.9)? For example a device with the
 * OPC 10000-21 DCA Privilege (§4.2.6 Table 4, §9.2.6) acting for its own
 * ApplicationId over its DeviceIdentity channel.
 * The core asks only after its own checks refused the call
 * (CertificateAuthorityAdmin, or the application itself through a
 * certificate the GDS CA issued, §7.2), so the hook can only add rights;
 * every other check stays (the application must exist, the certificate
 * still carries the record's ApplicationUri). It runs on a plugin worker,
 * the call completing asynchronously; it must not block for long. With no
 * hook the core keeps its own answer. Set it before gds_server_run;
 * GDS_ESTATE after. */
typedef bool (*gds_may_manage_fn)(void *ctx, const gds_caller *caller,
                                  const UA_NodeId *applicationId);
GDS_MUST_CHECK gds_status gds_server_set_application_rights_hook(struct gds_server *s,
                                                                 gds_may_manage_fn fn, void *ctx);

/* ---- approvals for embedders (UASM ask A22) ----
 * approve answers one question: may this caller's StartSigningRequest
 * (OPC 10000-12 §7.9.3) for this ApplicationId skip the administrator?
 * For example a device's DCA asking for its own certificates, which OPC
 * 10000-21 §4.3.3 lets it do "without the need for additional approvals"
 * because the Registrar already accepted the device. The core asks only
 * for a request that passed every check and that its own approval policy
 * (gds_server_config.approval) would leave Pending, so the hook can only
 * add approvals. With true the request is approved on arrival and signed
 * as usual, and a CertificateRequestedAuditEventType records that the
 * embedder approved it; with false it waits for an administrator as
 * before. It runs on a plugin worker, the call completing
 * asynchronously; it must not block for long. Set it before
 * gds_server_run; GDS_ESTATE after. */
typedef bool (*gds_approve_fn)(void *ctx, const gds_caller *caller,
                               const UA_NodeId *applicationId);
GDS_MUST_CHECK gds_status gds_server_set_approval_hook(struct gds_server *s, gds_approve_fn fn,
                                                       void *ctx);

/* ---- KeyCredential source (OPC 10000-12 §8.5; Elias, 9 Nov 2026) ----
 * By default the core makes each KeyCredential itself: a random
 * CredentialId and secret, of which it keeps only a salted hash
 * (docs/opengdsd.md, "KeyCredentials"). A source makes them instead, for
 * example an embedder that provisions the broker account or holds the
 * credentials in its own store.
 *
 * issue runs when FinishRequest delivers an approved request: it creates
 * the credential for the application on the service's resource, writes
 * its CredentialId (1 .. GDS_KEYCRED_ID_MAX printable ASCII bytes, unique
 * across all services) to credentialId and its secret (1 ..
 * GDS_KEYCRED_SECRET_MAX bytes, any content) to *secret, which the core
 * frees (wiping it) with UA_ByteString_clear after encrypting it for the
 * requester. `replaces`, when not NULL, is the CredentialId of the
 * application's earlier credential for the service: the core forgets it
 * once the new one is stored, so the source should drop it too. An error
 * fails the FinishRequest with Bad_InternalError (GDS_EDENIED:
 * Bad_RequestNotAllowed) and the request stays approved for a retry.
 * revoke runs on Revoke: GDS_OK or GDS_ENOTFOUND deletes the credential
 * from the core's store; any other error keeps it and fails the call.
 * Both run on a plugin worker, the call completing asynchronously; they
 * must not block for long. The core still decides access, approval and
 * auditing, and stores each CredentialId (not the secret), so Revoke and
 * replacement keep working. Set before gds_server_run; GDS_ESTATE after,
 * GDS_EUNSUPPORTED without KeyCredential support in the store. */
#define GDS_KEYCRED_ID_MAX 128
#define GDS_KEYCRED_SECRET_MAX 4096

typedef struct {
    uint32_t abi_major;
    uint32_t abi_minor;
    size_t struct_size;
    const char *service;            /* the KeyCredentialService's BrowseName */
    const char *resourceUri;        /* its ResourceUri */
    const UA_String *applicationUri;
    const UA_NodeId *applicationId; /* the ApplicationRecord */
    const char *replaces;           /* or NULL */
} gds_keycred_issue_request;

typedef struct {
    uint32_t abi_major;
    uint32_t abi_minor;
    size_t struct_size;
    void *ctx; /* borrowed: outlives the server */
    gds_status (*issue)(void *ctx, const gds_keycred_issue_request *req,
                        char credentialId[GDS_KEYCRED_ID_MAX + 1], UA_ByteString *secret);
    gds_status (*revoke)(void *ctx, const char *service, const char *credentialId);
} gds_keycred_source;

/* source NULL: back to the core's own credentials. The struct is copied. */
GDS_MUST_CHECK gds_status gds_server_set_keycred_source(struct gds_server *s,
                                                        const gds_keycred_source *source);

/* ---- revoking a serial the embedder reconciled (UASM ask A23) ----
 * Puts `serial` on the CRL of the CA that issued it. For an embedder
 * whose store learns of certificates the core never saw: UASM, after a
 * forced new primary, finds certificates that cut-off old nodes issued
 * and the new primary never recorded, and must put them on its CRL. The
 * store must already answer cert_is_revoked true for the serial (a
 * signer revokes nothing else; GDS_EDENIED otherwise), so the embedder
 * records the revocation in its store first, exactly as RevokeCertificate
 * (OPC 10000-12 §7.9.6) does. The issuing CA: the one whose subject is
 * `certificate`'s issuer name when certificate is not NULL; else the
 * issuer of certificateType (an ns0 ApplicationCertificateType); else,
 * with both NULL, every issuer this server has, so a serial whose
 * certificate is lost (a signer journal entry that never reached the
 * store) is on every CRL. Idempotent: a serial already on a CRL stays
 * there once. GDS_ESTATE on a STANDBY node (gds_server_set_role),
 * GDS_EINVAL for an empty or oversized serial or an unknown
 * certificateType, otherwise the CA's status. It blocks while the CA
 * answers; call it from a method callback or a thread of the embedder's
 * own, after gds_server_new. No audit event: the embedder raises its
 * own (gds_server_raise_audit_event). */
GDS_MUST_CHECK gds_status gds_server_revoke_serial(struct gds_server *s, const UA_ByteString *serial,
                                                   const UA_ByteString *certificate,
                                                   const UA_NodeId *certificateType);

/* ---- plugin trust lists (UASM ask A18) ----
 * A CertificateGroup of the plugin's own (OPC 10000-12 §7.8.3.1), for
 * example the SKS's push targets: a CertificateGroupType object `name`
 * (BrowseName in groupId's namespace) under parentId, whose TrustList
 * (TrustListType, §7.8.2) sessions holding one of `roles` over
 * SignAndEncrypt read and change with Open, OpenWithMasks, Read, Write,
 * Close, CloseAndUpdate, AddCertificate and RemoveCertificate. The lists
 * are saved after every change to pkiDir/trustlist.bin (pkiDir created,
 * mode 0700; the file an encoded TrustListDataType, written atomically,
 * mode 0600), so they survive restarts; a damaged file makes this call
 * fail (GDS_EINVAL). Changes are live at once (applyChangesRequired
 * FALSE); a change that cannot be saved answers Bad_InternalError. gds_server_get_trust_list(s, &groupId)
 * reads them. Before or while the server runs, from any thread; groupId
 * not in namespace 0 or the GDS namespace (GDS_EDENIED), parentId an
 * existing object (GDS_ENOTFOUND); at most 8 lists (GDS_ETOOBIG). */
#define GDS_MAX_PLUGIN_TRUST_LISTS 8

typedef struct {
    uint32_t abi_major;
    uint32_t abi_minor;
    size_t struct_size;
    UA_NodeId groupId;  /* the CertificateGroupType object to create */
    UA_NodeId parentId; /* the plugin's object */
    const char *name;
    const char *pkiDir;
    /* Who may call the TrustList methods (for example SecurityAdmin), as
     * gds_method_def.roles; at least one; copied. */
    const UA_NodeId *roles;
    size_t rolesSize;
} gds_trust_list_def;

GDS_MUST_CHECK gds_status gds_server_add_trust_list(struct gds_server *s,
                                                    const gds_trust_list_def *def);

/* Replaces the lists of a plugin trust list that tl->specifiedLists
 * selects (UASM ask A20), e.g. a cluster node bringing its copy in line
 * with the replicated one; checked as CloseAndUpdate checks (GDS_EINVAL).
 * A writer that opened the TrustList before this call gets
 * Bad_InvalidState at CloseAndUpdate, so a stale edit never lands. Any
 * thread, on a STANDBY node too. GDS_ENOTFOUND: no plugin trust list has
 * this group.
 * On a STANDBY node (gds_server_set_role) the TrustList is read-only over
 * OPC UA: Open for writing, CloseAndUpdate, AddCertificate and
 * RemoveCertificate answer Bad_InvalidState. */
GDS_MUST_CHECK gds_status gds_server_set_trust_list(struct gds_server *s, const UA_NodeId *groupId,
                                                    const UA_TrustListDataType *tl);

/* ---- push scheduling (OpenGDS plan W3, push.h "next_jobs(now, budget)") ----
 * The push engine (src/push/push_engine.c) keeps the Servers in the push
 * target list (gds_server_push_targets) up to date with the push model of
 * OPC 10000-12 §7.7: it renews a certificate when a third of its lifetime
 * is left, pushes the trust list again when it or a CRL in it changes,
 * backs off after a failure and adds random jitter to every job. Each
 * tick it lists the due jobs and asks the scheduler which of them to start
 * now; at most `budget` may start (the engine's free concurrency).
 *
 * The built-in scheduler starts the earliest due jobs first. A plugin
 * replaces it, for example UASM's push waves (maintenance windows, canary
 * first, pause on failures), with gds_server_set_push_scheduler before
 * gds_server_run. The engine still decides what is due and does the
 * pushing; the scheduler only picks and orders. It never runs on a
 * STANDBY node: there the engine lists nothing. */

/* Why a job is due (gds_push_job.reasons). */
#define GDS_PUSH_CHECK 0x01u     /* nothing known about the Server yet: look, push what it lacks */
#define GDS_PUSH_RENEW 0x02u     /* a third of the certificate's lifetime left, or not the GDS's */
#define GDS_PUSH_TRUSTLIST 0x04u /* the trust list or one of its CRLs changed */
#define GDS_PUSH_REJECTED 0x08u  /* time to read the Server's rejected list (§7.10.12) */
#define GDS_PUSH_RETRY 0x10u     /* the last attempt failed; back-off has passed */

typedef struct {
    UA_NodeId applicationId;    /* the target's record (GDS namespace) */
    const char *applicationUri; /* borrowed for the call */
    const char *endpointUrl;    /* borrowed for the call */
    uint32_t reasons;           /* GDS_PUSH_* */
    uint32_t reserved0;         /* explicit padding, always 0: the layout */
    UA_DateTime due;            /* when it became due, jitter and back-off included */
    UA_DateTime certNotAfter;   /* of the certificate the Server presents; 0: unknown */
    uint32_t failures;          /* consecutive failed attempts */
    uint32_t reserved1;         /* of plugin ABI 1.2 is unchanged */
} gds_push_job;

/* due: the nDue due jobs, earliest first; write the indexes of the jobs to
 * start now, in start order, to picked (room for budget) and return how
 * many (at most budget). Called on the engine's thread once per tick;
 * must not block. */
typedef size_t (*gds_push_next_jobs_fn)(void *ctx, UA_DateTime now, size_t budget,
                                        const gds_push_job *due, size_t nDue, size_t *picked);
/* After a job, with its outcome: Good, or the status of the failed step.
 * Called on an engine worker; must not block. */
typedef void (*gds_push_job_done_fn)(void *ctx, const gds_push_job *job, UA_StatusCode result);

typedef struct {
    uint32_t abi_major;
    uint32_t abi_minor;
    size_t struct_size;
    gds_push_next_jobs_fn next_jobs; /* required */
    gds_push_job_done_fn job_done;   /* may be NULL */
    void *ctx;
} gds_push_scheduler;

/* Replaces the built-in scheduler; NULL restores it. The struct is copied,
 * ctx is borrowed. Before gds_server_run (GDS_ESTATE after); GDS_EINVAL for
 * another ABI major or no next_jobs. */
GDS_MUST_CHECK gds_status gds_server_set_push_scheduler(struct gds_server *s,
                                                        const gds_push_scheduler *sched);
/* The scheduler in force (the engine's view); false: the built-in one. */
bool gds_server_push_scheduler(struct gds_server *s, gds_push_scheduler *out);
/* The built-in scheduler: the earliest due jobs, up to budget. */
size_t gds_push_next_jobs_default(void *ctx, UA_DateTime now, size_t budget,
                                  const gds_push_job *due, size_t nDue, size_t *picked);

/* The push target list (store table push_targets): every Server the
 * engine manages, with its ApplicationUri and the endpoint the engine
 * connects to. cb borrows its arguments and returns false to stop.
 * Targets whose record is gone are left out. GDS_EUNSUPPORTED: the store
 * backend has no push targets (before store ABI minor 6). Any thread
 * except the server thread. */
typedef bool (*gds_push_target_fn)(void *ctx, const UA_NodeId *applicationId,
                                   const char *applicationUri, const char *endpointUrl,
                                   bool enabled);
GDS_MUST_CHECK gds_status gds_server_push_targets(struct gds_server *s, gds_push_target_fn cb,
                                                  void *ctx);

/* Adds a certificate to the Trusted list of the DefaultApplicationGroup's
 * TrustList, as AddCertificate with isTrustedCertificate TRUE does (OPC
 * 10000-12 §7.8.2.6): an application instance certificate, not a CA. The
 * change is audited (TrustListUpdatedAuditEventType) with actor as
 * ClientUserId, and moves LastUpdateTime, so the push engine pushes the
 * list again. Runs on the server thread and waits up to timeoutMs: call it
 * from any other thread while the server runs. GDS_ENOTLEADER on a
 * STANDBY node; GDS_EINVAL: not a usable certificate; GDS_ESTATE: the list
 * is open for writing; GDS_EREMOTE: no answer within timeoutMs. */
GDS_MUST_CHECK gds_status gds_server_trust_certificate(struct gds_server *s, const char *actor,
                                                       const UA_ByteString *cert,
                                                       uint32_t timeoutMs);

#ifdef __cplusplus
}
#endif

#endif
