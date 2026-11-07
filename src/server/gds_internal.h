/* OpenGDS - state and helpers shared by the src/server files only.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_GDS_INTERNAL_H
#define OPENGDS_GDS_INTERNAL_H

#include <open62541/nodeids_gds.h>
#include <open62541/server.h>
#include <open62541/types_gds_generated.h>

#include <pthread.h>
#include <stdbool.h>

#include "ca.h"
#include "common/ua_args.h"
#include "gds_access.h"
#include "gds_plugin.h"
#include "gds_server.h"
#include "store.h"

#define GDS_NS_URI "http://opcfoundation.org/UA/GDS/"
#define GDS_MAX_PRIVILEGE_PROVIDERS 8
/* Anonymous, AuthenticatedUser and every built-in and embedder Role */
#define GDS_MAX_CALLER_ROLES (2 + GDS_ROLE_BUILTIN_COUNT + GDS_MAX_EMBED_ROLES)

typedef struct gds_binding gds_binding;
typedef struct gds_job gds_job;
typedef struct gds_node_perms gds_node_perms;
#define GDS_ALARM_QUEUE 64
/* A queued gds_server_set_alarm (gds_alarms.c). */
typedef struct {
    gds_alarm *a;
    bool active;
    UA_UInt16 severity;
    char *message;
} gds_alarm_op;

struct gds_server {
    UA_Server *ua;
    UA_UInt16 ns;
    gds_store *store;
    /* The store is single-writer: the server thread and the signing worker
     * take this lock around store calls only, never across a CA call. */
    pthread_mutex_t storeLock;
    gds_ca *ca;
    gds_buf caCert; /* issuer certificate for FinishRequest, read once at start */
    gds_approval_policy approval;
    size_t pendingApprovals; /* live dialogs; server thread only */
    UA_DateTime counterReset; /* QueryApplications lastCounterResetTime */
    /* node role (gds_server.c); roleLock is a leaf lock */
    pthread_mutex_t roleLock;
    gds_node_role role;
    UA_Byte serviceLevel;
    UA_DateTime estimatedReturnTime;
    /* signing worker (decision G7) */
    pthread_t worker;
    bool workerStarted;
    pthread_mutex_t workLock;
    pthread_cond_t workCond;
    bool workPending, workStop;
    bool plugStop; /* plugin workers stop (plugLock); here for packing */
    bool started;  /* gds_server_run was called (__atomic); here for packing */
    /* plugin privilege providers, fixed before the server runs */
    gds_privilege_provider privProviders[GDS_MAX_PRIVILEGE_PROVIDERS];
    size_t nPrivProviders;
    /* plugin methods (gds_embed.c): bindLock (a leaf lock) guards the
     * bindings and the RolePermissions table (gds_nodes.c); plugLock
     * guards the queue, the done list and plugStop only; plugInflight is
     * touched on the server thread only */
    pthread_mutex_t bindLock;
    gds_binding *bindings[GDS_MAX_PLUGIN_METHODS];
    size_t nBindings;
    gds_node_perms *perms;
    size_t nPerms, capPerms;
    pthread_mutex_t plugLock;
    pthread_cond_t plugCond;
    pthread_t plugThreads[GDS_PLUGIN_WORKERS];
    size_t plugWorkers;
    gds_job *plugQueue, *plugQueueTail, *plugDone;
    size_t plugQueued;
    gds_job *plugInflight[GDS_PLUGIN_QUEUE];
    /* plugin alarms (gds_alarms.c): alarmLock, a leaf lock, guards the
     * list and the queue that the server thread drains */
    pthread_mutex_t alarmLock;
    gds_alarm *alarms[GDS_MAX_ALARMS];
    size_t nAlarms;
    gds_alarm_op alarmOps[GDS_ALARM_QUEUE];
    size_t alarmOpHead, nAlarmOps;
    bool alarmDrainScheduled;
    /* issuance holds (gds_registrar.c, UASM ask A13), not replicated */
    pthread_mutex_t holdLock;
    UA_Guid *holds;
    size_t nHolds, capHolds;
    /* FindServers peers (gds_server.c, UASM ask A15); peerLock is a leaf
     * lock, taken under open62541's service mutex */
    pthread_mutex_t peerLock;
    UA_ApplicationDescription *peers;
    size_t nPeers;
    /* CertificateManager rights hook (UASM ask A14); fixed before run */
    gds_may_manage_fn mayManage;
    void *mayManageCtx;
};

/* ---- caller views (gds_caller.c, issue #17) ---- */
struct gds_privilege_set {
    char *names[GDS_MAX_PRIVILEGES];
    size_t n;
};

/* A gds_caller and the memory it points to; one per plugin call. */
typedef struct {
    gds_caller view;
    UA_NodeId sessionId;
    UA_NodeId roles[GDS_MAX_CALLER_ROLES];
    size_t nRoles;
    UA_NodeId applicationId;
    char user[GDS_MAX_USER_NAME + 1];
    char *appUri;
    char *policyUri;
    gds_privilege_set priv;
} gds_caller_buf;

/* Builds the view for a session: reads the store (for the ApplicationId)
 * and runs the privilege providers, so call it on a worker thread without
 * holding storeLock. GDS_EDENIED without a session or when a provider
 * fails; *b is then cleared. */
GDS_MUST_CHECK gds_status gds_caller_build(gds_server *s, const UA_NodeId *sessionId,
                                           const void *sessionContext, gds_caller_buf *b);
void gds_caller_buf_clear(gds_caller_buf *b);

/* ---- plugin methods (gds_embed.c, issue #16) ---- */
/* Async call settings and the cancel callback; c->context becomes s. */
void gds_embed_configure(UA_ServerConfig *c, gds_server *s);
/* Joins the workers and completes what finished; before UA_Server_delete. */
void gds_embed_stop(gds_server *s);
/* Frees jobs and bindings; after UA_Server_delete. */
void gds_embed_free(gds_server *s);
/* A14: the CertificateManager method fn refused the caller for app; ask
 * the embedder's may_manage hook on a worker and, if it allows, run fn
 * again on the server thread. Good_CompletesAsynchronously, or
 * Bad_UserAccessDenied when there is no hook (or it was asked already). */
GDS_MUST_CHECK UA_StatusCode gds_embed_defer_rights(gds_server *s, UA_MethodCallback fn,
                                                    const UA_NodeId *sessionId, void *sessionContext,
                                                    const UA_NodeId *methodId,
                                                    const UA_NodeId *objectId, const UA_Guid *app,
                                                    size_t inputSize, const UA_Variant *input,
                                                    size_t outputSize, UA_Variant *output);
/* Is a plugin callback bound to this method node? */
bool gds_embed_bound(gds_server *s, const UA_NodeId *methodId);
/* Drop the bindings whose method node no longer exists. */
void gds_embed_prune(gds_server *s);
gds_status gds_ua_status(UA_StatusCode r);
/* RolePermissions of embedder nodes (gds_nodes.c, issue #49). */
void gds_nodes_prune(gds_server *s);
void gds_nodes_free(gds_server *s);

/* Role NodeIds to gds_role bits, plus the implicit Anonymous and
 * AuthenticatedUser; GDS_EINVAL for a Role no session can hold. */
GDS_MUST_CHECK gds_status gds_role_bits(const gds_server *s, const UA_NodeId *roles, size_t n,
                                        unsigned *bits, bool *anonymous, bool *authenticated);
/* The session-level part of the access check (Roles, security mode). */
bool gds_embed_executable(const gds_binding *b, const void *sessionContext);

#define GDS_METHOD(name)                                                                 \
    UA_StatusCode name(UA_Server *server, const UA_NodeId *sessionId, void *sessionContext, \
                       const UA_NodeId *methodId, void *methodContext,                     \
                       const UA_NodeId *objectId, void *objectContext, size_t inputSize,   \
                       const UA_Variant *input, size_t outputSize, UA_Variant *output)
#define GDS_METHOD_UNUSED                                                                \
    (void)server, (void)sessionId, (void)methodId, (void)objectId, (void)objectContext,   \
        (void)outputSize

/* The method's node context is the gds_server. */
static inline gds_server *gds_ctx(void *methodContext) {
    return (gds_server *)methodContext;
}

static inline void gds_lock(gds_server *s) {
    pthread_mutex_lock(&s->storeLock);
}
static inline void gds_unlock(gds_server *s) {
    pthread_mutex_unlock(&s->storeLock);
}

/* A STANDBY node refuses every state-changing GDS method with
 * Bad_InvalidState before it touches the store or a plugin
 * (docs/architecture.md, "Plugin API rules"; issue #15). */
static inline UA_StatusCode gds_refuse_on_standby(gds_server *s) {
    return gds_server_role(s) == GDS_NODE_STANDBY ? UA_STATUSCODE_BADINVALIDSTATE
                                                  : UA_STATUSCODE_GOOD;
}

/* Inputs: the count first, then each argument's type and shape. */
GDS_MUST_CHECK UA_StatusCode gds_in_nodeid(size_t inputSize, const UA_Variant *input, size_t i,
                                           const UA_NodeId **out);
/* An ApplicationId / RequestId: a GUID NodeId in the GDS namespace. */
GDS_MUST_CHECK UA_StatusCode gds_in_guid(const gds_server *s, size_t inputSize,
                                         const UA_Variant *input, size_t i, UA_Guid *out);
GDS_MUST_CHECK UA_StatusCode gds_in_record(size_t inputSize, const UA_Variant *input, size_t i,
                                           const UA_ApplicationRecordDataType **out);

/* Record checks for Register/UpdateApplication (gds_validate.c). */
GDS_MUST_CHECK UA_StatusCode gds_validate_record(const UA_ApplicationRecordDataType *rec);

/* The record from the store with its applicationId in the GDS namespace. */
GDS_MUST_CHECK UA_StatusCode gds_load_app(gds_server *s, const UA_Guid *id,
                                          UA_ApplicationRecordDataType *out);

/* Method wiring, one table per file. */
GDS_MUST_CHECK UA_StatusCode gds_directory_install(gds_server *s);
GDS_MUST_CHECK UA_StatusCode gds_certmgr_install(gds_server *s);
GDS_MUST_CHECK UA_StatusCode gds_trustlist_install(gds_server *s);
/* The DefaultApplicationGroup trust list (the CA certificate and its CRL),
 * the lists in masks only; *out is a deep copy. Any thread. */
GDS_MUST_CHECK UA_StatusCode gds_trustlist_data(gds_server *s, UA_UInt32 masks,
                                                UA_TrustListDataType *out);
/* Issuance holds (gds_registrar.c, UASM ask A13): is this application's
 * issuance held back? Any thread; holdLock is a leaf lock. */
bool gds_issuance_held(gds_server *s, const UA_Guid *appId);
void gds_holds_free(gds_server *s);
/* Audit log + event with ClientUserId user (gds_audit.c). */
GDS_MUST_CHECK gds_status gds_audit_raise(gds_server *s, const char *user,
                                          const gds_audit_event *ev, int64_t *seq);
/* RevokeCertificate (gds_revoke.c). */
GDS_MUST_CHECK UA_StatusCode gds_revoke_install(gds_server *s);
/* Revoke every certificate of appId: store first, then the CA's CRL.
 * Server thread; takes storeLock for the store part only. */
GDS_MUST_CHECK UA_StatusCode gds_revoke_app_certs(gds_server *s, const UA_Guid *appId);
/* Approvals (gds_approvals.c): the source object, Respond/Respond2 and a
 * dialog for every Pending request in the store. Before the server runs. */
GDS_MUST_CHECK UA_StatusCode gds_approvals_install(gds_server *s);
/* A dialog for a request just stored as Pending. Server thread. */
GDS_MUST_CHECK UA_StatusCode gds_approvals_raise(gds_server *s, const gds_request *q,
                                                 const UA_String *appUri);
/* The node role changed: re-synchronise the dialogs with the store on the
 * server thread (none on a STANDBY). Any thread. */
void gds_approvals_role_changed(gds_server *s);
/* Plugin alarms (gds_alarms.c): the Acknowledge handler and the event
 * queue size for ConditionRefresh; before the server runs. */
GDS_MUST_CHECK UA_StatusCode gds_alarms_install(gds_server *s);
/* After UA_Server_delete. */
void gds_alarms_free(gds_server *s);
/* (Re)binds OpenGDS's Acknowledge handler: after every
 * UA_Server_createCondition, which binds open62541's. */
UA_StatusCode gds_alarms_bind_ack(gds_server *s);
/* The EventId of the alarm's last event (a copy). Server thread. */
GDS_MUST_CHECK UA_StatusCode gds_alarm_last_event_id(const gds_alarm *a, UA_ByteString *out);
/* Condition fields, scalar values only (OPC 10000-9 §5.5.2). */
GDS_MUST_CHECK UA_StatusCode gds_cond_set_field(UA_Server *ua, UA_NodeId c, const char *field,
                                                const void *v, const UA_DataType *t);
/* A TwoStateVariable field: its text and its Id. */
GDS_MUST_CHECK UA_StatusCode gds_cond_set_two_state(UA_Server *ua, UA_NodeId c, const char *field,
                                                    UA_Boolean id, const char *text);
/* Policy (gds_policy.c): Received (approved) or Pending for a request made
 * by sessionContext. Takes storeLock. */
GDS_MUST_CHECK gds_status gds_policy_initial_state(gds_server *s, const void *sessionContext,
                                                   const gds_request *q, gds_req_state *out);

/* Signing worker (gds_certmgr.c). */
GDS_MUST_CHECK gds_status gds_worker_start(gds_server *s);
void gds_worker_stop(gds_server *s);
void gds_worker_kick(gds_server *s);

typedef struct {
    UA_UInt32 id;
    UA_MethodCallback cb;
} gds_method_entry;
GDS_MUST_CHECK UA_StatusCode gds_install_methods(gds_server *s, const gds_method_entry *m,
                                                 size_t n);
/* An argument of a method node: name, ns 0 DataType id, scalar or array */
typedef struct {
    const char *name;
    UA_UInt32 dataType;
    bool array;
} gds_method_arg;
/* Add an Optional method of the Directory object (12 §7.9) that the GDS
 * nodeset does not instantiate, with its MethodType's arguments. Nothing
 * happens when the node exists already. */
GDS_MUST_CHECK UA_StatusCode gds_add_directory_method(gds_server *s, UA_UInt32 id, const char *name,
                                                      const gds_method_arg *in, size_t nIn,
                                                      const gds_method_arg *out, size_t nOut);

#endif
