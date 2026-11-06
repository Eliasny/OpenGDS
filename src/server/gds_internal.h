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
    bool started; /* gds_server_run was called (__atomic) */
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
/* Policy (gds_policy.c): Received (approved) or Pending. Takes storeLock. */
GDS_MUST_CHECK gds_status gds_policy_initial_state(gds_server *s, const gds_request *q,
                                                   gds_req_state *out);

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

#endif
