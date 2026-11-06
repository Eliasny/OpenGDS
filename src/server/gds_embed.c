/* OpenGDS - embedder address space and plugin methods (UASM ask A5,
 * issue #16).
 *
 * Threads (docs/spikes/02-async-methods-worker-pool.md, the handoff
 * pattern):
 *   1. Server thread, method callback: refuse a standby write, a full
 *      queue, a missing session; deep-copy the inputs into a job, note the
 *      job's output pointer in the in-flight table, queue it, and return
 *      Good_CompletesAsynchronously.
 *   2. Worker: build the caller view (gds_caller.c), check the method's
 *      Roles, Privileges and security mode, run the callback on job-owned
 *      memory, push the job onto the done list and wake the server thread
 *      with a timed callback. No lock of ours is held across a call into
 *      open62541.
 *   3. Server thread, drain: for each done job whose output pointer is
 *      still set, move the outputs and call
 *      UA_Server_setAsyncCallMethodResult; free the job.
 *   4. Cancel callback (timeout, Cancel service, UA_Server_delete; under
 *      the server lock): clear the job's output pointer. No lock taken.
 * The in-flight table and output pointers are touched only on the server
 * thread (or by gds_server_delete after the loop stopped).
 *
 * Runtime changes (UASM ask A9, issue #49): bindings can be added and
 * removed while the server runs, also from a plugin worker. bindLock
 * guards the bindings table; it is a leaf lock, taken by the access checks
 * under open62541's server lock and never held across a call into
 * open62541. A binding is reference counted: the table holds one
 * reference and every job one more, so a removed method's running calls
 * finish on memory that stays valid.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>

#include <stdlib.h>
#include <string.h>

#include "gds_internal.h"
#include "common/banned.h"

struct gds_binding {
    gds_server *s;
    UA_NodeId methodId;
    gds_method_fn fn;
    void *ctx;
    unsigned roleBits; /* gds_role bits */
    bool anonymous, authenticated;
    char *privileges[GDS_MAX_PRIVILEGES];
    size_t nPrivileges;
    gds_security_mode minMode;
    uint32_t flags;
    int refs; /* atomic */
};

struct gds_job {
    struct gds_job *next;
    const gds_binding *b;
    UA_NodeId sessionId;
    gds_session snap; /* the session as it was at the call; job-owned */
    UA_NodeId objectId;
    UA_Variant *in;
    size_t nIn;
    UA_Variant *out; /* job-owned outputs */
    size_t nOut;
    UA_Variant *output; /* open62541's; server thread only, NULL once cancelled */
    UA_StatusCode status;
};

/* ---- the worker pool ---- */

static void binding_free(gds_binding *b) {
    UA_NodeId_clear(&b->methodId);
    for(size_t k = 0; k < b->nPrivileges; k++)
        free(b->privileges[k]);
    free(b);
}

static void binding_release(const gds_binding *cb) {
    gds_binding *b = (gds_binding *)(uintptr_t)cb;
    if(b && __atomic_sub_fetch(&b->refs, 1, __ATOMIC_ACQ_REL) == 0)
        binding_free(b);
}

static void job_free(gds_job *j) {
    if(!j)
        return;
    binding_release(j->b);
    UA_NodeId_clear(&j->sessionId);
    UA_NodeId_clear(&j->objectId);
    UA_Array_delete(j->in, j->nIn, &UA_TYPES[UA_TYPES_VARIANT]);
    UA_Array_delete(j->out, j->nOut, &UA_TYPES[UA_TYPES_VARIANT]);
    UA_String_clear(&j->snap.clientAppUri);
    UA_String_clear(&j->snap.securityPolicyUri);
    free(j);
}

static bool caller_allowed(const gds_binding *b, const gds_caller *c) {
    if(c->securityMode < b->minMode)
        return false;
    if(b->anonymous)
        return true;
    if(b->authenticated && c->userName)
        return true;
    size_t n = 0;
    const gds_role_info *t = gds_role_table(&n);
    for(size_t i = 0; i < n; i++) {
        if(!(b->roleBits & t[i].bit))
            continue;
        UA_NodeId r = UA_NODEID_NUMERIC(t[i].gdsNamespace ? b->s->ns : 0, t[i].id);
        if(gds_caller_has_role(c, &r))
            return true;
    }
    for(size_t i = 0; i < b->nPrivileges; i++)
        if(gds_caller_has_privilege(c, b->privileges[i]))
            return true;
    return false;
}

static void run_job(gds_job *j) {
    gds_caller_buf cb;
    gds_status st = gds_caller_build(j->b->s, &j->sessionId, &j->snap, &cb);
    if(st != GDS_OK) {
        j->status = st == GDS_EDENIED ? UA_STATUSCODE_BADUSERACCESSDENIED : gds_status_to_ua(st);
        return;
    }
    /* RolePermissions again here: open62541 skips the object check for
     * its local admin session, and they may have changed since the call */
    gds_server *s = j->b->s;
    if(!gds_node_call_allowed(s, &j->snap, &j->objectId) ||
       !gds_node_call_allowed(s, &j->snap, &j->b->methodId) || !caller_allowed(j->b, &cb.view)) {
        j->status = UA_STATUSCODE_BADUSERACCESSDENIED;
    } else {
        j->status = j->b->fn(j->b->ctx, &cb.view, &j->objectId, j->nIn, j->in, j->nOut, j->out);
        if(j->status == UA_STATUSCODE_GOODCOMPLETESASYNCHRONOUSLY)
            j->status = UA_STATUSCODE_BADINTERNALERROR; /* not for plugins */
    }
    gds_caller_buf_clear(&cb);
}

static void drain(UA_Server *server, void *data);

static void *worker_main(void *arg) {
    gds_server *s = arg;
    for(;;) {
        pthread_mutex_lock(&s->plugLock);
        while(!s->plugQueue && !s->plugStop)
            pthread_cond_wait(&s->plugCond, &s->plugLock);
        gds_job *j = s->plugQueue;
        if(!j) {
            pthread_mutex_unlock(&s->plugLock);
            return NULL;
        }
        s->plugQueue = j->next;
        if(!s->plugQueue)
            s->plugQueueTail = NULL;
        s->plugQueued--;
        pthread_mutex_unlock(&s->plugLock);

        j->next = NULL;
        run_job(j);

        pthread_mutex_lock(&s->plugLock);
        j->next = s->plugDone;
        s->plugDone = j;
        bool stopping = s->plugStop;
        pthread_mutex_unlock(&s->plugLock);
        if(!stopping)
            (void)UA_Server_addTimedCallback(s->ua, drain, s, UA_DateTime_nowMonotonic(), NULL);
    }
}

static gds_status pool_start(gds_server *s) {
    if(s->plugWorkers > 0)
        return GDS_OK;
    for(size_t i = 0; i < GDS_PLUGIN_WORKERS; i++) {
        if(pthread_create(&s->plugThreads[i], NULL, worker_main, s) != 0)
            return GDS_ENOMEM;
        s->plugWorkers++;
    }
    return GDS_OK;
}

/* Server thread (or the deleting thread once the loop stopped). */
static void drain(UA_Server *server, void *data) {
    gds_server *s = data;
    pthread_mutex_lock(&s->plugLock);
    gds_job *list = s->plugDone;
    s->plugDone = NULL;
    pthread_mutex_unlock(&s->plugLock);
    while(list) {
        gds_job *j = list;
        list = j->next;
        if(j->output) {
            for(size_t i = 0; i < j->nOut; i++) {
                j->output[i] = j->out[i]; /* moved */
                UA_Variant_init(&j->out[i]);
            }
            (void)UA_Server_setAsyncCallMethodResult(server, j->output, j->status);
        }
        for(size_t i = 0; i < GDS_PLUGIN_QUEUE; i++)
            if(s->plugInflight[i] == j)
                s->plugInflight[i] = NULL;
        job_free(j);
    }
}

static void cancel_cb(UA_Server *server, const void *out) {
    gds_server *s = UA_Server_getConfig(server)->context;
    if(!s)
        return;
    for(size_t i = 0; i < GDS_PLUGIN_QUEUE; i++)
        if(s->plugInflight[i] && (const void *)s->plugInflight[i]->output == out)
            s->plugInflight[i]->output = NULL;
}

void gds_embed_configure(UA_ServerConfig *c, gds_server *s) {
    c->context = s;
    c->asyncOperationCancelCallback = cancel_cb;
    c->asyncOperationTimeout = GDS_PLUGIN_CALL_TIMEOUT_MS;
    /* a backstop above our own queue, which answers Bad_ServerTooBusy */
    c->maxAsyncOperationQueueSize = (size_t)2 * GDS_PLUGIN_QUEUE;
}

void gds_embed_stop(gds_server *s) {
    pthread_mutex_lock(&s->plugLock);
    s->plugStop = true;
    pthread_cond_broadcast(&s->plugCond);
    pthread_mutex_unlock(&s->plugLock);
    for(size_t i = 0; i < s->plugWorkers; i++)
        pthread_join(s->plugThreads[i], NULL);
    s->plugWorkers = 0;
    if(s->ua)
        drain(s->ua, s); /* complete what finished */
}

void gds_embed_free(gds_server *s) {
    /* after UA_Server_delete: every remaining job was cancelled */
    for(size_t i = 0; i < GDS_PLUGIN_QUEUE; i++) {
        s->plugInflight[i] = NULL;
    }
    gds_job *j = s->plugQueue;
    while(j) {
        gds_job *n = j->next;
        job_free(j);
        j = n;
    }
    s->plugQueue = s->plugQueueTail = NULL;
    for(size_t i = 0; i < s->nBindings; i++)
        binding_release(s->bindings[i]);
    s->nBindings = 0;
    gds_nodes_free(s);
}

/* The job for one call: copies of everything it needs. The session can
 * change or close while the job waits, so the worker reads a copy, never
 * the open62541 session context. */
static UA_StatusCode job_new(const gds_binding *b, const gds_session *ss,
                             const UA_NodeId *sessionId, const UA_NodeId *objectId,
                             size_t inputSize, const UA_Variant *input, size_t outputSize,
                             gds_job **out) {
    gds_job *j = calloc(1, sizeof(*j));
    if(!j)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    __atomic_add_fetch(&((gds_binding *)(uintptr_t)b)->refs, 1, __ATOMIC_ACQ_REL);
    j->b = b;
    j->snap.anonymous = ss->anonymous;
    memcpy(j->snap.user, ss->user, sizeof(j->snap.user));
    j->snap.roles = ss->roles;
    j->snap.securityMode = ss->securityMode;
    UA_StatusCode r = UA_String_copy(&ss->clientAppUri, &j->snap.clientAppUri);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_String_copy(&ss->securityPolicyUri, &j->snap.securityPolicyUri);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_NodeId_copy(sessionId, &j->sessionId);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_NodeId_copy(objectId, &j->objectId);
    if(r == UA_STATUSCODE_GOOD && inputSize > 0) {
        r = UA_Array_copy(input, inputSize, (void **)&j->in, &UA_TYPES[UA_TYPES_VARIANT]);
        if(r == UA_STATUSCODE_GOOD)
            j->nIn = inputSize;
    }
    if(r == UA_STATUSCODE_GOOD && outputSize > 0) {
        j->out = UA_Array_new(outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
        if(j->out)
            j->nOut = outputSize;
        else
            r = UA_STATUSCODE_BADOUTOFMEMORY;
    }
    if(r != UA_STATUSCODE_GOOD) {
        job_free(j);
        return r;
    }
    *out = j;
    return UA_STATUSCODE_GOOD;
}

/* ---- the method trampoline (server thread) ---- */

static UA_StatusCode call_cb(UA_Server *server, const UA_NodeId *sessionId, void *sessionContext,
                             const UA_NodeId *methodId, void *methodContext,
                             const UA_NodeId *objectId, void *objectContext, size_t inputSize,
                             const UA_Variant *input, size_t outputSize, UA_Variant *output) {
    (void)server, (void)methodId, (void)objectContext;
    const gds_binding *b = methodContext;
    gds_server *s = b ? b->s : NULL;
    if(!s || !sessionContext)
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    if(!(b->flags & GDS_METHOD_READ_ONLY) && gds_server_role(s) == GDS_NODE_STANDBY)
        return UA_STATUSCODE_BADINVALIDSTATE;
    size_t slot = GDS_PLUGIN_QUEUE;
    for(size_t i = 0; i < GDS_PLUGIN_QUEUE && slot == GDS_PLUGIN_QUEUE; i++)
        if(!s->plugInflight[i])
            slot = i;
    if(slot == GDS_PLUGIN_QUEUE)
        return UA_STATUSCODE_BADSERVERTOOBUSY;

    gds_job *j = NULL;
    UA_StatusCode r = job_new(b, sessionContext, sessionId, objectId, inputSize, input,
                              outputSize, &j);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    j->output = output;
    s->plugInflight[slot] = j;
    pthread_mutex_lock(&s->plugLock);
    if(s->plugQueueTail)
        s->plugQueueTail->next = j;
    else
        s->plugQueue = j;
    s->plugQueueTail = j;
    s->plugQueued++;
    pthread_cond_signal(&s->plugCond);
    pthread_mutex_unlock(&s->plugLock);
    return UA_STATUSCODE_GOODCOMPLETESASYNCHRONOUSLY;
}

/* ---- getUserExecutable for embedder methods (gds_access.c) ---- */

/* bindLock held */
static size_t find_locked(const gds_server *s, const UA_NodeId *methodId) {
    for(size_t i = 0; i < s->nBindings; i++)
        if(UA_NodeId_equal(&s->bindings[i]->methodId, methodId))
            return i;
    return s->nBindings;
}

bool gds_embed_bound(gds_server *s, const UA_NodeId *methodId) {
    if(!s)
        return false;
    pthread_mutex_lock(&s->bindLock);
    bool found = find_locked(s, methodId) < s->nBindings;
    pthread_mutex_unlock(&s->bindLock);
    return found;
}

/* The table takes b's first reference. */
static gds_status bind_insert(gds_server *s, gds_binding *b) {
    gds_status st = GDS_OK;
    pthread_mutex_lock(&s->bindLock);
    if(find_locked(s, &b->methodId) < s->nBindings)
        st = GDS_EEXISTS;
    else if(s->nBindings == GDS_MAX_PLUGIN_METHODS)
        st = GDS_ETOOBIG;
    else
        s->bindings[s->nBindings++] = b;
    pthread_mutex_unlock(&s->bindLock);
    if(st == GDS_OK)
        __atomic_store_n(&b->refs, 1, __ATOMIC_RELEASE);
    return st;
}

static void bind_remove(gds_server *s, const UA_NodeId *methodId) {
    gds_binding *b = NULL;
    pthread_mutex_lock(&s->bindLock);
    size_t i = find_locked(s, methodId);
    if(i < s->nBindings) {
        b = s->bindings[i];
        s->bindings[i] = s->bindings[--s->nBindings];
        s->bindings[s->nBindings] = NULL;
    }
    pthread_mutex_unlock(&s->bindLock);
    binding_release(b);
}

/* Drops the bindings whose method node is gone (removed with its parent). */
void gds_embed_prune(gds_server *s) {
    UA_NodeId *ids = calloc(GDS_MAX_PLUGIN_METHODS, sizeof(*ids));
    size_t n = 0;
    if(!ids)
        return; /* the stale bindings stay until the next prune; harmless */
    pthread_mutex_lock(&s->bindLock);
    for(size_t i = 0; i < s->nBindings; i++)
        if(UA_NodeId_copy(&s->bindings[i]->methodId, &ids[n]) == UA_STATUSCODE_GOOD)
            n++;
    pthread_mutex_unlock(&s->bindLock);
    for(size_t i = 0; i < n; i++) {
        UA_NodeClass nc = UA_NODECLASS_UNSPECIFIED;
        if(UA_Server_readNodeClass(s->ua, ids[i], &nc) == UA_STATUSCODE_BADNODEIDUNKNOWN)
            bind_remove(s, &ids[i]);
        UA_NodeId_clear(&ids[i]);
    }
    free(ids);
}

/* What the session alone can tell, on the server thread: the Roles and
 * the security mode. Privileges are known only on the worker, so a method
 * with Privileges stays executable here and is checked there. */
bool gds_embed_executable(const gds_binding *b, const void *sessionContext) {
    const gds_session *ss = gds_session_get(sessionContext);
    if(!ss || (gds_security_mode)ss->securityMode < b->minMode)
        return false;
    if(b->anonymous || b->nPrivileges > 0 || (b->authenticated && !ss->anonymous))
        return true;
    return (ss->roles & b->roleBits) != 0;
}

int gds_embed_decide(const gds_server *s, const void *sessionContext, const UA_NodeId *methodId) {
    if(!s)
        return -1;
    gds_server *ms = (gds_server *)(uintptr_t)s; /* the lock only */
    pthread_mutex_lock(&ms->bindLock);
    size_t i = find_locked(s, methodId);
    int d = i < s->nBindings ? (gds_embed_executable(s->bindings[i], sessionContext) ? 1 : 0) : -2;
    pthread_mutex_unlock(&ms->bindLock);
    if(d != -2)
        return d;
    if(methodId->namespaceIndex == 0)
        return -1;
    /* the GDS methods check rights themselves; nothing else is offered */
    return s && methodId->namespaceIndex == s->ns ? 1 : 0;
}

/* ---- registration (before or while the server runs) ---- */

gds_status gds_role_bits(const gds_server *s, const UA_NodeId *roles, size_t n, unsigned *bits,
                         bool *anonymous, bool *authenticated) {
    if(n > GDS_MAX_METHOD_ROLES || (n && !roles))
        return GDS_EINVAL;
    size_t nt = 0;
    const gds_role_info *t = gds_role_table(&nt);
    for(size_t i = 0; i < n; i++) {
        const UA_NodeId *r = &roles[i];
        if(r->identifierType != UA_NODEIDTYPE_NUMERIC)
            return GDS_EINVAL;
        if(r->namespaceIndex == 0 && r->identifier.numeric == UA_NS0ID_WELLKNOWNROLE_ANONYMOUS) {
            *anonymous = true;
            continue;
        }
        if(r->namespaceIndex == 0 &&
           r->identifier.numeric == UA_NS0ID_WELLKNOWNROLE_AUTHENTICATEDUSER) {
            *authenticated = true;
            continue;
        }
        unsigned bit = 0;
        for(size_t k = 0; k < nt && !bit; k++)
            if(r->namespaceIndex == (t[k].gdsNamespace ? s->ns : 0) &&
               r->identifier.numeric == t[k].id)
                bit = t[k].bit;
        if(!bit)
            return GDS_EINVAL; /* no session can hold it */
        *bits |= bit;
    }
    return GDS_OK;
}

static gds_status new_binding(gds_server *s, const gds_method_def *d, gds_binding **out) {
    *out = NULL;
    if(!s || !d || d->abi_major != GDS_PLUGIN_ABI_MAJOR ||
       d->struct_size < offsetof(gds_method_def, ctx) + sizeof(d->ctx) || !d->fn ||
       d->privilegesSize > GDS_MAX_PRIVILEGES || (d->privilegesSize && !d->privileges) ||
       d->minSecurityMode > GDS_SECURITY_MODE_SIGN_AND_ENCRYPT ||
       (d->flags & ~GDS_METHOD_READ_ONLY) != 0 || UA_NodeId_isNull(&d->methodId))
        return GDS_EINVAL;
    if(d->methodId.namespaceIndex == s->ns)
        return GDS_EDENIED; /* the GDS's own methods */
    gds_binding *b = calloc(1, sizeof(*b));
    if(!b)
        return GDS_ENOMEM;
    b->s = s;
    b->fn = d->fn;
    b->ctx = d->ctx;
    b->flags = d->flags;
    b->minMode = d->minSecurityMode == GDS_SECURITY_MODE_INVALID
                     ? GDS_SECURITY_MODE_SIGN_AND_ENCRYPT
                     : d->minSecurityMode;
    gds_status st = gds_role_bits(s, d->roles, d->rolesSize, &b->roleBits, &b->anonymous,
                                  &b->authenticated);
    if(st == GDS_OK && UA_NodeId_copy(&d->methodId, &b->methodId) != UA_STATUSCODE_GOOD)
        st = GDS_ENOMEM;
    gds_privilege_set ps = {{0}, 0};
    for(size_t i = 0; i < d->privilegesSize && st == GDS_OK; i++)
        st = gds_privilege_set_add(&ps, d->privileges[i]);
    for(size_t i = 0; i < ps.n; i++)
        b->privileges[i] = ps.names[i];
    b->nPrivileges = ps.n;
    if(st == GDS_OK && !b->anonymous && !b->authenticated && !b->roleBits && !b->nPrivileges)
        st = GDS_EINVAL; /* nobody could call it */
    if(st == GDS_OK)
        st = pool_start(s);
    if(st == GDS_OK)
        st = bind_insert(s, b);
    if(st != GDS_OK) {
        binding_free(b);
        return st;
    }
    *out = b;
    return GDS_OK;
}

gds_status gds_ua_status(UA_StatusCode r) {
    if(r == UA_STATUSCODE_GOOD)
        return GDS_OK;
    if(r == UA_STATUSCODE_BADNODEIDEXISTS || r == UA_STATUSCODE_BADBROWSENAMEDUPLICATED)
        return GDS_EEXISTS;
    if(r == UA_STATUSCODE_BADNODEIDUNKNOWN || r == UA_STATUSCODE_BADPARENTNODEIDINVALID ||
       r == UA_STATUSCODE_BADTYPEDEFINITIONINVALID)
        return GDS_ENOTFOUND;
    if(r == UA_STATUSCODE_BADOUTOFMEMORY)
        return GDS_ENOMEM;
    return GDS_EINVAL;
}

static bool name_ok(const char *n) {
    size_t len = n ? strnlen(n, GDS_MAX_STRING + 1) : 0;
    return len > 0 && len <= GDS_MAX_STRING;
}

static bool args_ok(const UA_Argument *a, size_t n) {
    return n <= GDS_MAX_METHOD_ARGS && (n == 0 || a);
}

gds_status gds_server_add_method(gds_server *s, const gds_method_def *d) {
    if(!d || !name_ok(d->browseName) || (d->displayName && !name_ok(d->displayName)) ||
       !args_ok(d->inputArguments, d->inputArgumentsSize) ||
       !args_ok(d->outputArguments, d->outputArgumentsSize))
        return GDS_EINVAL;
    gds_binding *b = NULL;
    gds_status st = new_binding(s, d, &b);
    if(st != GDS_OK)
        return st;
    UA_MethodAttributes ma = UA_MethodAttributes_default;
    ma.displayName = UA_LOCALIZEDTEXT("", (char *)(uintptr_t)(d->displayName ? d->displayName
                                                                             : d->browseName));
    ma.executable = true;
    ma.userExecutable = true;
    UA_QualifiedName bn = UA_QUALIFIEDNAME(d->methodId.namespaceIndex,
                                           (char *)(uintptr_t)d->browseName);
    UA_StatusCode r = UA_Server_addMethodNode(
        s->ua, d->methodId, d->parentId, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT), bn, ma,
        call_cb, d->inputArgumentsSize, d->inputArguments, d->outputArgumentsSize,
        d->outputArguments, b, NULL);
    if(r != UA_STATUSCODE_GOOD) {
        bind_remove(s, &d->methodId);
        return gds_ua_status(r);
    }
    return GDS_OK;
}

gds_status gds_server_bind_method(gds_server *s, const gds_method_def *d) {
    UA_NodeClass nc = UA_NODECLASS_UNSPECIFIED;
    if(!s || !d)
        return GDS_EINVAL;
    UA_StatusCode r = UA_Server_readNodeClass(s->ua, d->methodId, &nc);
    if(r != UA_STATUSCODE_GOOD)
        return GDS_ENOTFOUND;
    if(nc != UA_NODECLASS_METHOD)
        return GDS_EINVAL;
    gds_binding *b = NULL;
    gds_status st = new_binding(s, d, &b);
    if(st != GDS_OK)
        return st;
    r = UA_Server_setNodeContext(s->ua, d->methodId, b);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_setMethodNodeCallback(s->ua, d->methodId, call_cb);
    if(r != UA_STATUSCODE_GOOD) {
        (void)UA_Server_setNodeContext(s->ua, d->methodId, NULL);
        bind_remove(s, &d->methodId);
        return gds_ua_status(r);
    }
    return GDS_OK;
}

gds_status gds_server_add_namespace(gds_server *s, const char *uri, UA_UInt16 *nsIndex) {
    if(!s || !nsIndex || !name_ok(uri))
        return GDS_EINVAL;
    if(strcmp(uri, GDS_NS_URI) == 0)
        return GDS_EDENIED;
    UA_UInt16 ns = UA_Server_addNamespace(s->ua, uri);
    if(ns == 0)
        return GDS_ENOMEM;
    *nsIndex = ns;
    return GDS_OK;
}

gds_status gds_server_load_nodeset(gds_server *s, gds_nodeset_fn fn) {
    if(!s || !fn)
        return GDS_EINVAL;
    return gds_ua_status(fn(s->ua));
}

gds_status gds_server_add_object(gds_server *s, const UA_NodeId *nodeId, const UA_NodeId *parentId,
                                 const char *browseName, const UA_NodeId *typeDefinition) {
    if(!s || !nodeId || !parentId || !name_ok(browseName) || nodeId->namespaceIndex == s->ns)
        return GDS_EINVAL;
    UA_ObjectAttributes oa = UA_ObjectAttributes_default;
    oa.displayName = UA_LOCALIZEDTEXT("", (char *)(uintptr_t)browseName);
    UA_NodeId objects = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    UA_NodeId ref = UA_NODEID_NUMERIC(
        0, UA_NodeId_equal(parentId, &objects) ? UA_NS0ID_ORGANIZES : UA_NS0ID_HASCOMPONENT);
    UA_NodeId type = typeDefinition && !UA_NodeId_isNull(typeDefinition)
                         ? *typeDefinition
                         : UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE);
    UA_QualifiedName bn = UA_QUALIFIEDNAME(nodeId->namespaceIndex, (char *)(uintptr_t)browseName);
    return gds_ua_status(
        UA_Server_addObjectNode(s->ua, *nodeId, *parentId, ref, bn, type, oa, NULL, NULL));
}
