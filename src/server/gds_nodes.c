/* OpenGDS - runtime embedder nodes: RolePermissions and removal (UASM ask
 * A9, issue #49).
 *
 * RolePermissions (OPC 10000-3 §5.2.9; the permission bits are
 * PermissionType, §8.55) are kept in a table here, keyed by NodeId, under
 * the server's bindLock. OpenGDS enforces the Call permission in the
 * getUserExecutableOnObject check (gds_access.c), on the object and on
 * the method node. A node without RolePermissions falls back to the
 * method's own checks: OpenGDS publishes no DefaultRolePermissions
 * (§5.2.9 lets a server leave them out).
 *
 * Role Booleans (UASM ask A17): an embedder Boolean variable whose value
 * is computed per session from its Roles, as UserExecutable is, for
 * example the UserWritable Property of an OPC 10000-20 FileType (§4.2.1).
 * The table is kept under bindLock too.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>

#include <stdlib.h>
#include <string.h>

#include "gds_internal.h"
#include "common/banned.h"

#define MAX_PERM_NODES 4096
#define MAX_ROLE_BOOLEANS 256
#define PERMISSION_MASK 0x1FFFFu /* PermissionType bits 0..16 */

typedef struct {
    unsigned roleBits;
    bool anonymous, authenticated;
    uint32_t permissions;
} perm_entry;

struct gds_node_perms {
    UA_NodeId node;
    size_t n;
    perm_entry e[GDS_MAX_ROLE_PERMISSIONS];
};

struct gds_role_bool {
    UA_NodeId node;
    unsigned roleBits;
    bool anonymous, authenticated;
};

/* bindLock held */
static size_t find_perms(const gds_server *s, const UA_NodeId *node) {
    for(size_t i = 0; i < s->nPerms; i++)
        if(UA_NodeId_equal(&s->perms[i].node, node))
            return i;
    return s->nPerms;
}

/* bindLock held */
static void drop_perms(gds_server *s, size_t i) {
    UA_NodeId_clear(&s->perms[i].node);
    s->perms[i] = s->perms[--s->nPerms];
    memset(&s->perms[s->nPerms], 0, sizeof(s->perms[s->nPerms]));
}

/* What the entries grant to a holder of these Roles. */
static uint32_t granted(const gds_node_perms *p, unsigned roles, bool anonymous) {
    uint32_t g = 0;
    for(size_t i = 0; i < p->n; i++) {
        const perm_entry *e = &p->e[i];
        if(e->anonymous || (e->authenticated && !anonymous) || (e->roleBits & roles))
            g |= e->permissions;
    }
    return g;
}

static bool allowed(gds_server *s, const UA_NodeId *node, unsigned roles, bool anonymous,
                    uint32_t want) {
    pthread_mutex_lock(&s->bindLock);
    size_t i = find_perms(s, node);
    bool ok = i == s->nPerms || (granted(&s->perms[i], roles, anonymous) & want) == want;
    pthread_mutex_unlock(&s->bindLock);
    return ok;
}

bool gds_node_call_allowed(gds_server *s, const void *sessionContext, const UA_NodeId *nodeId) {
    const gds_session *ss = gds_session_get(sessionContext);
    if(!s || !nodeId)
        return true;
    if(!ss)
        return allowed(s, nodeId, 0, true, UA_PERMISSIONTYPE_CALL);
    return allowed(s, nodeId, gds_session_roles(ss), gds_session_anonymous(ss),
                   UA_PERMISSIONTYPE_CALL);
}

bool gds_caller_permitted(gds_server *s, const gds_caller *c, const UA_NodeId *nodeId,
                          uint32_t permissions) {
    if(!s || !c || !nodeId)
        return false;
    unsigned roles = 0;
    bool anon = false, auth = false;
    /* every Role of a caller is in the table; Anonymous always is */
    if(gds_role_bits(s, c->roles, c->rolesSize, &roles, &anon, &auth) != GDS_OK)
        return false;
    return allowed(s, nodeId, roles, !auth, permissions);
}

static gds_status to_entries(gds_server *s, const gds_role_permission *p, size_t n,
                             perm_entry *out) {
    for(size_t i = 0; i < n; i++) {
        if((p[i].permissions & ~PERMISSION_MASK) != 0)
            return GDS_EINVAL;
        memset(&out[i], 0, sizeof(out[i]));
        out[i].permissions = p[i].permissions;
        gds_status st = gds_role_bits(s, &p[i].roleId, 1, &out[i].roleBits, &out[i].anonymous,
                                      &out[i].authenticated);
        if(st != GDS_OK)
            return st;
    }
    return GDS_OK;
}

/* bindLock held */
static gds_status put_perms(gds_server *s, const UA_NodeId *node, const perm_entry *e, size_t n) {
    size_t i = find_perms(s, node);
    if(n == 0) {
        if(i < s->nPerms)
            drop_perms(s, i);
        return GDS_OK;
    }
    if(i == s->nPerms) {
        if(s->nPerms == MAX_PERM_NODES)
            return GDS_ETOOBIG;
        if(s->nPerms == s->capPerms) {
            size_t cap = s->capPerms ? s->capPerms * 2 : 16;
            gds_node_perms *g = realloc(s->perms, cap * sizeof(*g));
            if(!g)
                return GDS_ENOMEM;
            s->perms = g;
            s->capPerms = cap;
        }
        memset(&s->perms[i], 0, sizeof(s->perms[i]));
        if(UA_NodeId_copy(node, &s->perms[i].node) != UA_STATUSCODE_GOOD)
            return GDS_ENOMEM;
        s->nPerms++;
    }
    memcpy(s->perms[i].e, e, n * sizeof(*e));
    s->perms[i].n = n;
    return GDS_OK;
}

gds_status gds_server_set_role_permissions(gds_server *s, const UA_NodeId *nodeId,
                                           const gds_role_permission *perms, size_t n) {
    if(!s || !nodeId || UA_NodeId_isNull(nodeId) || n > GDS_MAX_ROLE_PERMISSIONS ||
       (n && !perms))
        return GDS_EINVAL;
    if(nodeId->namespaceIndex == s->ns)
        return GDS_EDENIED;
    UA_NodeClass nc = UA_NODECLASS_UNSPECIFIED;
    if(UA_Server_readNodeClass(s->ua, *nodeId, &nc) != UA_STATUSCODE_GOOD)
        return GDS_ENOTFOUND;
    perm_entry e[GDS_MAX_ROLE_PERMISSIONS];
    gds_status st = to_entries(s, perms, n, e);
    if(st != GDS_OK)
        return st;
    pthread_mutex_lock(&s->bindLock);
    st = put_perms(s, nodeId, e, n);
    pthread_mutex_unlock(&s->bindLock);
    return st;
}

static void prune_bools(gds_server *s);

/* Drops the RolePermissions and Role Booleans of nodes that no longer
 * exist. */
void gds_nodes_prune(gds_server *s) {
    prune_bools(s);
    pthread_mutex_lock(&s->bindLock);
    size_t max = s->nPerms;
    UA_NodeId *ids = max ? calloc(max, sizeof(*ids)) : NULL;
    size_t n = 0;
    for(size_t i = 0; ids && i < max; i++)
        if(UA_NodeId_copy(&s->perms[i].node, &ids[n]) == UA_STATUSCODE_GOOD)
            n++;
    pthread_mutex_unlock(&s->bindLock);
    for(size_t i = 0; i < n; i++) {
        UA_NodeClass nc = UA_NODECLASS_UNSPECIFIED;
        if(UA_Server_readNodeClass(s->ua, ids[i], &nc) == UA_STATUSCODE_BADNODEIDUNKNOWN) {
            pthread_mutex_lock(&s->bindLock);
            size_t k = find_perms(s, &ids[i]);
            if(k < s->nPerms)
                drop_perms(s, k);
            pthread_mutex_unlock(&s->bindLock);
        }
        UA_NodeId_clear(&ids[i]);
    }
    free(ids);
}

void gds_nodes_free(gds_server *s) {
    for(size_t i = 0; i < s->nPerms; i++)
        UA_NodeId_clear(&s->perms[i].node);
    free(s->perms);
    s->perms = NULL;
    s->nPerms = s->capPerms = 0;
    for(size_t i = 0; i < s->nRoleBools; i++)
        UA_NodeId_clear(&s->roleBools[i].node);
    free(s->roleBools);
    s->roleBools = NULL;
    s->nRoleBools = s->capRoleBools = 0;
}

/* ---- Role Booleans (A17) ---- */

static size_t find_bool(const gds_server *s, const UA_NodeId *node);
static void drop_bool(gds_server *s, size_t i);

static void prune_bools(gds_server *s) {
    pthread_mutex_lock(&s->bindLock);
    size_t max = s->nRoleBools;
    UA_NodeId *ids = max ? calloc(max, sizeof(*ids)) : NULL;
    size_t n = 0;
    for(size_t i = 0; ids && i < max; i++)
        if(UA_NodeId_copy(&s->roleBools[i].node, &ids[n]) == UA_STATUSCODE_GOOD)
            n++;
    pthread_mutex_unlock(&s->bindLock);
    for(size_t i = 0; i < n; i++) {
        UA_NodeClass nc = UA_NODECLASS_UNSPECIFIED;
        if(UA_Server_readNodeClass(s->ua, ids[i], &nc) == UA_STATUSCODE_BADNODEIDUNKNOWN) {
            pthread_mutex_lock(&s->bindLock);
            size_t k = find_bool(s, &ids[i]);
            if(k < s->nRoleBools)
                drop_bool(s, k);
            pthread_mutex_unlock(&s->bindLock);
        }
        UA_NodeId_clear(&ids[i]);
    }
    free(ids);
}

/* bindLock held */
static size_t find_bool(const gds_server *s, const UA_NodeId *node) {
    for(size_t i = 0; i < s->nRoleBools; i++)
        if(UA_NodeId_equal(&s->roleBools[i].node, node))
            return i;
    return s->nRoleBools;
}

/* bindLock held */
static void drop_bool(gds_server *s, size_t i) {
    UA_NodeId_clear(&s->roleBools[i].node);
    s->roleBools[i] = s->roleBools[--s->nRoleBools];
    memset(&s->roleBools[s->nRoleBools], 0, sizeof(s->roleBools[s->nRoleBools]));
}

static UA_StatusCode read_bool(UA_Server *server, const UA_NodeId *sessionId,
                               void *sessionContext, const UA_NodeId *nodeId, void *nodeContext,
                               UA_Boolean includeSourceTimeStamp, const UA_NumericRange *range,
                               UA_DataValue *value) {
    (void)sessionId, (void)nodeContext, (void)includeSourceTimeStamp;
    gds_server *s = UA_Server_getConfig(server)->context;
    if(range) {
        value->hasStatus = true;
        value->status = UA_STATUSCODE_BADINDEXRANGEINVALID;
        return UA_STATUSCODE_GOOD;
    }
    const gds_session *ss = gds_session_get(sessionContext);
    bool anon = gds_session_anonymous(ss);
    unsigned roles = gds_session_roles(ss);
    UA_Boolean v = false;
    bool found = false;
    pthread_mutex_lock(&s->bindLock);
    size_t i = find_bool(s, nodeId);
    if(i < s->nRoleBools) {
        const gds_role_bool *b = &s->roleBools[i];
        found = true;
        /* no session (an internal read): no Roles */
        v = ss && (b->anonymous || (b->authenticated && !anon) || (b->roleBits & roles) != 0);
    }
    pthread_mutex_unlock(&s->bindLock);
    if(!found) {
        value->hasStatus = true;
        value->status = UA_STATUSCODE_BADNODEIDUNKNOWN;
        return UA_STATUSCODE_GOOD;
    }
    UA_StatusCode r = UA_Variant_setScalarCopy(&value->value, &v, &UA_TYPES[UA_TYPES_BOOLEAN]);
    value->hasValue = r == UA_STATUSCODE_GOOD;
    return r;
}

static bool is_boolean_variable(gds_server *s, const UA_NodeId *nodeId) {
    UA_NodeClass nc = UA_NODECLASS_UNSPECIFIED;
    UA_NodeId dt = UA_NODEID_NULL;
    UA_NodeId boolean = UA_NODEID_NUMERIC(0, UA_NS0ID_BOOLEAN);
    bool ok = UA_Server_readNodeClass(s->ua, *nodeId, &nc) == UA_STATUSCODE_GOOD &&
              nc == UA_NODECLASS_VARIABLE &&
              UA_Server_readDataType(s->ua, *nodeId, &dt) == UA_STATUSCODE_GOOD &&
              UA_NodeId_equal(&dt, &boolean);
    UA_NodeId_clear(&dt);
    return ok;
}

/* bindLock held */
static gds_status put_bool(gds_server *s, const UA_NodeId *node, const gds_role_bool *b) {
    size_t i = find_bool(s, node);
    if(i == s->nRoleBools) {
        if(s->nRoleBools == MAX_ROLE_BOOLEANS)
            return GDS_ETOOBIG;
        if(s->nRoleBools == s->capRoleBools) {
            size_t cap = s->capRoleBools ? s->capRoleBools * 2 : 8;
            gds_role_bool *g = realloc(s->roleBools, cap * sizeof(*g));
            if(!g)
                return GDS_ENOMEM;
            s->roleBools = g;
            s->capRoleBools = cap;
        }
        memset(&s->roleBools[i], 0, sizeof(s->roleBools[i]));
        if(UA_NodeId_copy(node, &s->roleBools[i].node) != UA_STATUSCODE_GOOD)
            return GDS_ENOMEM;
        s->nRoleBools++;
    }
    s->roleBools[i].roleBits = b->roleBits;
    s->roleBools[i].anonymous = b->anonymous;
    s->roleBools[i].authenticated = b->authenticated;
    return GDS_OK;
}

gds_status gds_server_set_role_boolean(gds_server *s, const UA_NodeId *nodeId,
                                       const UA_NodeId *roles, size_t n) {
    if(!s || !nodeId || UA_NodeId_isNull(nodeId) || n == 0 || !roles ||
       n > GDS_MAX_CALLER_ROLES)
        return GDS_EINVAL;
    if(nodeId->namespaceIndex == 0 || nodeId->namespaceIndex == s->ns)
        return GDS_EDENIED;
    UA_NodeClass nc = UA_NODECLASS_UNSPECIFIED;
    if(UA_Server_readNodeClass(s->ua, *nodeId, &nc) != UA_STATUSCODE_GOOD)
        return GDS_ENOTFOUND;
    if(!is_boolean_variable(s, nodeId))
        return GDS_EINVAL;
    gds_role_bool b;
    memset(&b, 0, sizeof(b));
    gds_status st = gds_role_bits(s, roles, n, &b.roleBits, &b.anonymous, &b.authenticated);
    if(st != GDS_OK)
        return st;
    pthread_mutex_lock(&s->bindLock);
    st = put_bool(s, nodeId, &b);
    pthread_mutex_unlock(&s->bindLock);
    if(st != GDS_OK)
        return st;
    /* no write callback: writes are refused (Bad_NotWritable) */
    UA_CallbackValueSource src = {read_bool, NULL};
    UA_StatusCode r = UA_Server_setVariableNode_callbackValueSource(s->ua, *nodeId, src);
    if(r != UA_STATUSCODE_GOOD) {
        pthread_mutex_lock(&s->bindLock);
        size_t i = find_bool(s, nodeId);
        if(i < s->nRoleBools)
            drop_bool(s, i);
        pthread_mutex_unlock(&s->bindLock);
        return gds_ua_status(r);
    }
    return GDS_OK;
}

gds_status gds_server_remove_node(gds_server *s, const UA_NodeId *nodeId) {
    if(!s || !nodeId || UA_NodeId_isNull(nodeId))
        return GDS_EINVAL;
    if(nodeId->namespaceIndex == 0 || nodeId->namespaceIndex == s->ns)
        return GDS_EDENIED;
    UA_StatusCode r = UA_Server_deleteNode(s->ua, *nodeId, true);
    if(r != UA_STATUSCODE_GOOD)
        return r == UA_STATUSCODE_BADNODEIDUNKNOWN ? GDS_ENOTFOUND : gds_ua_status(r);
    gds_embed_prune(s);
    gds_nodes_prune(s);
    return GDS_OK;
}
