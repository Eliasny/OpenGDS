/* OpenGDS - the caller view for plugin callbacks (UASM ask A6, issue #17).
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>

#include <stdlib.h>
#include <string.h>

#include "gds_internal.h"
#include "common/banned.h"

/* ---- views ---- */

bool gds_caller_has_role(const gds_caller *c, const UA_NodeId *role) {
    if(!c || !role)
        return false;
    for(size_t i = 0; i < c->rolesSize; i++)
        if(UA_NodeId_equal(&c->roles[i], role))
            return true;
    return false;
}

bool gds_caller_has_ns0_role(const gds_caller *c, UA_UInt32 ns0RoleId) {
    UA_NodeId r = UA_NODEID_NUMERIC(0, ns0RoleId);
    return gds_caller_has_role(c, &r);
}

bool gds_caller_has_privilege(const gds_caller *c, const char *privilege) {
    if(!c || !privilege)
        return false;
    for(size_t i = 0; i < c->privilegesSize; i++)
        if(strcmp(c->privileges[i], privilege) == 0)
            return true;
    return false;
}

static bool privilege_name_ok(const char *p, size_t *len) {
    size_t n = 0;
    while(n <= GDS_MAX_PRIVILEGE_NAME && p[n]) {
        if(p[n] < 0x21 || p[n] > 0x7e)
            return false;
        n++;
    }
    *len = n;
    return n > 0 && n <= GDS_MAX_PRIVILEGE_NAME;
}

gds_status gds_privilege_set_add(gds_privilege_set *set, const char *privilege) {
    size_t len = 0;
    if(!set || !privilege || !privilege_name_ok(privilege, &len))
        return GDS_EINVAL;
    for(size_t i = 0; i < set->n; i++)
        if(strcmp(set->names[i], privilege) == 0)
            return GDS_OK;
    if(set->n == GDS_MAX_PRIVILEGES)
        return GDS_ETOOBIG;
    char *copy = malloc(len + 1);
    if(!copy)
        return GDS_ENOMEM;
    memcpy(copy, privilege, len + 1);
    set->names[set->n++] = copy;
    return GDS_OK;
}

/* A NUL-terminated copy of a UA_String, NULL if empty or with a NUL. */
static gds_status cstr(const UA_String *in, char **out) {
    *out = NULL;
    if(!in || in->length == 0)
        return GDS_OK;
    if(in->length > GDS_MAX_STRING || memchr(in->data, 0, in->length))
        return GDS_EINVAL;
    *out = malloc(in->length + 1);
    if(!*out)
        return GDS_ENOMEM;
    memcpy(*out, in->data, in->length);
    (*out)[in->length] = '\0';
    return GDS_OK;
}

/* Shallow: embedder Role NodeIds live as long as the server. */
static void add_role(gds_caller_buf *b, UA_NodeId id) {
    if(b->nRoles < GDS_MAX_CALLER_ROLES)
        b->roles[b->nRoles++] = id;
}

/* The registered ApplicationId for the channel's ApplicationUri. */
static gds_status find_app(gds_server *s, const UA_String *uri, UA_NodeId *out) {
    *out = UA_NODEID_NULL;
    UA_ApplicationRecordDataType *found = NULL;
    size_t n = 0;
    gds_lock(s);
    gds_status st = gds_store_app_find_uri(s->store, uri, 1, &found, &n);
    gds_unlock(s);
    if(st == GDS_OK && n == 1 && found[0].applicationId.identifierType == UA_NODEIDTYPE_GUID)
        *out = UA_NODEID_GUID(s->ns, found[0].applicationId.identifier.guid);
    if(found)
        UA_Array_delete(found, n, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    return st;
}

gds_status gds_caller_build(gds_server *s, const UA_NodeId *sessionId, const void *sessionContext,
                            gds_caller_buf *b) {
    memset(b, 0, sizeof(*b));
    const gds_session *ss = gds_session_get(sessionContext);
    if(!s || !ss)
        return GDS_EDENIED;
    gds_status st = GDS_OK;
    if(sessionId && UA_NodeId_copy(sessionId, &b->sessionId) != UA_STATUSCODE_GOOD)
        st = GDS_ENOMEM;
    /* OPC 10000-18 §4.3: Anonymous for every session, AuthenticatedUser
     * for every session with user credentials. */
    add_role(b, UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS));
    if(!ss->anonymous) {
        add_role(b, UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_AUTHENTICATEDUSER));
        memcpy(b->user, ss->user, sizeof(b->user));
        b->user[sizeof(b->user) - 1] = '\0';
    }
    for(size_t i = 0; i < gds_role_count(); i++) {
        UA_NodeId id;
        unsigned bit = 0;
        const char *name = NULL;
        gds_role_at(i, s->ns, &id, &bit, &name);
        if(ss->roles & bit)
            add_role(b, id);
    }

    if(st == GDS_OK)
        st = cstr(&ss->clientAppUri, &b->appUri);
    if(st == GDS_OK)
        st = cstr(&ss->securityPolicyUri, &b->policyUri);
    if(st == GDS_OK && b->appUri)
        st = find_app(s, &ss->clientAppUri, &b->applicationId);
    /* OPC 10000-12 §6.2 Table 2: the channel's certificate names the
     * application, which may administer its own registration. */
    if(st == GDS_OK && b->appUri)
        st = gds_privilege_set_add(&b->priv, GDS_PRIVILEGE_APPLICATION_SELF_ADMIN);

    gds_caller *c = &b->view;
    c->abi_major = GDS_PLUGIN_ABI_MAJOR;
    c->abi_minor = GDS_PLUGIN_ABI_MINOR;
    c->struct_size = sizeof(*c);
    c->sessionId = &b->sessionId;
    c->userName = ss->anonymous ? NULL : b->user;
    c->roles = b->roles;
    c->rolesSize = b->nRoles;
    c->applicationUri = b->appUri;
    c->applicationId = &b->applicationId;
    c->securityMode = ss->securityMode <= UA_MESSAGESECURITYMODE_SIGNANDENCRYPT
                          ? (gds_security_mode)ss->securityMode
                          : GDS_SECURITY_MODE_INVALID;
    c->securityPolicyUri = b->policyUri ? b->policyUri : "";

    /* Plugin privileges: providers see the view built so far. */
    for(size_t i = 0; i < s->nPrivProviders && st == GDS_OK; i++) {
        c->privileges = (const char *const *)b->priv.names;
        c->privilegesSize = b->priv.n;
        const gds_privilege_provider *p = &s->privProviders[i];
        st = p->grant(p->ctx, c, &b->priv);
        if(st != GDS_OK)
            st = GDS_EDENIED; /* fail closed */
    }
    c->privileges = (const char *const *)b->priv.names;
    c->privilegesSize = b->priv.n;
    if(st != GDS_OK)
        gds_caller_buf_clear(b);
    return st;
}

void gds_caller_buf_clear(gds_caller_buf *b) {
    if(!b)
        return;
    UA_NodeId_clear(&b->sessionId);
    UA_NodeId_clear(&b->applicationId);
    for(size_t i = 0; i < b->priv.n; i++)
        free(b->priv.names[i]);
    free(b->appUri);
    free(b->policyUri);
    memset(b, 0, sizeof(*b));
}

/* ---- registration ---- */

gds_status gds_server_add_privilege_provider(gds_server *s, const gds_privilege_provider *p) {
    if(!s || !p || p->abi_major != GDS_PLUGIN_ABI_MAJOR ||
       p->struct_size < offsetof(gds_privilege_provider, grant) + sizeof(p->grant) || !p->grant)
        return GDS_EINVAL;
    if(s->nPrivProviders == GDS_MAX_PRIVILEGE_PROVIDERS)
        return GDS_ETOOBIG;
    gds_privilege_provider *d = &s->privProviders[s->nPrivProviders++];
    memset(d, 0, sizeof(*d));
    d->abi_major = p->abi_major;
    d->abi_minor = p->abi_minor;
    d->struct_size = sizeof(*d);
    d->ctx = p->ctx;
    d->grant = p->grant;
    return GDS_OK;
}
