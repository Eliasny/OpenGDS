/* OpenGDS - the GDS server object: open62541 configuration, the method
 * wiring, the signing worker and the node role / ServiceLevel slot.
 *
 * Channel security (docs/architecture.md, "Transport"):
 *   - sessions only over SignAndEncrypt with Basic256Sha256,
 *     Aes128_Sha256_RsaOaep or Aes256_Sha256_RsaPss;
 *   - SecurityPolicy None for discovery only (FindServers, GetEndpoints);
 *   - any client certificate opens a channel, because applications come
 *     to the GDS for their first certificate. Rights come from the user
 *     token or from a certificate the GDS CA issued (gds_access.c).
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/server_config_default.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gds_internal.h"
#include "common/banned.h"

#define URL_MAX 600

UA_Server *gds_server_ua(gds_server *s) {
    return s ? s->ua : NULL;
}

/* ---- node role and ServiceLevel (issue #14) ---- */

static bool level_ok(gds_node_role role, UA_Byte level, UA_DateTime ert) {
    if(ert != 0 && level != GDS_SERVICE_LEVEL_MAINTENANCE)
        return false;
    switch(role) {
    case GDS_NODE_STANDALONE:
    case GDS_NODE_PRIMARY:
        return true;
    case GDS_NODE_STANDBY:
        return level < GDS_SERVICE_LEVEL_HEALTHY_MIN;
    default:
        return false;
    }
}

gds_status gds_server_set_role(gds_server *s, gds_node_role role, UA_Byte level,
                               UA_DateTime estimatedReturnTime) {
    if(!s || !level_ok(role, level, estimatedReturnTime))
        return GDS_EINVAL;
    pthread_mutex_lock(&s->roleLock);
    bool changed = s->role != role;
    s->role = role;
    s->serviceLevel = level;
    s->estimatedReturnTime = estimatedReturnTime;
    pthread_mutex_unlock(&s->roleLock);
    if(changed) /* a STANDBY shows no approvals; a new PRIMARY shows the store's */
        gds_approvals_role_changed(s);
    return GDS_OK;
}

gds_status gds_server_set_service_level(gds_server *s, UA_Byte level,
                                        UA_DateTime estimatedReturnTime) {
    if(!s)
        return GDS_EINVAL;
    pthread_mutex_lock(&s->roleLock);
    gds_status r = GDS_EINVAL;
    if(level_ok(s->role, level, estimatedReturnTime)) {
        s->serviceLevel = level;
        s->estimatedReturnTime = estimatedReturnTime;
        r = GDS_OK;
    }
    pthread_mutex_unlock(&s->roleLock);
    return r;
}

gds_node_role gds_server_role(gds_server *s) {
    pthread_mutex_lock(&s->roleLock);
    gds_node_role r = s->role;
    pthread_mutex_unlock(&s->roleLock);
    return r;
}

static UA_StatusCode read_role_value(UA_Server *server, const UA_NodeId *sessionId,
                                     void *sessionContext, const UA_NodeId *nodeId,
                                     void *nodeContext, UA_Boolean includeSourceTimeStamp,
                                     const UA_NumericRange *range, UA_DataValue *value) {
    (void)server, (void)sessionId, (void)sessionContext;
    gds_server *s = nodeContext;
    if(range) {
        value->hasStatus = true;
        value->status = UA_STATUSCODE_BADINDEXRANGEINVALID;
        return UA_STATUSCODE_GOOD;
    }
    pthread_mutex_lock(&s->roleLock);
    UA_Byte level = s->serviceLevel;
    UA_DateTime ert = s->estimatedReturnTime;
    pthread_mutex_unlock(&s->roleLock);
    UA_StatusCode r;
    if(nodeId->identifier.numeric == UA_NS0ID_SERVER_SERVICELEVEL)
        r = UA_Variant_setScalarCopy(&value->value, &level, &UA_TYPES[UA_TYPES_BYTE]);
    else
        r = UA_Variant_setScalarCopy(&value->value, &ert, &UA_TYPES[UA_TYPES_DATETIME]);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    value->hasValue = true;
    if(includeSourceTimeStamp) {
        value->sourceTimestamp = UA_DateTime_now();
        value->hasSourceTimestamp = true;
    }
    return UA_STATUSCODE_GOOD;
}

/* open62541 reports a constant 255 and removes the optional
 * EstimatedReturnTime; both now read the role slot. */
static UA_StatusCode install_role_nodes(gds_server *s) {
    UA_CallbackValueSource src = {read_role_value, NULL};
    UA_NodeId level = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVICELEVEL);
    UA_StatusCode r = UA_Server_setNodeContext(s->ua, level, s);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_setVariableNode_callbackValueSource(s->ua, level, src);
    if(r != UA_STATUSCODE_GOOD)
        return r;

    UA_NodeId ert = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_ESTIMATEDRETURNTIME);
    UA_VariableAttributes a = UA_VariableAttributes_default;
    a.displayName = UA_LOCALIZEDTEXT("", "EstimatedReturnTime");
    a.dataType = UA_TYPES[UA_TYPES_DATETIME].typeId;
    a.valueRank = UA_VALUERANK_SCALAR;
    a.accessLevel = UA_ACCESSLEVELMASK_READ;
    UA_DateTime zero = 0;
    UA_Variant_setScalar(&a.value, &zero, &UA_TYPES[UA_TYPES_DATETIME]);
    r = UA_Server_addVariableNode(s->ua, ert, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER),
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY),
                                  UA_QUALIFIEDNAME(0, "EstimatedReturnTime"),
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE), a, NULL, NULL);
    if(r == UA_STATUSCODE_BADNODEIDEXISTS)
        r = UA_STATUSCODE_GOOD; /* a future open62541 keeps the node */
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_setNodeContext(s->ua, ert, s);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_setVariableNode_callbackValueSource(s->ua, ert, src);
    return r;
}

/* ---- configuration ---- */

static UA_StatusCode set_string(UA_String *dst, const char *v) {
    UA_String_clear(dst);
    *dst = UA_String_fromChars(v);
    return dst->length || !*v ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADOUTOFMEMORY;
}

static UA_StatusCode set_description(UA_ServerConfig *c, const gds_server_config *cfg) {
    UA_ApplicationDescription *d = &c->applicationDescription;
    d->applicationType = UA_APPLICATIONTYPE_DISCOVERYSERVER;
    UA_StatusCode r = set_string(&d->applicationUri, cfg->applicationUri);
    r |= set_string(&d->productUri, cfg->productUri);
    r |= set_string(&c->buildInfo.productUri, cfg->productUri);
    UA_LocalizedText_clear(&d->applicationName);
    d->applicationName = UA_LOCALIZEDTEXT_ALLOC("", cfg->applicationName);
    if(!d->applicationName.text.length)
        r |= UA_STATUSCODE_BADOUTOFMEMORY;
    return r;
}

static UA_StatusCode set_listen_url(UA_ServerConfig *c, const gds_server_config *cfg) {
    const char *host = cfg->loopbackOnly ? "127.0.0.1" : cfg->hostname;
    if(!host)
        return UA_STATUSCODE_GOOD; /* opc.tcp://:<port>, all interfaces */
    char url[URL_MAX];
    int n = snprintf(url, sizeof(url), "opc.tcp://%s:%u", host, (unsigned)cfg->port);
    if(n < 0 || (size_t)n >= sizeof(url))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_Array_delete(c->serverUrls, c->serverUrlsSize, &UA_TYPES[UA_TYPES_STRING]);
    c->serverUrls = UA_String_new();
    c->serverUrlsSize = 0;
    if(!c->serverUrls)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    c->serverUrlsSize = 1;
    return set_string(&c->serverUrls[0], url);
}

typedef UA_StatusCode (*add_policy_fn)(UA_ServerConfig *, const UA_ByteString *,
                                       const UA_ByteString *);

static UA_StatusCode find_servers_peers(UA_Server *server, void *context,
                                        UA_ApplicationDescription **out, size_t *n);

/* The mDNS announce (disc_mdns.h); not with loopbackOnly: nothing on the
 * subnet could reach 127.0.0.1. */
static UA_StatusCode configure_mdns(UA_ServerConfig *c, const gds_server_config *cfg) {
    gds_status st = cfg->loopbackOnly
                        ? GDS_EINVAL
                        : gds_disc_mdns_configure(c, &cfg->mdns, cfg->applicationName);
    if(st == GDS_OK)
        return UA_STATUSCODE_GOOD;
    fprintf(stderr, "opengds: mDNS announce: %s%s\n", gds_status_name(st),
            st == GDS_EUNSUPPORTED ? " (built without OPENGDS_WITH_MDNS)"
            : cfg->loopbackOnly    ? " (not with loopback_only)"
                                   : "");
    return UA_STATUSCODE_BADCONFIGURATIONERROR;
}

static UA_StatusCode configure(UA_ServerConfig *c, const gds_server_config *cfg,
                               const gds_buf *caCert, gds_server *s) {
    UA_StatusCode r = UA_ServerConfig_setBasics_withPort(c, cfg->port);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    gds_embed_configure(c, s);
    /* Accept-all at channel level (see the file comment); user
     * certificates only with a DefaultUserTokenGroup trust list. */
    if(c->secureChannelPKI.clear)
        c->secureChannelPKI.clear(&c->secureChannelPKI);
    UA_CertificateGroup_AcceptAll(&c->secureChannelPKI);
    if(c->sessionPKI.clear)
        c->sessionPKI.clear(&c->sessionPKI);
    if(cfg->userPkiDir) {
        /* user certificates: the DefaultUserTokenGroup trust list */
        UA_NodeId group =
            UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP);
        r = UA_CertificateGroup_Filestore(&c->sessionPKI, &group,
                                          UA_STRING((char *)(uintptr_t)cfg->userPkiDir),
                                          c->logging, NULL);
        if(r != UA_STATUSCODE_GOOD)
            return r;
    } else {
        UA_CertificateGroup_AcceptAll(&c->sessionPKI);
    }

    UA_ByteString cert = {cfg->ownCert.len, cfg->ownCert.data};
    UA_ByteString key = {cfg->ownKey.len, cfg->ownKey.data};
    static const add_policy_fn secure[] = {
        UA_ServerConfig_addSecurityPolicyBasic256Sha256,
        UA_ServerConfig_addSecurityPolicyAes128Sha256RsaOaep,
        UA_ServerConfig_addSecurityPolicyAes256Sha256RsaPss,
    };
    for(size_t i = 0; i < GDS_ARRAY_SIZE(secure) && r == UA_STATUSCODE_GOOD; i++)
        r = secure[i](c, &cert, &key);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    /* Before None is added: the user token policies are made for the
     * secure policies only, so no password ever travels over None. */
    if(gds_access_install(c, cfg->users, caCert, cfg->userPkiDir != NULL) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    r = UA_ServerConfig_addSecurityPolicyNone(c, &cert);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    c->securityPolicyNoneDiscoveryOnly = true;
    c->allowNonePolicyPassword = false;
    c->findServersPeers = find_servers_peers;
    c->findServersPeersContext = s;
    for(size_t i = 0; i < c->securityPoliciesSize && r == UA_STATUSCODE_GOOD; i++) {
        const UA_SecurityPolicy *p = &c->securityPolicies[i];
        bool none = UA_String_equal(&p->policyUri, &UA_SECURITY_POLICY_NONE_URI);
        r = UA_ServerConfig_addEndpoint(c, p->policyUri,
                                        none ? UA_MESSAGESECURITYMODE_NONE
                                             : UA_MESSAGESECURITYMODE_SIGNANDENCRYPT);
    }
    if(r == UA_STATUSCODE_GOOD)
        r = set_description(c, cfg);
    if(r == UA_STATUSCODE_GOOD)
        r = set_listen_url(c, cfg);
    if(r == UA_STATUSCODE_GOOD && cfg->mdns.enabled)
        r = configure_mdns(c, cfg);
    return r;
}

/* ---- FindServers peers (UASM ask A15) ---- */

/* open62541 calls this under its service mutex (patch 0005). */
static UA_StatusCode find_servers_peers(UA_Server *server, void *context,
                                        UA_ApplicationDescription **out, size_t *n) {
    (void)server;
    gds_server *s = context;
    pthread_mutex_lock(&s->peerLock);
    UA_StatusCode r = UA_Array_copy(s->peers, s->nPeers, (void **)out,
                                    &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
    *n = r == UA_STATUSCODE_GOOD ? s->nPeers : 0;
    pthread_mutex_unlock(&s->peerLock);
    return r;
}

static bool peer_ok(const UA_ApplicationDescription *p, const UA_String *self) {
    if(p->applicationUri.length == 0 || p->applicationUri.length > GDS_MAX_APPLICATION_URI ||
       UA_String_equal(&p->applicationUri, self) || p->discoveryUrlsSize == 0 ||
       p->discoveryUrlsSize > GDS_MAX_ARRAY_FIELD)
        return false;
    if(p->applicationType != UA_APPLICATIONTYPE_SERVER &&
       p->applicationType != UA_APPLICATIONTYPE_CLIENTANDSERVER &&
       p->applicationType != UA_APPLICATIONTYPE_DISCOVERYSERVER)
        return false;
    for(size_t i = 0; i < p->discoveryUrlsSize; i++)
        if(p->discoveryUrls[i].length == 0)
            return false;
    return true;
}

gds_status gds_server_set_peer_servers(gds_server *s, const UA_ApplicationDescription *peers,
                                       size_t n) {
    if(!s || (n && !peers))
        return GDS_EINVAL;
    if(n > GDS_MAX_PEER_SERVERS)
        return GDS_ETOOBIG;
    const UA_String *self = &UA_Server_getConfig(s->ua)->applicationDescription.applicationUri;
    for(size_t i = 0; i < n; i++) {
        if(!peer_ok(&peers[i], self))
            return GDS_EINVAL;
        for(size_t j = 0; j < i; j++)
            if(UA_String_equal(&peers[i].applicationUri, &peers[j].applicationUri))
                return GDS_EINVAL;
    }
    UA_ApplicationDescription *copy = NULL;
    if(n && UA_Array_copy(peers, n, (void **)&copy, &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]) !=
                UA_STATUSCODE_GOOD)
        return GDS_ENOMEM;
    pthread_mutex_lock(&s->peerLock);
    UA_ApplicationDescription *old = s->peers;
    size_t oldN = s->nPeers;
    s->peers = copy;
    s->nPeers = n;
    pthread_mutex_unlock(&s->peerLock);
    UA_Array_delete(old, oldN, &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
    return GDS_OK;
}

/* ---- lifecycle ---- */

static bool config_ok(const gds_server_config *cfg) {
    return cfg && cfg->applicationUri && cfg->productUri && cfg->applicationName &&
           cfg->ownCert.len && cfg->ownKey.len && cfg->store && cfg->ca && cfg->users &&
           cfg->approval >= GDS_APPROVE_ALL && cfg->approval <= GDS_APPROVE_MANUAL;
}

/* Server.Auditing (OPC 10000-5 §6.3.1, "currently generating audit
 * events"): TRUE with a store that keeps the audit log, which every audit
 * event goes through first. open62541's own source answers FALSE. */
static UA_StatusCode read_auditing(UA_Server *server, const UA_NodeId *sessionId,
                                   void *sessionContext, const UA_NodeId *nodeId,
                                   void *nodeContext, UA_Boolean includeSourceTimeStamp,
                                   const UA_NumericRange *range, UA_DataValue *value) {
    (void)server, (void)sessionId, (void)sessionContext, (void)nodeId;
    const gds_server *s = nodeContext;
    if(range) {
        value->hasStatus = true;
        value->status = UA_STATUSCODE_BADINDEXRANGEINVALID;
        return UA_STATUSCODE_GOOD;
    }
    UA_Boolean on = s && gds_store_has_audit(s->store);
    UA_StatusCode r = UA_Variant_setScalarCopy(&value->value, &on, &UA_TYPES[UA_TYPES_BOOLEAN]);
    value->hasValue = r == UA_STATUSCODE_GOOD;
    if(includeSourceTimeStamp) {
        value->hasSourceTimestamp = true;
        value->sourceTimestamp = UA_DateTime_now();
    }
    return r;
}

static UA_StatusCode install_auditing(gds_server *s) {
    UA_NodeId n = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_AUDITING);
    UA_CallbackValueSource src = {read_auditing, NULL};
    UA_StatusCode r = UA_Server_setNodeContext(s->ua, n, s);
    return r == UA_STATUSCODE_GOOD ? UA_Server_setVariableNode_callbackValueSource(s->ua, n, src)
                                   : r;
}

static gds_status install(gds_server *s, const gds_authz_config *authz,
                          const gds_buf *ownCert) {
    size_t ns = 0;
    UA_String uri = UA_STRING(GDS_NS_URI);
    if(UA_Server_getNamespaceByName(s->ua, uri, &ns) != UA_STATUSCODE_GOOD || ns > UA_UINT16_MAX) {
        fprintf(stderr, "opengds: the GDS information model is not loaded\n");
        return GDS_ENOTFOUND;
    }
    s->ns = (UA_UInt16)ns;
    UA_StatusCode r = gds_directory_install(s);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_certmgr_install(s);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_revoke_install(s);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_trustlist_install(s);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_keycred_install(s);
    if(r == UA_STATUSCODE_GOOD)
        r = install_role_nodes(s);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_approvals_install(s);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_alarms_install(s);
    if(r == UA_STATUSCODE_GOOD)
        r = install_auditing(s);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_authz_install(s, authz, ownCert);
    if(r != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "opengds: installing the GDS methods failed: %s\n", UA_StatusCode_name(r));
        return GDS_ENOTFOUND;
    }
    return gds_worker_start(s);
}

gds_status gds_server_new(const gds_server_config *cfg, gds_server **out) {
    *out = NULL;
    if(!config_ok(cfg))
        return GDS_EINVAL;
    gds_server *s = calloc(1, sizeof(*s));
    if(!s)
        return GDS_ENOMEM;
    pthread_mutex_init(&s->storeLock, NULL);
    pthread_mutex_init(&s->workLock, NULL);
    pthread_mutex_init(&s->roleLock, NULL);
    pthread_cond_init(&s->workCond, NULL);
    pthread_mutex_init(&s->plugLock, NULL);
    pthread_mutex_init(&s->bindLock, NULL);
    pthread_mutex_init(&s->alarmLock, NULL);
    pthread_mutex_init(&s->visLock, NULL);
    pthread_mutex_init(&s->dialogLock, NULL);
    pthread_mutex_init(&s->holdLock, NULL);
    pthread_mutex_init(&s->peerLock, NULL);
    pthread_mutex_init(&s->kpLock, NULL);
    pthread_cond_init(&s->plugCond, NULL);
    s->store = cfg->store;
    s->ca = cfg->ca;
    s->approval = cfg->approval;
    s->counterReset = UA_DateTime_now();
    s->role = GDS_NODE_STANDALONE;
    s->serviceLevel = 255;

    gds_status st = gds_keycred_copy(s, cfg->keyCredServices, cfg->keyCredServicesSize);
    if(st != GDS_OK) {
        fprintf(stderr, "opengds: KeyCredentialServices: %s\n", gds_status_name(st));
        gds_server_delete(s);
        return st;
    }
    st = gds_ca_get_ca_cert(s->ca, &s->caCert);
    for(unsigned i = 0; st == GDS_OK && i < GDS_CA_ISSUERS; i++) {
        st = gds_ca_get_issuer_cert(s->ca, (gds_ca_issuer)i, &s->issuerCert[i]);
        if(st == GDS_ENOTFOUND && i != GDS_CA_ISSUER_RSA)
            st = GDS_OK; /* a CA slot without this issuer: its types are not offered */
    }
    if(st != GDS_OK) {
        fprintf(stderr, "opengds: reading the CA certificate failed: %s\n", gds_status_name(st));
        gds_server_delete(s);
        return st;
    }
    UA_ServerConfig c;
    memset(&c, 0, sizeof(c));
    UA_StatusCode r = configure(&c, cfg, &s->caCert, s);
    if(r == UA_STATUSCODE_GOOD) {
        s->ua = UA_Server_newWithConfig(&c); /* takes c, also on failure */
        if(!s->ua)
            r = UA_STATUSCODE_BADINTERNALERROR;
    } else {
        UA_ServerConfig_clear(&c);
    }
    if(r != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "opengds: server configuration failed: %s\n", UA_StatusCode_name(r));
        gds_server_delete(s);
        return GDS_EINVAL;
    }
    st = install(s, cfg->authz, &cfg->ownCert);
    if(st != GDS_OK) {
        gds_server_delete(s);
        return st;
    }
    *out = s;
    return GDS_OK;
}

/* ---- embedder Roles (A10, issue #63) ---- */

/* OPC 10000-18 §4.2: the Server's Roles are the components of
 * ServerCapabilities/RoleSet. A Role node the embedder already loaded (a
 * NodeSet such as Opc.Ua.Onboarding) is linked there; otherwise a RoleType
 * object is created under it. */
static UA_StatusCode role_node(gds_server *s, const char *name, const UA_NodeId *id) {
    const UA_NodeId roleSet = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET);
    const UA_NodeId hasComponent = UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT);
    UA_NodeClass nc = UA_NODECLASS_UNSPECIFIED;
    UA_StatusCode r = UA_Server_readNodeClass(s->ua, *id, &nc);
    if(r == UA_STATUSCODE_GOOD) {
        if(nc != UA_NODECLASS_OBJECT)
            return UA_STATUSCODE_BADNODECLASSINVALID;
        UA_ExpandedNodeId target = UA_EXPANDEDNODEID_NULL;
        target.nodeId = *id;
        r = UA_Server_addReference(s->ua, roleSet, hasComponent, target, true);
        return r == UA_STATUSCODE_BADDUPLICATEREFERENCENOTALLOWED ? UA_STATUSCODE_GOOD : r;
    }
    if(r != UA_STATUSCODE_BADNODEIDUNKNOWN)
        return r;
    UA_ObjectAttributes oa = UA_ObjectAttributes_default;
    oa.displayName = UA_LOCALIZEDTEXT("", (char *)(uintptr_t)name);
    return UA_Server_addObjectNode(s->ua, *id, roleSet, hasComponent,
                                   UA_QUALIFIEDNAME(id->namespaceIndex, (char *)(uintptr_t)name),
                                   UA_NODEID_NUMERIC(0, UA_NS0ID_ROLETYPE), oa, NULL, NULL);
}

gds_status gds_server_add_role(gds_server *s, const char *name, const UA_NodeId *roleId) {
    if(!s || !name || !roleId)
        return GDS_EINVAL;
    if(__atomic_load_n(&s->started, __ATOMIC_ACQUIRE))
        return GDS_ESTATE;
    if(roleId->namespaceIndex == s->ns)
        return GDS_EDENIED; /* the GDS namespace has its own Roles */
    gds_status st = gds_access_add_role(name, roleId, s->ns);
    if(st != GDS_OK)
        return st;
    UA_StatusCode r = role_node(s, name, roleId);
    if(r != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "opengds: Role %s: %s\n", name, UA_StatusCode_name(r));
        gds_access_drop_last_role();
        return r == UA_STATUSCODE_BADNODECLASSINVALID || r == UA_STATUSCODE_BADNODEIDINVALID
                   ? GDS_EINVAL
                   : GDS_EIO;
    }
    return GDS_OK;
}

gds_status gds_server_run(gds_server *s, volatile UA_Boolean *running) {
    __atomic_store_n(&s->started, true, __ATOMIC_RELEASE);
    gds_status st = gds_access_check_users();
    if(st != GDS_OK)
        return st;
    UA_StatusCode r = UA_Server_run(s->ua, running);
    if(r != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "opengds: server stopped: %s\n", UA_StatusCode_name(r));
        return GDS_EIO;
    }
    return GDS_OK;
}

void gds_server_delete(gds_server *s) {
    if(!s)
        return;
    gds_worker_stop(s);
    gds_embed_stop(s);
    __atomic_store_n(&s->stopping, true, __ATOMIC_RELEASE);
    if(s->ua)
        UA_Server_delete(s->ua); /* closes every session, cancels plugin calls */
    gds_embed_free(s);
    gds_alarms_free(s);
    gds_ptl_free(s);
    gds_authz_free(s);
    gds_access_uninstall();
    gds_buf_free(&s->caCert);
    for(size_t i = 0; i < GDS_CA_ISSUERS; i++)
        gds_buf_free(&s->issuerCert[i]);
    pthread_cond_destroy(&s->plugCond);
    pthread_mutex_destroy(&s->plugLock);
    pthread_mutex_destroy(&s->bindLock);
    pthread_mutex_destroy(&s->alarmLock);
    gds_dialogs_free(s);
    pthread_mutex_destroy(&s->dialogLock);
    gds_cond_vis_free(s);
    pthread_mutex_destroy(&s->visLock);
    gds_holds_free(s);
    pthread_mutex_destroy(&s->holdLock);
    UA_Array_delete(s->peers, s->nPeers, &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
    pthread_mutex_destroy(&s->peerLock);
    gds_kp_free(s);
    pthread_mutex_destroy(&s->kpLock);
    gds_keycred_free(s);
    pthread_cond_destroy(&s->workCond);
    pthread_mutex_destroy(&s->roleLock);
    pthread_mutex_destroy(&s->workLock);
    pthread_mutex_destroy(&s->storeLock);
    free(s);
}
