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

static UA_StatusCode configure(UA_ServerConfig *c, const gds_server_config *cfg,
                               const gds_buf *caCert, gds_server *s) {
    UA_StatusCode r = UA_ServerConfig_setBasics_withPort(c, cfg->port);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    gds_embed_configure(c, s);
    /* Accept-all at channel and session level; see the file comment. */
    if(c->secureChannelPKI.clear)
        c->secureChannelPKI.clear(&c->secureChannelPKI);
    UA_CertificateGroup_AcceptAll(&c->secureChannelPKI);
    if(c->sessionPKI.clear)
        c->sessionPKI.clear(&c->sessionPKI);
    UA_CertificateGroup_AcceptAll(&c->sessionPKI);

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
    if(gds_access_install(c, cfg->users, caCert) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    r = UA_ServerConfig_addSecurityPolicyNone(c, &cert);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    c->securityPolicyNoneDiscoveryOnly = true;
    c->allowNonePolicyPassword = false;
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
    return r;
}

/* ---- lifecycle ---- */

static bool config_ok(const gds_server_config *cfg) {
    return cfg && cfg->applicationUri && cfg->productUri && cfg->applicationName &&
           cfg->ownCert.len && cfg->ownKey.len && cfg->store && cfg->ca && cfg->users &&
           cfg->approval >= GDS_APPROVE_ALL && cfg->approval <= GDS_APPROVE_MANUAL;
}

static gds_status install(gds_server *s) {
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
        r = gds_trustlist_install(s);
    if(r == UA_STATUSCODE_GOOD)
        r = install_role_nodes(s);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_approvals_install(s);
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
    pthread_cond_init(&s->plugCond, NULL);
    s->store = cfg->store;
    s->ca = cfg->ca;
    s->approval = cfg->approval;
    s->counterReset = UA_DateTime_now();
    s->role = GDS_NODE_STANDALONE;
    s->serviceLevel = 255;

    gds_status st = gds_ca_get_ca_cert(s->ca, &s->caCert);
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
    st = install(s);
    if(st != GDS_OK) {
        gds_server_delete(s);
        return st;
    }
    *out = s;
    return GDS_OK;
}

gds_status gds_server_run(gds_server *s, volatile UA_Boolean *running) {
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
    if(s->ua)
        UA_Server_delete(s->ua); /* closes every session, cancels plugin calls */
    gds_embed_free(s);
    gds_access_uninstall();
    gds_buf_free(&s->caCert);
    pthread_cond_destroy(&s->plugCond);
    pthread_mutex_destroy(&s->plugLock);
    pthread_cond_destroy(&s->workCond);
    pthread_mutex_destroy(&s->roleLock);
    pthread_mutex_destroy(&s->workLock);
    pthread_mutex_destroy(&s->storeLock);
    free(s);
}
