/* OpenGDS T0 spec tests: access to the GDS (OPC 10000-12 §6.2, §7.2, and the
 * security rules of OPC 10000-2 / 10000-4 §5.4 / 10000-7 profiles).
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/nodeids_gds.h>
#include <open62541/plugin/log_stdout.h>

#include <string.h>

#include "common/limits.h"
#include "gds_target.h"
#include "spec_tests.h"
#include "common/banned.h"

#define POLICY_PREFIX "http://opcfoundation.org/UA/SecurityPolicy#"

static bool policy_is(const UA_String *uri, const char *name) {
    size_t pl = strlen(POLICY_PREFIX), nl = strlen(name);
    return uri->length == pl + nl && memcmp(uri->data, POLICY_PREFIX, pl) == 0 &&
           memcmp(uri->data + pl, name, nl) == 0;
}

/* A client limited to SecurityPolicy None (no certificate) */
static UA_Client *none_client(void) {
    UA_ClientConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.logging = UA_Log_Stdout_new(uac_log_level());
    if(!cfg.logging || UA_ClientConfig_setDefault(&cfg) != UA_STATUSCODE_GOOD) {
        UA_ClientConfig_clear(&cfg);
        return NULL;
    }
    cfg.securityMode = UA_MESSAGESECURITYMODE_NONE;
    return UA_Client_newWithConfig(&cfg);
}

/* GetEndpoints: what the GDS offers */
static void t_endpoints(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    /* open62541 finishes GetEndpoints only if some endpoint matches the
     * client configuration, so ask with the Auditor's secure client */
    UA_Client *c = gt_new_client(t);
    if(!c) {
        ga_not_tested(ctx, "could not create a client");
        return;
    }
    size_t n = 0;
    UA_EndpointDescription *eps = NULL;
    UA_StatusCode r = UA_Client_getEndpoints(c, t->url, &n, &eps);
    if(r != UA_STATUSCODE_GOOD || n == 0) {
        ga_not_tested(ctx, "GetEndpoints -> %s, %zu endpoint(s)", UA_StatusCode_name(r), n);
        UA_Client_delete(c);
        return;
    }
    size_t enc = 0, signOnly = 0, deprecated = 0, none = 0;
    for(size_t i = 0; i < n; i++) {
        const UA_EndpointDescription *e = &eps[i];
        if(e->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
            enc++;
        else if(e->securityMode == UA_MESSAGESECURITYMODE_SIGN)
            signOnly++;
        else
            none++;
        if(policy_is(&e->securityPolicyUri, "Basic128Rsa15") ||
           policy_is(&e->securityPolicyUri, "Basic256"))
            deprecated++;
    }
    ga_note(ctx, "%zu endpoint(s): %zu SignAndEncrypt, %zu Sign, %zu None", n, enc, signOnly, none);
    if(enc == 0)
        ga_fail(ctx, "no SignAndEncrypt endpoint: GDS methods need an encrypted channel");
    else if(deprecated > 0)
        ga_warn(ctx, "%zu endpoint(s) with deprecated policies Basic128Rsa15/Basic256", deprecated);
    else if(signOnly > 0)
        ga_warn(ctx, "%zu Sign-only endpoint(s): message bodies, such as issued private keys, are not encrypted",
                signOnly);
    else
        ga_pass(ctx, "SignAndEncrypt offered, no Sign-only or deprecated endpoint");
    UA_Array_delete(eps, n, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    UA_Client_delete(c);
}

/* A session without security must not reach the Directory methods */
static void t_none_session(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_Client *c = none_client();
    if(!c) {
        ga_not_tested(ctx, "could not create a client");
        return;
    }
    UA_StatusCode r = UA_Client_connect(c, t->url);
    if(r != UA_STATUSCODE_GOOD) {
        if(r == UA_STATUSCODE_BADIDENTITYTOKENREJECTED)
            ga_pass(ctx, "no endpoint offers a session over SecurityPolicy None");
        else
            ga_pass(ctx, "session over SecurityPolicy None refused (%s)", UA_StatusCode_name(r));
        UA_Client_delete(c);
        return;
    }
    UA_UInt16 ns = 0;
    r = UA_Client_getNamespaceIndex(c, UA_STRING("http://opcfoundation.org/UA/GDS/"), &ns);
    if(r != UA_STATUSCODE_GOOD) {
        ga_warn(ctx, "None session allowed; namespace read -> %s", UA_StatusCode_name(r));
    } else {
        UA_String u = UA_STRING("urn:opengds:auditor:none-probe");
        UA_Variant in;
        UA_Variant_setScalar(&in, &u, &UA_TYPES[UA_TYPES_STRING]);
        size_t outN = 0;
        UA_Variant *out = NULL;
        r = UA_Client_call(c, UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY),
                           UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_FINDAPPLICATIONS), 1, &in,
                           &outN, &out);
        gt_free_out(out, outN);
        if(r == UA_STATUSCODE_GOOD)
            ga_fail(ctx, "FindApplications answered over an unencrypted session");
        else
            ga_pass(ctx, "None session allowed for browsing, FindApplications refused (%s)",
                    UA_StatusCode_name(r));
    }
    UA_Client_disconnect(c);
    UA_Client_delete(c);
}

/* Registering needs a privileged user (§6.2: DiscoveryAdmin / SecurityAdmin) */
static void t_anonymous_register(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_Client *c = gt_new_client(t);
    if(!c) {
        ga_not_tested(ctx, "could not create a client");
        return;
    }
    UA_StatusCode r = UA_Client_connect(c, t->url);
    if(r != UA_STATUSCODE_GOOD) {
        ga_pass(ctx, "anonymous session refused (%s)", UA_StatusCode_name(r));
        UA_Client_delete(c);
        return;
    }
    ga_note(ctx, "anonymous SignAndEncrypt session accepted");
    UA_UInt16 ns = 0;
    r = UA_Client_getNamespaceIndex(c, UA_STRING("http://opcfoundation.org/UA/GDS/"), &ns);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "no GDS namespace: %s", UA_StatusCode_name(r));
    } else {
        gt_bind_ns(ns);
        char uri[GDS_MAX_APPLICATION_URI + 1];
        gt_unique_uri(t, uri, sizeof(uri));
        UA_ApplicationRecordDataType rec;
        UA_LocalizedText name;
        UA_String url;
        gt_record(&rec, uri, UA_APPLICATIONTYPE_CLIENT, &name, &url);
        UA_Variant in;
        UA_Variant_setScalar(&in, &rec, gt_record_type());
        size_t outN = 0;
        UA_Variant *out = NULL;
        r = UA_Client_call(c, UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY),
                           UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_REGISTERAPPLICATION), 1, &in,
                           &outN, &out);
        gt_free_out(out, outN);
        if(r == UA_STATUSCODE_GOOD)
            ga_fail(ctx, "an anonymous session registered an application");
        else if(r == UA_STATUSCODE_BADUSERACCESSDENIED)
            ga_pass(ctx, "BadUserAccessDenied");
        else
            ga_warn(ctx, "refused with %s; expected BadUserAccessDenied", UA_StatusCode_name(r));
    }
    UA_Client_disconnect(c);
    UA_Client_delete(c);
}

const ga_test spec_access_tests[] = {
    {"gds.sec.endpoints", "4 §5.4.4, 7 (security profiles)", "Endpoints offer SignAndEncrypt and no weak modes",
     false, false, t_endpoints},
    {"gds.sec.none_session", "12 §7.2", "Directory methods are not reachable without security",
     false, false, t_none_session},
    {"gds.sec.anonymous_register", "12 §6.2, §6.5.5", "An anonymous user cannot register applications",
     true, false, t_anonymous_register},
};
const size_t spec_access_count = GDS_ARRAY_SIZE(spec_access_tests);
