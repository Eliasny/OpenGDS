/* OpenGDS spec tests: Role and user management of the GDS (OPC 10000-18
 * §4.3 - §4.5 RoleSet, RoleType methods and RoleMappingRuleChangedAudit-
 * EventType; §5.2 - §5.3 UserManagement), which OPC 10000-12 §6.2 and
 * Annex G.2 use to configure the GDS Roles.
 *
 * The admin user of the target must hold SecurityAdmin. Each test leaves
 * the target as it found it: rules and users it adds carry the run tag
 * and are removed again. The "outsider" is a session with the Auditor's
 * application certificate and no user.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>
#include <open62541/nodeids_gds.h>

#include <stdio.h>
#include <string.h>

#include "common/limits.h"
#include "gds_target.h"
#include "spec_tests.h"
#include "common/banned.h"

#define GDS_NS_URI "http://opcfoundation.org/UA/GDS/"
#define URI_LEN (GDS_MAX_APPLICATION_URI + 1)
#define EV_WAIT 3000

/* ---- helpers ---- */

static bool absent(UA_StatusCode r) {
    return r == UA_STATUSCODE_BADMETHODINVALID || r == UA_STATUSCODE_BADNOTIMPLEMENTED ||
           r == UA_STATUSCODE_BADNODEIDUNKNOWN || r == UA_STATUSCODE_BADNOTFOUND ||
           r == UA_STATUSCODE_BADNOMATCH;
}

/* Call parent.<name> (a namespace 0 BrowseName) on client c. */
static UA_StatusCode call_named(UA_Client *c, UA_NodeId parent, const char *name, size_t inN,
                                const UA_Variant *in) {
    UA_NodeId m;
    UA_StatusCode r = gt_find(c, parent, 0, name, &m);
    if(r != UA_STATUSCODE_GOOD)
        return r == UA_STATUSCODE_BADNOMATCH ? UA_STATUSCODE_BADMETHODINVALID : r;
    size_t outN = 0;
    UA_Variant *out = NULL;
    r = UA_Client_call(c, parent, m, inN, in, &outN, &out);
    gt_free_out(out, outN);
    UA_NodeId_clear(&m);
    return r;
}

/* Read parent.<name> into *v */
static UA_StatusCode read_named(UA_Client *c, UA_NodeId parent, const char *name, UA_Variant *v) {
    UA_NodeId p;
    UA_Variant_init(v);
    UA_StatusCode r = gt_find(c, parent, 0, name, &p);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Client_readValueAttribute(c, p, v);
    UA_NodeId_clear(&p);
    return r;
}

static UA_NodeId role(UA_UInt32 id) {
    return UA_NODEID_NUMERIC(0, id);
}

static UA_NodeId user_mgmt(void) {
    return UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT);
}

static UA_StatusCode rule_call(UA_Client *c, UA_NodeId r, const char *method,
                               UA_IdentityCriteriaType type, const char *criteria) {
    UA_IdentityMappingRuleType rule;
    UA_IdentityMappingRuleType_init(&rule);
    rule.criteriaType = type;
    rule.criteria = UA_STRING((char *)(uintptr_t)criteria);
    UA_Variant in;
    UA_Variant_setScalar(&in, &rule, &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE]);
    return call_named(c, r, method, 1, &in);
}

static UA_StatusCode str_call(UA_Client *c, UA_NodeId obj, const char *method, const char *v) {
    UA_String s = UA_STRING((char *)(uintptr_t)v);
    UA_Variant in;
    UA_Variant_setScalar(&in, &s, &UA_TYPES[UA_TYPES_STRING]);
    return call_named(c, obj, method, 1, &in);
}

static UA_StatusCode add_user(UA_Client *c, const char *name, const char *pw) {
    UA_String n = UA_STRING((char *)(uintptr_t)name), p = UA_STRING((char *)(uintptr_t)pw),
              d = UA_STRING("OpenGDS Auditor test user");
    UA_UInt32 cfg = 0;
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], &n, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &p, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[2], &cfg, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[3], &d, &UA_TYPES[UA_TYPES_STRING]);
    return call_named(c, user_mgmt(), "AddUser", 4, in);
}

static UA_StatusCode disable_user(UA_Client *c, const char *name) {
    UA_String n = UA_STRING((char *)(uintptr_t)name), empty = UA_STRING_NULL;
    UA_Boolean no = false, yes = true;
    UA_UInt32 cfg = 0x2; /* Disabled, §5.2.3 */
    UA_Variant in[7];
    UA_Variant_setScalar(&in[0], &n, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &no, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Variant_setScalar(&in[2], &empty, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[3], &yes, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Variant_setScalar(&in[4], &cfg, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[5], &no, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Variant_setScalar(&in[6], &empty, &UA_TYPES[UA_TYPES_STRING]);
    return call_named(c, user_mgmt(), "ModifyUser", 7, in);
}

static UA_StatusCode change_password(UA_Client *c, const char *oldPw, const char *newPw) {
    UA_String o = UA_STRING((char *)(uintptr_t)oldPw), n = UA_STRING((char *)(uintptr_t)newPw);
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &o, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &n, &UA_TYPES[UA_TYPES_STRING]);
    return call_named(c, user_mgmt(), "ChangePassword", 2, in);
}

/* A run-unique user name and a password of 24 characters */
static void make_user(gds_target *t, const char *what, char *name, size_t nl, char *pw,
                      size_t pl) {
    (void)snprintf(name, nl, "auditor-%s-%s-%u", what, t->runTag, ++t->seq);
    (void)snprintf(pw, pl, "Pw-%s-Aa1!", t->runTag);
}

static UA_Client *user_session(gds_target *t, const char *name, const char *pw,
                               UA_StatusCode *r) {
    UA_Client *c = gt_new_client(t);
    if(!c) {
        *r = UA_STATUSCODE_BADOUTOFMEMORY;
        return NULL;
    }
    *r = UA_Client_connectUsername(c, t->url, name, pw);
    if(*r != UA_STATUSCODE_GOOD) {
        UA_Client_delete(c);
        return NULL;
    }
    return c;
}

static bool admin(ga_ctx *ctx, gds_target *t) {
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup: admin session -> %s", UA_StatusCode_name(r));
    return r == UA_STATUSCODE_GOOD;
}

/* Does the array of IdentityMappingRuleType in v hold (type, criteria)? */
static bool has_rule(const UA_Variant *v, UA_IdentityCriteriaType type, const char *criteria) {
    if(v->type != &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE])
        return false;
    const UA_IdentityMappingRuleType *r = v->data;
    UA_String c = UA_STRING((char *)(uintptr_t)criteria);
    for(size_t i = 0; i < v->arrayLength; i++)
        if(r[i].criteriaType == type && UA_String_equal(&r[i].criteria, &c))
            return true;
    return false;
}

static bool has_user(const UA_Variant *v, const char *name) {
    if(v->type != &UA_TYPES[UA_TYPES_USERMANAGEMENTDATATYPE])
        return false;
    const UA_UserManagementDataType *u = v->data;
    UA_String n = UA_STRING((char *)(uintptr_t)name);
    for(size_t i = 0; i < v->arrayLength; i++)
        if(UA_String_equal(&u[i].userName, &n))
            return true;
    return false;
}

/* Verdict for a call that must be refused with `want` */
static void refused(ga_ctx *ctx, UA_StatusCode r, UA_StatusCode want, const char *what) {
    if(r == want)
        ga_pass(ctx, "%s -> %s", what, UA_StatusCode_name(r));
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "%s succeeded; expected %s", what, UA_StatusCode_name(want));
    else
        ga_warn(ctx, "%s refused with %s; the spec names %s", what, UA_StatusCode_name(r),
                UA_StatusCode_name(want));
}

/* ---- RoleType (§4.4) ---- */

/* §4.4.1: Identities is Mandatory and readable by administrators only */
static void t_identities_read(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    UA_Variant v;
    UA_StatusCode r = read_named(t->client, role(UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN),
                                 "Identities", &v);
    bool typed = r == UA_STATUSCODE_GOOD &&
                 (v.type == &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE] ||
                  (v.type == NULL && v.arrayLength == 0)) &&
                 !UA_Variant_isScalar(&v);
    UA_Variant_clear(&v);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "SecurityAdmin.Identities cannot be read by the admin: %s",
                UA_StatusCode_name(r));
        return;
    }
    UA_Client *out = gt_anon_session(t, &r);
    UA_StatusCode ro = UA_STATUSCODE_BADUSERACCESSDENIED;
    if(out) {
        ro = read_named(out, role(UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN), "Identities", &v);
        UA_Variant_clear(&v);
        gt_drop(out);
    }
    if(!typed)
        ga_fail(ctx, "SecurityAdmin.Identities is not an IdentityMappingRuleType array");
    else if(ro == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "a session without a Role can read SecurityAdmin.Identities");
    else
        ga_pass(ctx, "Identities is an IdentityMappingRuleType array; the outsider gets %s",
                UA_StatusCode_name(ro));
}

/* §4.4.5, §4.4.6: add, see, re-add, remove, re-remove a UserName rule */
static void t_add_remove_identity(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    char name[96], pw[64];
    make_user(t, "rule", name, sizeof(name), pw, sizeof(pw));
    UA_NodeId obs = role(UA_NS0ID_WELLKNOWNROLE_OBSERVER);
    UA_StatusCode r = rule_call(t->client, obs, "AddIdentity", UA_IDENTITYCRITERIATYPE_USERNAME, name);
    if(absent(r)) {
        ga_not_supported(ctx, "Observer has no AddIdentity (%s)", UA_StatusCode_name(r));
        return;
    }
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "AddIdentity UserName -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_Variant v;
    UA_StatusCode rr = read_named(t->client, obs, "Identities", &v);
    bool listed = rr == UA_STATUSCODE_GOOD && has_rule(&v, UA_IDENTITYCRITERIATYPE_USERNAME, name);
    UA_Variant_clear(&v);
    UA_StatusCode again = rule_call(t->client, obs, "AddIdentity", UA_IDENTITYCRITERIATYPE_USERNAME, name);
    UA_StatusCode rm = rule_call(t->client, obs, "RemoveIdentity", UA_IDENTITYCRITERIATYPE_USERNAME, name);
    UA_StatusCode rm2 = rule_call(t->client, obs, "RemoveIdentity", UA_IDENTITYCRITERIATYPE_USERNAME, name);
    if(!listed)
        ga_fail(ctx, "the added rule is not in Identities");
    else if(rm != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "RemoveIdentity -> %s", UA_StatusCode_name(rm));
    else if(again != UA_STATUSCODE_BADALREADYEXISTS)
        ga_warn(ctx, "adding the same rule again -> %s; the spec names Bad_AlreadyExists",
                UA_StatusCode_name(again));
    else if(rm2 != UA_STATUSCODE_BADNOTFOUND)
        ga_warn(ctx, "removing it again -> %s; the spec names Bad_NotFound",
                UA_StatusCode_name(rm2));
    else
        ga_pass(ctx, "rule added, listed, Bad_AlreadyExists, removed, Bad_NotFound");
}

/* §4.4.5: only administrators over an encrypted channel */
static void t_identity_needs_admin(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_StatusCode r;
    UA_Client *out = gt_anon_session(t, &r);
    if(!out) {
        ga_pass(ctx, "a session without a user is refused (%s)", UA_StatusCode_name(r));
        return;
    }
    char name[96], pw[64];
    make_user(t, "outsider", name, sizeof(name), pw, sizeof(pw));
    r = rule_call(out, role(UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN), "AddIdentity",
                  UA_IDENTITYCRITERIATYPE_USERNAME, name);
    gt_drop(out);
    if(absent(r))
        ga_not_supported(ctx, "SecurityAdmin has no AddIdentity (%s)", UA_StatusCode_name(r));
    else
        refused(ctx, r, UA_STATUSCODE_BADUSERACCESSDENIED, "AddIdentity on SecurityAdmin by the outsider");
    if(r == UA_STATUSCODE_GOOD && gt_session(t) == UA_STATUSCODE_GOOD)
        (void)rule_call(t->client, role(UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN), "RemoveIdentity",
                        UA_IDENTITYCRITERIATYPE_USERNAME, name);
}

/* §4.4.1: a Server should refuse an Anonymous rule on an administrator Role */
static void t_anonymous_admin(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    UA_NodeId sa = role(UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN);
    UA_StatusCode r = rule_call(t->client, sa, "AddIdentity", UA_IDENTITYCRITERIATYPE_ANONYMOUS, "");
    if(absent(r)) {
        ga_not_supported(ctx, "SecurityAdmin has no AddIdentity (%s)", UA_StatusCode_name(r));
        return;
    }
    if(r == UA_STATUSCODE_GOOD) {
        (void)rule_call(t->client, sa, "RemoveIdentity", UA_IDENTITYCRITERIATYPE_ANONYMOUS, "");
        ga_warn(ctx, "an Anonymous rule was added to SecurityAdmin (removed again); "
                     "the spec says a Server should refuse it");
        return;
    }
    refused(ctx, r, UA_STATUSCODE_BADREQUESTNOTALLOWED, "Anonymous rule on SecurityAdmin");
}

/* §4.3: the Anonymous and AuthenticatedUser Roles do not change */
static void t_fixed_roles(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    char name[96], pw[64];
    make_user(t, "fixed", name, sizeof(name), pw, sizeof(pw));
    UA_NodeId anon = role(UA_NS0ID_WELLKNOWNROLE_ANONYMOUS);
    UA_StatusCode r = rule_call(t->client, anon, "AddIdentity", UA_IDENTITYCRITERIATYPE_USERNAME, name);
    if(absent(r)) {
        ga_pass(ctx, "the Anonymous Role offers no AddIdentity");
        return;
    }
    if(r == UA_STATUSCODE_GOOD)
        (void)rule_call(t->client, anon, "RemoveIdentity", UA_IDENTITYCRITERIATYPE_USERNAME, name);
    refused(ctx, r, UA_STATUSCODE_BADREQUESTNOTALLOWED, "AddIdentity on the Anonymous Role");
}

/* §4.4.7 - §4.4.10: one call pair on Observer */
static void pair(ga_ctx *ctx, gds_target *t, const char *add, const char *remove,
                 const UA_Variant *in) {
    if(!admin(ctx, t))
        return;
    UA_NodeId obs = role(UA_NS0ID_WELLKNOWNROLE_OBSERVER);
    UA_StatusCode r = call_named(t->client, obs, add, 1, in);
    if(absent(r)) {
        ga_not_supported(ctx, "Observer has no %s (%s)", add, UA_StatusCode_name(r));
        return;
    }
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "%s -> %s", add, UA_StatusCode_name(r));
        return;
    }
    UA_StatusCode again = call_named(t->client, obs, add, 1, in);
    UA_StatusCode rm = call_named(t->client, obs, remove, 1, in);
    UA_StatusCode rm2 = call_named(t->client, obs, remove, 1, in);
    if(rm != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "%s -> %s", remove, UA_StatusCode_name(rm));
    else if(again != UA_STATUSCODE_BADALREADYEXISTS || rm2 != UA_STATUSCODE_BADNOTFOUND)
        ga_warn(ctx, "repeated %s -> %s, repeated %s -> %s; the spec names Bad_AlreadyExists "
                     "and Bad_NotFound", add, UA_StatusCode_name(again), remove,
                UA_StatusCode_name(rm2));
    else
        ga_pass(ctx, "%s and %s, with Bad_AlreadyExists and Bad_NotFound on repeats", add, remove);
}

static void t_add_remove_application(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    char uri[URI_LEN];
    gt_unique_uri(t, uri, sizeof(uri));
    UA_String s = UA_STRING(uri);
    UA_Variant in;
    UA_Variant_setScalar(&in, &s, &UA_TYPES[UA_TYPES_STRING]);
    pair(ctx, t, "AddApplication", "RemoveApplication", &in);
}

static void t_add_remove_endpoint(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    char url[160];
    (void)snprintf(url, sizeof(url), "opc.tcp://auditor-%s.invalid:4840", t->runTag);
    UA_EndpointType e;
    UA_EndpointType_init(&e);
    e.endpointUrl = UA_STRING(url);
    e.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    UA_Variant in;
    UA_Variant_setScalar(&in, &e, &UA_TYPES[UA_TYPES_ENDPOINTTYPE]);
    pair(ctx, t, "AddEndpoint", "RemoveEndpoint", &in);
}

/* §4.5: one RoleMappingRuleChangedAuditEventType per rule change */
typedef struct {
    size_t hits;
} sink;

static void on_event(UA_Client *c, UA_UInt32 subId, void *subCtx, UA_UInt32 monId, void *monCtx,
                     const UA_KeyValueMap f) {
    (void)c, (void)subId, (void)subCtx, (void)monId, (void)f;
    ((sink *)monCtx)->hits++;
}

static UA_StatusCode subscribe(UA_Client *c, sink *s, UA_UInt32 *sub) {
    UA_CreateSubscriptionRequest sreq = UA_CreateSubscriptionRequest_default();
    sreq.requestedPublishingInterval = 50;
    UA_CreateSubscriptionResponse sresp = UA_Client_Subscriptions_create(c, sreq, NULL, NULL, NULL);
    UA_StatusCode r = sresp.responseHeader.serviceResult;
    *sub = sresp.subscriptionId;
    UA_CreateSubscriptionResponse_clear(&sresp);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_QualifiedName qStatus = UA_QUALIFIEDNAME(0, "Status");
    UA_SimpleAttributeOperand sel;
    UA_SimpleAttributeOperand_init(&sel);
    sel.typeDefinitionId = UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE);
    sel.attributeId = UA_ATTRIBUTEID_VALUE;
    sel.browsePathSize = 1;
    sel.browsePath = &qStatus;
    UA_NodeId type = UA_NODEID_NUMERIC(0, UA_NS0ID_ROLEMAPPINGRULECHANGEDAUDITEVENTTYPE);
    UA_LiteralOperand lit;
    UA_LiteralOperand_init(&lit);
    UA_Variant_setScalar(&lit.value, &type, &UA_TYPES[UA_TYPES_NODEID]);
    UA_ExtensionObject op;
    UA_ExtensionObject_setValue(&op, &lit, &UA_TYPES[UA_TYPES_LITERALOPERAND]);
    UA_ContentFilterElement el;
    UA_ContentFilterElement_init(&el);
    el.filterOperator = UA_FILTEROPERATOR_OFTYPE;
    el.filterOperands = &op;
    el.filterOperandsSize = 1;
    UA_EventFilter filter;
    UA_EventFilter_init(&filter);
    filter.selectClauses = &sel;
    filter.selectClausesSize = 1;
    filter.whereClause.elements = &el;
    filter.whereClause.elementsSize = 1;
    UA_MonitoredItemCreateRequest item;
    UA_MonitoredItemCreateRequest_init(&item);
    item.itemToMonitor.nodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER);
    item.itemToMonitor.attributeId = UA_ATTRIBUTEID_EVENTNOTIFIER;
    item.monitoringMode = UA_MONITORINGMODE_REPORTING;
    UA_ExtensionObject_setValue(&item.requestedParameters.filter, &filter,
                                &UA_TYPES[UA_TYPES_EVENTFILTER]);
    item.requestedParameters.queueSize = 16;
    UA_MonitoredItemCreateResult res = UA_Client_MonitoredItems_createEvent(
        c, *sub, UA_TIMESTAMPSTORETURN_NEITHER, item, s, on_event, NULL);
    r = res.statusCode;
    UA_MonitoredItemCreateResult_clear(&res);
    if(r != UA_STATUSCODE_GOOD)
        (void)UA_Client_Subscriptions_deleteSingle(c, *sub);
    else
        (void)UA_Client_run_iterate(c, 100);
    return r;
}

static void t_audit_rule_changed(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    sink s = {0};
    UA_UInt32 sub = 0;
    UA_StatusCode r = subscribe(t->client, &s, &sub);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "event subscription -> %s", UA_StatusCode_name(r));
        return;
    }
    char name[96], pw[64];
    make_user(t, "audit", name, sizeof(name), pw, sizeof(pw));
    UA_NodeId obs = role(UA_NS0ID_WELLKNOWNROLE_OBSERVER);
    r = rule_call(t->client, obs, "AddIdentity", UA_IDENTITYCRITERIATYPE_USERNAME, name);
    UA_StatusCode rm = r == UA_STATUSCODE_GOOD
                           ? rule_call(t->client, obs, "RemoveIdentity",
                                       UA_IDENTITYCRITERIATYPE_USERNAME, name)
                           : r;
    for(int waited = 0; waited < EV_WAIT && s.hits < 2; waited += 50)
        (void)UA_Client_run_iterate(t->client, 50);
    (void)UA_Client_Subscriptions_deleteSingle(t->client, sub);
    if(absent(r))
        ga_not_supported(ctx, "Observer has no AddIdentity (%s)", UA_StatusCode_name(r));
    else if(r != UA_STATUSCODE_GOOD || rm != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup: AddIdentity -> %s, RemoveIdentity -> %s",
                      UA_StatusCode_name(r), UA_StatusCode_name(rm));
    else if(s.hits < 2)
        ga_fail(ctx, "%zu RoleMappingRuleChanged event(s) for an add and a remove, expected 2",
                s.hits);
    else
        ga_pass(ctx, "one RoleMappingRuleChangedAuditEvent per rule change");
}

/* ---- UserManagement (§5.2) ---- */

/* §5.2.5, §5.2.7 with the Users Property */
static void t_add_remove_user(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    char name[96], pw[64];
    make_user(t, "user", name, sizeof(name), pw, sizeof(pw));
    UA_StatusCode r = add_user(t->client, name, pw);
    if(absent(r)) {
        ga_not_supported(ctx, "no UserManagement AddUser (%s)", UA_StatusCode_name(r));
        return;
    }
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "AddUser -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_Variant v;
    UA_StatusCode rr = read_named(t->client, user_mgmt(), "Users", &v);
    bool listed = rr == UA_STATUSCODE_GOOD && has_user(&v, name);
    UA_Variant_clear(&v);
    UA_StatusCode again = add_user(t->client, name, pw);
    UA_StatusCode rm = str_call(t->client, user_mgmt(), "RemoveUser", name);
    UA_StatusCode rm2 = str_call(t->client, user_mgmt(), "RemoveUser", name);
    if(!listed)
        ga_fail(ctx, "the new user is not in Users (%s)", UA_StatusCode_name(rr));
    else if(rm != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "RemoveUser -> %s", UA_StatusCode_name(rm));
    else if(again != UA_STATUSCODE_BADALREADYEXISTS || rm2 != UA_STATUSCODE_BADNOTFOUND)
        ga_warn(ctx, "repeated AddUser -> %s, repeated RemoveUser -> %s; the spec names "
                     "Bad_AlreadyExists and Bad_NotFound", UA_StatusCode_name(again),
                UA_StatusCode_name(rm2));
    else
        ga_pass(ctx, "user added, listed in Users, removed; repeats refused as specified");
}

/* §5.2.5 Bad_OutOfRange, against PasswordLength */
static void t_short_password(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    UA_Variant v;
    UA_StatusCode r = read_named(t->client, user_mgmt(), "PasswordLength", &v);
    double low = 0;
    if(r == UA_STATUSCODE_GOOD && UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_RANGE]))
        low = ((UA_Range *)v.data)->low;
    UA_Variant_clear(&v);
    if(absent(r)) {
        ga_not_supported(ctx, "no UserManagement (%s)", UA_StatusCode_name(r));
        return;
    }
    if(low < 2) {
        ga_not_tested(ctx, "PasswordLength low is %.0f: no password is too short", low);
        return;
    }
    char name[96], pw[64];
    make_user(t, "short", name, sizeof(name), pw, sizeof(pw));
    r = add_user(t->client, name, "x");
    if(r == UA_STATUSCODE_GOOD)
        (void)str_call(t->client, user_mgmt(), "RemoveUser", name);
    refused(ctx, r, UA_STATUSCODE_BADOUTOFRANGE, "AddUser with a 1-character password");
}

/* §5.2.1: Users and AddUser for administrators only */
static void t_user_mgmt_needs_admin(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_StatusCode r;
    UA_Client *out = gt_anon_session(t, &r);
    if(!out) {
        ga_pass(ctx, "a session without a user is refused (%s)", UA_StatusCode_name(r));
        return;
    }
    char name[96], pw[64];
    make_user(t, "intruder", name, sizeof(name), pw, sizeof(pw));
    UA_Variant v;
    UA_StatusCode rr = read_named(out, user_mgmt(), "Users", &v);
    bool leaked = rr == UA_STATUSCODE_GOOD && v.arrayLength > 0;
    UA_Variant_clear(&v);
    r = add_user(out, name, pw);
    gt_drop(out);
    if(absent(r) && absent(rr)) {
        ga_not_supported(ctx, "no UserManagement (%s)", UA_StatusCode_name(r));
        return;
    }
    if(r == UA_STATUSCODE_GOOD && gt_session(t) == UA_STATUSCODE_GOOD)
        (void)str_call(t->client, user_mgmt(), "RemoveUser", name);
    if(leaked)
        ga_fail(ctx, "the outsider can read Users");
    else
        refused(ctx, r, UA_STATUSCODE_BADUSERACCESSDENIED, "AddUser by the outsider");
}

/* §4.4.3 UserName rule + §5.2: a managed user gets the Role its rule names */
static void t_user_rule_grants_role(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    char name[96], pw[64];
    make_user(t, "da", name, sizeof(name), pw, sizeof(pw));
    UA_StatusCode r = add_user(t->client, name, pw);
    if(absent(r)) {
        ga_not_supported(ctx, "no UserManagement AddUser (%s)", UA_StatusCode_name(r));
        return;
    }
    UA_NodeId da = UA_NODEID_NUMERIC(t->ns, UA_GDSID_WELLKNOWNROLE_DISCOVERYADMIN);
    UA_StatusCode ra = r == UA_STATUSCODE_GOOD
                           ? rule_call(t->client, da, "AddIdentity",
                                       UA_IDENTITYCRITERIATYPE_USERNAME, name)
                           : r;
    UA_StatusCode reg = UA_STATUSCODE_BADINTERNALERROR, before = UA_STATUSCODE_BADINTERNALERROR;
    if(r == UA_STATUSCODE_GOOD && ra == UA_STATUSCODE_GOOD) {
        UA_StatusCode cr;
        UA_Client *c = user_session(t, name, pw, &cr);
        if(c) {
            char uri[URI_LEN];
            gt_unique_uri(t, uri, sizeof(uri));
            UA_ApplicationRecordDataType rec;
            UA_LocalizedText ln;
            UA_String url;
            gt_record(&rec, uri, UA_APPLICATIONTYPE_CLIENT, &ln, &url);
            UA_Variant in;
            UA_Variant_setScalar(&in, &rec, gt_record_type());
            size_t outN = 0;
            UA_Variant *out = NULL;
            reg = UA_Client_call(c, UA_NODEID_NUMERIC(t->ns, UA_GDSID_DIRECTORY),
                                 UA_NODEID_NUMERIC(t->ns, UA_GDSID_DIRECTORY_REGISTERAPPLICATION),
                                 1, &in, &outN, &out);
            if(reg == UA_STATUSCODE_GOOD && outN == 1) {
                UA_Variant_setScalar(&in, out[0].data, &UA_TYPES[UA_TYPES_NODEID]);
                size_t n2 = 0;
                UA_Variant *o2 = NULL;
                (void)UA_Client_call(c, UA_NODEID_NUMERIC(t->ns, UA_GDSID_DIRECTORY),
                                     UA_NODEID_NUMERIC(t->ns, UA_GDSID_DIRECTORY_UNREGISTERAPPLICATION),
                                     1, &in, &n2, &o2);
                gt_free_out(o2, n2);
            }
            gt_free_out(out, outN);
            gt_drop(c);
        } else {
            reg = cr;
        }
        before = UA_STATUSCODE_GOOD;
    }
    if(ra == UA_STATUSCODE_GOOD)
        (void)rule_call(t->client, da, "RemoveIdentity", UA_IDENTITYCRITERIATYPE_USERNAME, name);
    if(r == UA_STATUSCODE_GOOD)
        (void)str_call(t->client, user_mgmt(), "RemoveUser", name);
    if(r != UA_STATUSCODE_GOOD || ra != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup: AddUser -> %s, AddIdentity on DiscoveryAdmin -> %s",
                      UA_StatusCode_name(r), UA_StatusCode_name(ra));
    else if(before == UA_STATUSCODE_GOOD && reg == UA_STATUSCODE_GOOD)
        ga_pass(ctx, "the user mapped to DiscoveryAdmin registered an application");
    else
        ga_fail(ctx, "the user mapped to DiscoveryAdmin could not register: %s",
                UA_StatusCode_name(reg));
}

/* §5.2.8: ChangePassword for the session's own user */
static void t_change_password(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    char name[96], pw[64], pw2[80];
    make_user(t, "cp", name, sizeof(name), pw, sizeof(pw));
    (void)snprintf(pw2, sizeof(pw2), "%s-new", pw);
    UA_StatusCode r = add_user(t->client, name, pw);
    if(absent(r)) {
        ga_not_supported(ctx, "no UserManagement AddUser (%s)", UA_StatusCode_name(r));
        return;
    }
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: AddUser -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_StatusCode cr, wrong = UA_STATUSCODE_GOOD, ch = UA_STATUSCODE_BADINTERNALERROR;
    UA_StatusCode oldLogin = UA_STATUSCODE_GOOD, newLogin = UA_STATUSCODE_BADINTERNALERROR;
    UA_Client *c = user_session(t, name, pw, &cr);
    if(c) {
        wrong = change_password(c, pw2, pw2);
        ch = change_password(c, pw, pw2);
        gt_drop(c);
        UA_Client *o = user_session(t, name, pw, &oldLogin);
        gt_drop(o);
        UA_Client *n = user_session(t, name, pw2, &newLogin);
        gt_drop(n);
    }
    if(gt_session(t) == UA_STATUSCODE_GOOD)
        (void)str_call(t->client, user_mgmt(), "RemoveUser", name);
    if(!c)
        ga_fail(ctx, "the new user cannot open a session: %s", UA_StatusCode_name(cr));
    else if(ch != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "ChangePassword -> %s", UA_StatusCode_name(ch));
    else if(oldLogin == UA_STATUSCODE_GOOD || newLogin != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "after ChangePassword the old password -> %s, the new -> %s",
                UA_StatusCode_name(oldLogin), UA_StatusCode_name(newLogin));
    else if(wrong != UA_STATUSCODE_BADIDENTITYTOKENINVALID)
        ga_warn(ctx, "a wrong old password -> %s; the spec names Bad_IdentityTokenInvalid",
                UA_StatusCode_name(wrong));
    else
        ga_pass(ctx, "password changed; the old one is refused, the new one accepted");
}

/* §5.2.3, §5.2.6: a disabled user cannot sign in */
static void t_disable_user(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    char name[96], pw[64];
    make_user(t, "off", name, sizeof(name), pw, sizeof(pw));
    UA_StatusCode r = add_user(t->client, name, pw);
    if(absent(r)) {
        ga_not_supported(ctx, "no UserManagement AddUser (%s)", UA_StatusCode_name(r));
        return;
    }
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: AddUser -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_StatusCode d = disable_user(t->client, name), login = UA_STATUSCODE_GOOD;
    if(d == UA_STATUSCODE_GOOD) {
        UA_Client *c = user_session(t, name, pw, &login);
        gt_drop(c);
    }
    (void)str_call(t->client, user_mgmt(), "RemoveUser", name);
    if(d == UA_STATUSCODE_BADNOTSUPPORTED)
        ga_not_supported(ctx, "ModifyUser Disabled -> Bad_NotSupported");
    else if(d != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "ModifyUser Disabled -> %s", UA_StatusCode_name(d));
    else if(login == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "a disabled user opened a session");
    else
        ga_pass(ctx, "the disabled user is refused (%s)", UA_StatusCode_name(login));
}

/* §5.2.7: RemoveUser of the caller's own user */
static void t_remove_self(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    if(!admin(ctx, t))
        return;
    char name[96], pw[64];
    make_user(t, "self", name, sizeof(name), pw, sizeof(pw));
    UA_StatusCode r = add_user(t->client, name, pw);
    if(absent(r)) {
        ga_not_supported(ctx, "no UserManagement AddUser (%s)", UA_StatusCode_name(r));
        return;
    }
    UA_NodeId sa = role(UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN);
    UA_StatusCode ra = r == UA_STATUSCODE_GOOD
                           ? rule_call(t->client, sa, "AddIdentity",
                                       UA_IDENTITYCRITERIATYPE_USERNAME, name)
                           : r;
    UA_StatusCode self = UA_STATUSCODE_GOOD, cr = UA_STATUSCODE_GOOD;
    if(ra == UA_STATUSCODE_GOOD) {
        UA_Client *c = user_session(t, name, pw, &cr);
        if(c)
            self = str_call(c, user_mgmt(), "RemoveUser", name);
        gt_drop(c);
    }
    if(gt_session(t) == UA_STATUSCODE_GOOD) {
        if(ra == UA_STATUSCODE_GOOD)
            (void)rule_call(t->client, sa, "RemoveIdentity", UA_IDENTITYCRITERIATYPE_USERNAME, name);
        (void)str_call(t->client, user_mgmt(), "RemoveUser", name);
    }
    if(r != UA_STATUSCODE_GOOD || ra != UA_STATUSCODE_GOOD || cr != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup: AddUser -> %s, AddIdentity -> %s, session -> %s",
                      UA_StatusCode_name(r), UA_StatusCode_name(ra), UA_StatusCode_name(cr));
    else
        refused(ctx, self, UA_STATUSCODE_BADINVALIDSELFREFERENCE, "RemoveUser of the caller");
}

const ga_test spec_part18_tests[] = {
    {"gds.p18.identities_read", "18 §4.4.1", "Identities is readable by administrators only",
     true, false, t_identities_read},
    {"gds.p18.add_remove_identity", "18 §4.4.5, §4.4.6", "AddIdentity and RemoveIdentity of a UserName rule",
     true, false, t_add_remove_identity},
    {"gds.p18.identity_needs_admin", "18 §4.4.5", "AddIdentity needs an administrator",
     true, false, t_identity_needs_admin},
    {"gds.p18.anonymous_admin", "18 §4.4.1", "No Anonymous rule on an administrator Role",
     true, false, t_anonymous_admin},
    {"gds.p18.fixed_roles", "18 §4.3", "The Anonymous Role cannot be changed",
     true, false, t_fixed_roles},
    {"gds.p18.add_remove_application", "18 §4.4.7, §4.4.8", "AddApplication and RemoveApplication",
     true, false, t_add_remove_application},
    {"gds.p18.add_remove_endpoint", "18 §4.4.9, §4.4.10", "AddEndpoint and RemoveEndpoint",
     true, false, t_add_remove_endpoint},
    {"gds.p18.audit_rule_changed", "18 §4.5", "A RoleMappingRuleChangedAuditEvent per rule change",
     true, false, t_audit_rule_changed},
    {"gds.p18.add_remove_user", "18 §5.2.5, §5.2.7", "AddUser and RemoveUser with the Users Property",
     true, false, t_add_remove_user},
    {"gds.p18.short_password", "18 §5.2.1, §5.2.5", "AddUser refuses a password below PasswordLength",
     true, false, t_short_password},
    {"gds.p18.user_mgmt_needs_admin", "18 §5.2.1, §5.2.5", "Users and AddUser need an administrator",
     true, false, t_user_mgmt_needs_admin},
    {"gds.p18.user_rule_grants_role", "18 §4.4.1, §4.4.3; 12 §6.2", "A UserName rule grants its Role to a managed user",
     true, false, t_user_rule_grants_role},
    {"gds.p18.change_password", "18 §5.2.8", "ChangePassword by the user itself",
     true, false, t_change_password},
    {"gds.p18.disable_user", "18 §5.2.3, §5.2.6", "A disabled user cannot open a session",
     true, false, t_disable_user},
    {"gds.p18.remove_self", "18 §5.2.7", "RemoveUser of the caller is Bad_InvalidSelfReference",
     true, false, t_remove_self},
};
const size_t spec_part18_count = GDS_ARRAY_SIZE(spec_part18_tests);
