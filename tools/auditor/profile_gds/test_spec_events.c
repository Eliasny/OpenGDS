/* OpenGDS spec tests: audit events and alarms of the GDS
 * (OPC 10000-12 §6.5.12 ApplicationRegistrationChangedAuditEventType,
 * §7.9.12-§7.9.14 Certificate Requested/Delivered/Revoked, §7.8.2.1 and
 * §7.8.2.12 TrustListUpdatedAuditEventType, §8.5.9-§8.5.11 KeyCredential
 * events, §7.8.3.1 CertificateGroup alarms). Audit events are raised "if
 * auditing is supported": with Server.Auditing false every audit test is
 * Not supported.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>
#include <open62541/nodeids_gds.h>

#include <string.h>

#include "common/limits.h"
#include "gds_tl.h"
#include "spec_tests.h"
#include "common/banned.h"

#define URI_LEN  (GDS_MAX_APPLICATION_URI + 1)
#define EV_WAIT  3000 /* ms to wait for an event after the action */
#define F_STATUS 0
#define F_GROUP  1

typedef struct {
    size_t hits, good, bad;
    bool groupOk; /* CertificateGroup field was the default group on every hit */
    UA_NodeId wantGroup;
    bool strOk;         /* the second field was the same String on every hit */
    UA_String *wantStr; /* NULL: not checked; that String, set by the first hit */
} ev_sink;

static void on_event(UA_Client *c, UA_UInt32 subId, void *subCtx, UA_UInt32 monId, void *monCtx,
                     const UA_KeyValueMap f) {
    (void)c;
    (void)subId;
    (void)subCtx;
    (void)monId;
    ev_sink *s = monCtx;
    s->hits++;
    if(f.mapSize > F_STATUS && UA_Variant_hasScalarType(&f.map[F_STATUS].value, &UA_TYPES[UA_TYPES_BOOLEAN])) {
        if(*(UA_Boolean *)f.map[F_STATUS].value.data)
            s->good++;
        else
            s->bad++;
    }
    if(!UA_NodeId_isNull(&s->wantGroup)) {
        bool ok = f.mapSize > F_GROUP &&
                  UA_Variant_hasScalarType(&f.map[F_GROUP].value, &UA_TYPES[UA_TYPES_NODEID]) &&
                  UA_NodeId_equal((UA_NodeId *)f.map[F_GROUP].value.data, &s->wantGroup);
        if(!ok)
            s->groupOk = false;
    }
    if(s->wantStr) { /* every hit carries the same string, kept in *wantStr */
        const UA_String *v =
            f.mapSize > F_GROUP &&
                    UA_Variant_hasScalarType(&f.map[F_GROUP].value, &UA_TYPES[UA_TYPES_STRING])
                ? f.map[F_GROUP].value.data
                : NULL;
        bool first = v && v->length > 0 && s->wantStr->length == 0;
        bool ok = v && v->length > 0 &&
                  (first ? UA_String_copy(v, s->wantStr) == UA_STATUSCODE_GOOD
                         : UA_String_equal(v, s->wantStr));
        s->strOk = s->strOk && ok;
    }
}

typedef struct {
    UA_UInt32 sub;
    ev_sink sink;
    bool ok;
} ev_watch;

/* Subscribe to events of `type` (and subtypes) on the Server Object, selecting
 * Status and, when given, a second field (`second`). */
static UA_StatusCode watch_field(gds_target *t, UA_NodeId type, const UA_QualifiedName *second,
                                 ev_watch *w) {
    memset(w, 0, sizeof(*w));
    w->sink.groupOk = true;
    w->sink.strOk = true;
    UA_CreateSubscriptionRequest sreq = UA_CreateSubscriptionRequest_default();
    sreq.requestedPublishingInterval = 50;
    UA_CreateSubscriptionResponse sresp =
        UA_Client_Subscriptions_create(t->client, sreq, NULL, NULL, NULL);
    UA_StatusCode r = sresp.responseHeader.serviceResult;
    w->sub = sresp.subscriptionId;
    UA_CreateSubscriptionResponse_clear(&sresp);
    if(r != UA_STATUSCODE_GOOD)
        return r;

    UA_SimpleAttributeOperand sel[2];
    UA_QualifiedName qStatus = UA_QUALIFIEDNAME(0, "Status");
    UA_QualifiedName qSecond = second ? *second : UA_QUALIFIEDNAME(0, "Status");
    for(size_t i = 0; i < 2; i++) {
        UA_SimpleAttributeOperand_init(&sel[i]);
        sel[i].typeDefinitionId = UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE);
        sel[i].attributeId = UA_ATTRIBUTEID_VALUE;
        sel[i].browsePathSize = 1;
    }
    sel[0].browsePath = &qStatus;
    sel[1].browsePath = &qSecond;

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
    filter.selectClauses = sel;
    filter.selectClausesSize = second ? 2 : 1;
    filter.whereClause.elements = &el;
    filter.whereClause.elementsSize = 1;

    UA_MonitoredItemCreateRequest item;
    UA_MonitoredItemCreateRequest_init(&item);
    item.itemToMonitor.nodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER);
    item.itemToMonitor.attributeId = UA_ATTRIBUTEID_EVENTNOTIFIER;
    item.monitoringMode = UA_MONITORINGMODE_REPORTING;
    UA_ExtensionObject_setValue(&item.requestedParameters.filter, &filter,
                                &UA_TYPES[UA_TYPES_EVENTFILTER]);
    item.requestedParameters.queueSize = 64;
    item.requestedParameters.discardOldest = true;
    UA_MonitoredItemCreateResult res = UA_Client_MonitoredItems_createEvent(
        t->client, w->sub, UA_TIMESTAMPSTORETURN_NEITHER, item, &w->sink, on_event, NULL);
    r = res.statusCode;
    UA_MonitoredItemCreateResult_clear(&res);
    if(r != UA_STATUSCODE_GOOD) {
        (void)UA_Client_Subscriptions_deleteSingle(t->client, w->sub);
        return r;
    }
    w->ok = true;
    (void)UA_Client_run_iterate(t->client, 100);
    return UA_STATUSCODE_GOOD;
}

/* Status and, with groupField, <GDS ns>:CertificateGroup. */
static UA_StatusCode watch(gds_target *t, UA_NodeId type, bool groupField, ev_watch *w) {
    UA_QualifiedName qGroup = UA_QUALIFIEDNAME(t->ns, "CertificateGroup");
    return watch_field(t, type, groupField ? &qGroup : NULL, w);
}

/* Wait until `want` events arrived or EV_WAIT ms passed. */
static void drain(gds_target *t, ev_watch *w, size_t want) {
    for(int waited = 0; waited < EV_WAIT && w->sink.hits < want; waited += 50)
        (void)UA_Client_run_iterate(t->client, 50);
    (void)UA_Client_run_iterate(t->client, 50);
}

static void unwatch(gds_target *t, ev_watch *w) {
    if(w->ok && t->client)
        (void)UA_Client_Subscriptions_deleteSingle(t->client, w->sub);
    w->ok = false;
}

/* Setup common to the audit tests: the admin session; *on is Server.Auditing.
 * The tests watch for events either way: with Auditing FALSE and no event
 * the test is Not supported (audit events are raised "if auditing is
 * supported"); events raised while Auditing is FALSE are gds.ev.auditing_flag. */
static bool auditing(ga_ctx *ctx, gds_target *t, bool *on) {
    *on = false;
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: admin session -> %s", UA_StatusCode_name(r));
        return false;
    }
    UA_Variant v;
    UA_Variant_init(&v);
    r = UA_Client_readValueAttribute(t->client, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_AUDITING), &v);
    *on = r == UA_STATUSCODE_GOOD && UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_BOOLEAN]) &&
          *(UA_Boolean *)v.data;
    UA_Variant_clear(&v);
    return true;
}

/* With Auditing FALSE and nothing received: Not supported. */
static void none_if_off(ga_ctx *ctx, bool on, size_t hits) {
    if(!on && hits == 0)
        ga_not_supported(ctx, "Server.Auditing is FALSE and no audit event was raised");
}

static void t_registration_changed(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    bool on;
    if(!auditing(ctx, t, &on))
        return;
    ev_watch w;
    UA_StatusCode r = watch(t, gt_node(t, UA_GDSID_APPLICATIONREGISTRATIONCHANGEDAUDITEVENTTYPE),
                            false, &w);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "event subscription -> %s", UA_StatusCode_name(r));
        return;
    }
    char uri[URI_LEN];
    UA_NodeId id;
    r = gt_register(t, UA_APPLICATIONTYPE_CLIENT, uri, sizeof(uri), &id);
    if(r == UA_STATUSCODE_GOOD) {
        UA_Variant in;
        UA_Variant_setScalar(&in, &id, &UA_TYPES[UA_TYPES_NODEID]);
        size_t outN = 0;
        UA_Variant *out = NULL;
        r = gt_call(t, UA_GDSID_DIRECTORY_UNREGISTERAPPLICATION, 1, &in, 0, &outN, &out);
        gt_free_out(out, outN);
        UA_NodeId_clear(&id);
    }
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: RegisterApplication/UnregisterApplication -> %s",
                      UA_StatusCode_name(r));
        unwatch(t, &w);
        return;
    }
    drain(t, &w, 2);
    unwatch(t, &w);
    none_if_off(ctx, on, w.sink.hits);
    if(w.sink.hits < 2)
        ga_fail(ctx, "%zu ApplicationRegistrationChanged event(s) for a Register and an "
                     "Unregister, expected 2", w.sink.hits);
    else if(w.sink.good < 2)
        ga_fail(ctx, "events arrived but Status is not TRUE on both");
    else
        ga_pass(ctx, "one event per RegisterApplication and UnregisterApplication, Status TRUE");
}

/* Requested on success and on failure; Delivered on a successful FinishRequest */
static void t_certificate_requested_delivered(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    bool on;
    if(!auditing(ctx, t, &on))
        return;
    ev_watch req, del;
    UA_StatusCode r1 = watch(t, gt_node(t, UA_GDSID_CERTIFICATEREQUESTEDAUDITEVENTTYPE), true, &req);
    UA_StatusCode r2 = watch(t, gt_node(t, UA_GDSID_CERTIFICATEDELIVEREDAUDITEVENTTYPE), true, &del);
    if(r1 != UA_STATUSCODE_GOOD || r2 != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "event subscriptions -> %s / %s", UA_StatusCode_name(r1),
                UA_StatusCode_name(r2));
        unwatch(t, &req);
        unwatch(t, &del);
        return;
    }
    req.sink.wantGroup = del.sink.wantGroup = gt_default_group(t);
    char uri[URI_LEN];
    UA_NodeId id;
    gds_buf cert = {0}, issuer = {0};
    UA_StatusCode r = gt_issue(t, ctx, uri, sizeof(uri), &id, &cert, &issuer);
    if(r == UA_STATUSCODE_GOOD) { /* and one refused request: not a CSR */
        static const uint8_t junk[] = {0x30, 0x03, 0x02, 0x01, 0x00};
        UA_NodeId group = gt_default_group(t), type = gt_rsa_type();
        UA_ByteString csr = {sizeof(junk), (UA_Byte *)(uintptr_t)junk};
        UA_Variant in[4];
        UA_Variant_setScalar(&in[0], &id, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&in[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&in[2], &type, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&in[3], &csr, &UA_TYPES[UA_TYPES_BYTESTRING]);
        size_t outN = 0;
        UA_Variant *out = NULL;
        UA_StatusCode rb = gt_call(t, UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST, 4, in, 0, &outN, &out);
        gt_free_out(out, outN);
        ga_note(ctx, "StartSigningRequest(not a CSR) -> %s", UA_StatusCode_name(rb));
        UA_NodeId_clear(&id);
    }
    gds_buf_free(&cert);
    gds_buf_free(&issuer);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: signing flow -> %s", UA_StatusCode_name(r));
    } else {
        drain(t, &req, 2);
        drain(t, &del, 1);
        none_if_off(ctx, on, req.sink.hits + del.sink.hits);
        if(req.sink.hits < 2)
            ga_fail(ctx, "%zu CertificateRequested event(s) for one accepted and one refused "
                         "request, expected 2", req.sink.hits);
        else if(req.sink.good < 1 || req.sink.bad < 1)
            ga_fail(ctx, "CertificateRequested Status should be TRUE once and FALSE once "
                         "(%zu/%zu)", req.sink.good, req.sink.bad);
        else if(del.sink.hits < 1)
            ga_fail(ctx, "no CertificateDelivered event after a successful FinishRequest");
        else if(!req.sink.groupOk || !del.sink.groupOk)
            ga_fail(ctx, "CertificateGroup field is not DefaultApplicationGroup");
        else
            ga_pass(ctx, "Requested (accepted and refused) and Delivered events with the group");
    }
    unwatch(t, &req);
    unwatch(t, &del);
}

static void t_certificate_revoked(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    bool on;
    if(!auditing(ctx, t, &on))
        return;
    ev_watch w;
    UA_StatusCode r = watch(t, gt_node(t, UA_GDSID_CERTIFICATEREVOKEDAUDITEVENTTYPE), false, &w);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "event subscription -> %s", UA_StatusCode_name(r));
        return;
    }
    char uri[URI_LEN];
    UA_NodeId id;
    gds_buf cert = {0}, issuer = {0};
    r = gt_issue(t, ctx, uri, sizeof(uri), &id, &cert, &issuer);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: signing flow -> %s", UA_StatusCode_name(r));
        unwatch(t, &w);
        return;
    }
    UA_ByteString c = {cert.len, cert.data};
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &id, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &c, &UA_TYPES[UA_TYPES_BYTESTRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    r = gt_call(t, UA_GDSID_DIRECTORY_REVOKECERTIFICATE, 2, in, 0, &outN, &out);
    gt_free_out(out, outN);
    if(!gt_absent(ctx, r, true, "RevokeCertificate")) {
        if(r != UA_STATUSCODE_GOOD) {
            ga_not_tested(ctx, "setup: RevokeCertificate -> %s", UA_StatusCode_name(r));
        } else {
            drain(t, &w, 1);
            none_if_off(ctx, on, w.sink.hits);
            if(w.sink.hits < 1)
                ga_fail(ctx, "no CertificateRevoked event after a successful RevokeCertificate");
            else
                ga_pass(ctx, "CertificateRevoked event raised");
        }
    }
    unwatch(t, &w);
    UA_NodeId_clear(&id);
    gds_buf_free(&cert);
    gds_buf_free(&issuer);
}

/* Raised once after AddCertificate and once after RemoveCertificate */
static void t_trustlist_updated(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    bool on;
    if(!auditing(ctx, t, &on))
        return;
    ev_watch w;
    UA_StatusCode r = watch(t, UA_NODEID_NUMERIC(0, UA_NS0ID_TRUSTLISTUPDATEDAUDITEVENTTYPE), false, &w);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "event subscription -> %s", UA_StatusCode_name(r));
        return;
    }
    EVP_PKEY *k = EVP_RSA_gen(2048);
    gds_buf cert = {0};
    char uri[URI_LEN], tp[X509_THUMBPRINT_LEN];
    gt_unique_uri(t, uri, sizeof(uri));
    if(!k || gtl_make_cert(NULL, NULL, k, "OpenGDS Auditor TL event", uri, false, 7, &cert) != GDS_OK ||
       x509_thumbprint(&cert, tp) != GDS_OK) {
        ga_not_tested(ctx, "setup: test certificate");
    } else {
        UA_NodeId tl = gtl_default(t);
        r = gtl_add(t->client, tl, &cert, true);
        if(r == UA_STATUSCODE_GOOD)
            r = gtl_remove_thumb(t->client, tl, tp, true);
        if(r != UA_STATUSCODE_GOOD) {
            ga_not_tested(ctx, "setup: AddCertificate/RemoveCertificate -> %s",
                          UA_StatusCode_name(r));
        } else {
            drain(t, &w, 2);
            none_if_off(ctx, on, w.sink.hits);
            if(w.sink.hits != 2)
                ga_fail(ctx, "%zu TrustListUpdated event(s) for one Add and one Remove, "
                             "expected 2", w.sink.hits);
            else
                ga_pass(ctx, "one TrustListUpdated event per change");
        }
    }
    unwatch(t, &w);
    EVP_PKEY_free(k);
    gds_buf_free(&cert);
}

/* "Auditing is a Boolean specifying if the Server is currently generating
 * audit events" (OPC 10000-5 §6.3.1): a GDS raising them shows TRUE. */
static void t_auditing_flag(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    bool on;
    if(!auditing(ctx, t, &on))
        return;
    ev_watch w;
    UA_StatusCode r = watch(t, UA_NODEID_NUMERIC(0, UA_NS0ID_AUDITEVENTTYPE), false, &w);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "event subscription -> %s", UA_StatusCode_name(r));
        return;
    }
    char uri[URI_LEN];
    UA_NodeId id;
    r = gt_register(t, UA_APPLICATIONTYPE_CLIENT, uri, sizeof(uri), &id);
    UA_NodeId_clear(&id);
    if(r == UA_STATUSCODE_GOOD)
        drain(t, &w, 1);
    unwatch(t, &w);
    if(r != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup: RegisterApplication -> %s", UA_StatusCode_name(r));
    else if(!on && w.sink.hits > 0)
        ga_fail(ctx, "%zu audit event(s) raised while Server.Auditing is FALSE", w.sink.hits);
    else if(!on)
        ga_not_supported(ctx, "Server.Auditing FALSE and no audit event");
    else if(w.sink.hits == 0)
        ga_warn(ctx, "Server.Auditing TRUE but RegisterApplication raised no audit event");
    else
        ga_pass(ctx, "Server.Auditing TRUE and audit events raised");
}

/* CertificateGroupType's Optional CertificateExpired and TrustListOutOfDate
 * alarms: when present, of the standard types. */
static void t_group_alarms(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: session -> %s", UA_StatusCode_name(r));
        return;
    }
    const struct {
        const char *name;
        UA_UInt32 type;
    } al[] = {{"CertificateExpired", UA_NS0ID_CERTIFICATEEXPIRATIONALARMTYPE},
              {"TrustListOutOfDate", UA_NS0ID_TRUSTLISTOUTOFDATEALARMTYPE}};
    size_t present = 0;
    for(size_t i = 0; i < GDS_ARRAY_SIZE(al); i++) {
        UA_NodeId n;
        if(uac_find_child(t->client, gt_default_group(t), al[i].name, &n) != UA_STATUSCODE_GOOD)
            continue;
        present++;
        UA_BrowseDescription bd;
        UA_BrowseDescription_init(&bd);
        bd.nodeId = n;
        bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
        bd.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASTYPEDEFINITION);
        bd.resultMask = UA_BROWSERESULTMASK_NONE;
        UA_BrowseRequest req;
        UA_BrowseRequest_init(&req);
        req.nodesToBrowse = &bd;
        req.nodesToBrowseSize = 1;
        UA_BrowseResponse resp = UA_Client_Service_browse(t->client, req);
        UA_NodeId want = UA_NODEID_NUMERIC(0, al[i].type);
        bool ok = resp.resultsSize == 1 && resp.results[0].referencesSize == 1 &&
                  UA_NodeId_equal(&resp.results[0].references[0].nodeId.nodeId, &want);
        UA_BrowseResponse_clear(&resp);
        UA_NodeId_clear(&n);
        if(!ok) {
            ga_warn(ctx, "%s is not typed %s (a subtype is allowed; not checked)", al[i].name,
                    i == 0 ? "CertificateExpirationAlarmType" : "TrustListOutOfDateAlarmType");
            return;
        }
    }
    if(present == 0)
        ga_not_supported(ctx, "DefaultApplicationGroup has neither Optional alarm");
    else
        ga_pass(ctx, "%zu alarm(s) present with the standard type", present);
}

/* KeyCredential audit events (§8.5.9 - §8.5.11) with the ResourceUri of
 * KeyCredentialAuditEventType (§8.5.8). */
typedef struct {
    ev_watch req, del, rev;
    UA_String got[3]; /* the ResourceUri each watch saw */
} kc_watch;

static void kc_verdict_requested(ga_ctx *ctx, const kc_watch *w, const spec_kc_run *run) {
    if(w->req.sink.hits < 2)
        ga_fail(ctx, "%zu KeyCredentialRequested event(s) for one accepted and one refused "
                     "request, expected 2", w->req.sink.hits);
    else if(w->req.sink.good < 1 || w->req.sink.bad < 1)
        ga_fail(ctx, "KeyCredentialRequested Status should be TRUE once and FALSE once (%zu/%zu)",
                w->req.sink.good, w->req.sink.bad);
    else if(w->del.sink.hits < 1)
        ga_fail(ctx, "no KeyCredentialDelivered event after a successful FinishRequest");
    else if(!w->req.sink.strOk || !w->del.sink.strOk)
        ga_fail(ctx, "ResourceUri is not the service's ('%s')", run->resourceUri);
    else
        ga_pass(ctx, "Requested (accepted and refused) and Delivered with the ResourceUri");
}

static void kc_verdict_revoked(ga_ctx *ctx, const kc_watch *w, const spec_kc_run *run) {
    if(gt_absent(ctx, run->revoke, true, "Revoke"))
        return;
    if(run->revoke != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup: Revoke -> %s", UA_StatusCode_name(run->revoke));
    else if(w->rev.sink.hits < 1)
        ga_fail(ctx, "no KeyCredentialRevoked event after a successful Revoke");
    else if(!w->rev.sink.strOk)
        ga_fail(ctx, "ResourceUri is not the service's ('%s')", run->resourceUri);
    else
        ga_pass(ctx, "KeyCredentialRevoked raised with the ResourceUri");
}

static UA_StatusCode kc_watch_all(gds_target *t, kc_watch *w) {
    UA_QualifiedName qRes = UA_QUALIFIEDNAME(0, "ResourceUri");
    memset(w, 0, sizeof(*w));
    UA_StatusCode r = watch_field(t, gt_node(t, UA_GDSID_KEYCREDENTIALREQUESTEDAUDITEVENTTYPE),
                                  &qRes, &w->req);
    if(r == UA_STATUSCODE_GOOD)
        r = watch_field(t, gt_node(t, UA_GDSID_KEYCREDENTIALDELIVEREDAUDITEVENTTYPE), &qRes,
                        &w->del);
    if(r == UA_STATUSCODE_GOOD)
        r = watch_field(t, gt_node(t, UA_GDSID_KEYCREDENTIALREVOKEDAUDITEVENTTYPE), &qRes,
                        &w->rev);
    w->req.sink.wantStr = &w->got[0];
    w->del.sink.wantStr = &w->got[1];
    w->rev.sink.wantStr = &w->got[2];
    return r;
}

static void kc_unwatch_all(gds_target *t, kc_watch *w) {
    unwatch(t, &w->req);
    unwatch(t, &w->del);
    unwatch(t, &w->rev);
    for(size_t i = 0; i < 3; i++)
        UA_String_clear(&w->got[i]);
}

static void t_keycred(ga_ctx *ctx, gds_target *t, bool revoked) {
    bool on;
    if(!auditing(ctx, t, &on))
        return;
    kc_watch w;
    spec_kc_run run;
    UA_StatusCode r = kc_watch_all(t, &w);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "event subscriptions -> %s", UA_StatusCode_name(r));
    } else if(spec_kc_exercise(ctx, t, revoked, &run)) {
        drain(t, &w.req, 2);
        drain(t, &w.del, 1);
        if(revoked)
            drain(t, &w.rev, 1);
        UA_String res = UA_STRING(run.resourceUri);
        ev_watch *each[3] = {&w.req, &w.del, &w.rev};
        for(size_t i = 0; i < 3; i++)
            if(w.got[i].length && !UA_String_equal(&w.got[i], &res))
                each[i]->sink.strOk = false;
        ga_note(ctx, "refused StartRequest -> %s; Revoke -> %s", UA_StatusCode_name(run.refused),
                UA_StatusCode_name(run.revoke));
        none_if_off(ctx, on, w.req.sink.hits + w.del.sink.hits + w.rev.sink.hits);
        if(revoked)
            kc_verdict_revoked(ctx, &w, &run);
        else
            kc_verdict_requested(ctx, &w, &run);
    }
    kc_unwatch_all(t, &w);
}

static void t_keycred_requested_delivered(ga_ctx *ctx, void *p) {
    t_keycred(ctx, p, false);
}

static void t_keycred_revoked(ga_ctx *ctx, void *p) {
    t_keycred(ctx, p, true);
}

const ga_test spec_events_tests[] = {
    {"gds.ev.registration_changed", "12 §6.5.12", "Register and Unregister raise ApplicationRegistrationChanged audit events",
     true, false, t_registration_changed},
    {"gds.ev.certificate_requested_delivered", "12 §7.9.12, §7.9.13", "Signing requests raise CertificateRequested (accepted and refused) and CertificateDelivered",
     true, false, t_certificate_requested_delivered},
    {"gds.ev.certificate_revoked", "12 §7.9.6, §7.9.14", "RevokeCertificate raises CertificateRevoked",
     true, false, t_certificate_revoked},
    {"gds.ev.trustlist_updated", "12 §7.8.2.1", "AddCertificate and RemoveCertificate each raise one TrustListUpdated event",
     true, false, t_trustlist_updated},
    {"gds.ev.keycred_requested_delivered", "12 §8.5.8 - §8.5.10", "KeyCredential requests raise KeyCredentialRequested (accepted and refused) and KeyCredentialDelivered with the ResourceUri",
     true, false, t_keycred_requested_delivered},
    {"gds.ev.keycred_revoked", "12 §8.5.7, §8.5.11", "Revoke raises KeyCredentialRevoked with the ResourceUri",
     true, false, t_keycred_revoked},
    {"gds.ev.auditing_flag", "5 §6.3.1; 12 §6.5.12", "Server.Auditing is TRUE when the GDS raises audit events",
     true, false, t_auditing_flag},
    {"gds.ev.group_alarms", "12 §7.8.3.1", "CertificateGroup alarms, when present, have the standard types",
     false, false, t_group_alarms},
};
const size_t spec_events_count = GDS_ARRAY_SIZE(spec_events_tests);
