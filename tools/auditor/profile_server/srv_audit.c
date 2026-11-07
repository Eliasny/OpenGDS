/* OpenGDS Auditor server profile: audit events (srv_audit.c).
 * ConformanceUnit: Push Model for Global Certificate and TrustList Management.
 * Catalogue: docs/auditor/server-profile.md, "Audit events".
 *
 * A second admin session subscribes to the events of the Server Object
 * while the test makes the changes itself (the same calls as the tests the
 * catalogue names) and counts the audit events each change raises.
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>
#include <time.h>

#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include "srv_target.h"
#include "srv_tests.h"
#include "x509util.h"
#include "common/banned.h"

#define TLOBJ UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST
#define TLM(x) UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_##x
#define SETTLE_MS 1500  /* events of a change arrive within this */
#define APPLY_WAIT_MS 10000

static UA_NodeId ns0(UA_UInt32 id) {
    return UA_NODEID_NUMERIC(0, id);
}

static void nap_ms(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static bool same(const gds_buf *a, const gds_buf *b) {
    return a->len == b->len && a->len && memcmp(a->data, b->data, a->len) == 0;
}

/* ---------------- The event watcher ---------------- */

typedef struct {
    UA_Client *c;
    size_t tl, cert, certWrongSource, other;
} watcher;

/* The fields come in the order of the select clauses: EventType, SourceNode */
static void on_event(UA_Client *client, UA_UInt32 subId, void *subContext, UA_UInt32 monId,
                     void *monContext, const UA_KeyValueMap fields) {
    (void)client, (void)subId, (void)subContext, (void)monId;
    watcher *w = monContext;
    if(fields.mapSize < 2 || !UA_Variant_hasScalarType(&fields.map[0].value, &UA_TYPES[UA_TYPES_NODEID]))
        return;
    const UA_NodeId *type = fields.map[0].value.data;
    const UA_NodeId *src = UA_Variant_hasScalarType(&fields.map[1].value, &UA_TYPES[UA_TYPES_NODEID])
                               ? fields.map[1].value.data
                               : NULL;
    UA_NodeId sc = ns0(UA_NS0ID_SERVERCONFIGURATION);
    if(UA_NodeId_equal(type, &(UA_NodeId){0, UA_NODEIDTYPE_NUMERIC,
                                          {UA_NS0ID_TRUSTLISTUPDATEDAUDITEVENTTYPE}})) {
        w->tl++;
    } else if(UA_NodeId_equal(type, &(UA_NodeId){0, UA_NODEIDTYPE_NUMERIC,
                                                 {UA_NS0ID_CERTIFICATEUPDATEDAUDITEVENTTYPE}})) {
        w->cert++;
        if(!src || !UA_NodeId_equal(src, &sc))
            w->certWrongSource++;
    } else {
        w->other++;
    }
}

/* Pump the watcher's connection for ms (it reconnects after a certificate
 * change; the subscription stays on the server). */
static void pump(watcher *w, long ms) {
    for(long waited = 0; waited < ms; waited += 50)
        if(UA_Client_run_iterate(w->c, 50) != UA_STATUSCODE_GOOD)
            nap_ms(50);
}

/* After a certificate change the server closed the watcher's channel and
 * presents another certificate: open a new channel (GetEndpoints again) and
 * activate the same Session, so its subscription delivers what it queued. */
static UA_StatusCode rechannel(watcher *w, const char *url) {
    (void)UA_Client_disconnectSecureChannel(w->c);
    return UA_Client_connect(w->c, url);
}

typedef struct {
    bool done;
    UA_StatusCode r;
} apply_wait;

static void applied(UA_Client *client, void *userdata, UA_UInt32 requestId, UA_CallResponse *cr) {
    (void)client, (void)requestId;
    apply_wait *a = userdata;
    a->done = true;
    a->r = cr->responseHeader.serviceResult;
    if(a->r == UA_STATUSCODE_GOOD)
        a->r = cr->resultsSize == 1 ? cr->results[0].statusCode : UA_STATUSCODE_BADUNEXPECTEDERROR;
}

/* ApplyChanges on c while the watcher keeps reading, so it gets the events
 * the change raises before the server closes the channels (§7.10.9). */
static UA_StatusCode apply_watching(UA_Client *c, watcher *w) {
    apply_wait a = {false, UA_STATUSCODE_GOOD};
    UA_UInt32 id = 0;
    UA_StatusCode r = UA_Client_call_async(c, ns0(UA_NS0ID_SERVERCONFIGURATION),
                                           ns0(UA_NS0ID_SERVERCONFIGURATION_APPLYCHANGES), 0, NULL,
                                           applied, &a, &id);
    for(long waited = 0; r == UA_STATUSCODE_GOOD && !a.done && waited < APPLY_WAIT_MS; waited += 40) {
        if(UA_Client_run_iterate(c, 20) != UA_STATUSCODE_GOOD && !a.done)
            r = UA_STATUSCODE_BADCONNECTIONCLOSED;
        pump(w, 20);
    }
    if(r == UA_STATUSCODE_GOOD)
        r = a.done ? a.r : UA_STATUSCODE_BADTIMEOUT;
    pump(w, 300);
    return r;
}

static void counts_reset(watcher *w) {
    w->tl = w->cert = w->certWrongSource = w->other = 0;
}

static UA_StatusCode watch(srv_target *t, watcher *w) {
    memset(w, 0, sizeof(*w));
    UA_StatusCode r = st_admin_fresh(t, true, &w->c);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_CreateSubscriptionRequest sreq = UA_CreateSubscriptionRequest_default();
    sreq.requestedPublishingInterval = 100.0;
    UA_CreateSubscriptionResponse sres = UA_Client_Subscriptions_create(w->c, sreq, NULL, NULL, NULL);
    r = sres.responseHeader.serviceResult;
    UA_UInt32 subId = sres.subscriptionId;
    UA_CreateSubscriptionResponse_clear(&sres);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_SimpleAttributeOperand sel[2];
    UA_QualifiedName names[2] = {UA_QUALIFIEDNAME(0, "EventType"), UA_QUALIFIEDNAME(0, "SourceNode")};
    for(size_t i = 0; i < 2; i++) {
        UA_SimpleAttributeOperand_init(&sel[i]);
        sel[i].typeDefinitionId = ns0(UA_NS0ID_BASEEVENTTYPE);
        sel[i].browsePathSize = 1;
        sel[i].browsePath = &names[i];
        sel[i].attributeId = UA_ATTRIBUTEID_VALUE;
    }
    UA_EventFilter filter;
    UA_EventFilter_init(&filter);
    filter.selectClauses = sel;
    filter.selectClausesSize = 2;
    UA_MonitoredItemCreateRequest item;
    UA_MonitoredItemCreateRequest_init(&item);
    item.itemToMonitor.nodeId = ns0(UA_NS0ID_SERVER);
    item.itemToMonitor.attributeId = UA_ATTRIBUTEID_EVENTNOTIFIER;
    item.monitoringMode = UA_MONITORINGMODE_REPORTING;
    item.requestedParameters.samplingInterval = 0.0;
    item.requestedParameters.queueSize = 100;
    item.requestedParameters.discardOldest = false;
    UA_ExtensionObject_setValue(&item.requestedParameters.filter, &filter,
                                &UA_TYPES[UA_TYPES_EVENTFILTER]);
    UA_MonitoredItemCreateResult res =
        UA_Client_MonitoredItems_createEvent(w->c, subId, UA_TIMESTAMPSTORETURN_NEITHER, item, w,
                                             on_event, NULL);
    r = res.statusCode;
    UA_MonitoredItemCreateResult_clear(&res);
    return r;
}

static void unwatch(watcher *w) {
    st_client_free(w->c);
    w->c = NULL;
}

/* Server.Auditing (OPC 10000-5): the group is Not supported without it. */
static bool auditing(ga_ctx *ctx, srv_target *t) {
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode r = st_admin(t);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Client_readValueAttribute(t->client, ns0(UA_NS0ID_SERVER_AUDITING), &v);
    bool on = r == UA_STATUSCODE_GOOD && UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_BOOLEAN]) &&
              *(const UA_Boolean *)v.data;
    UA_Variant_clear(&v);
    if(r != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup: read Server.Auditing as admin -> %s", UA_StatusCode_name(r));
    else if(!on)
        ga_not_supported(ctx, "Server.Auditing is FALSE");
    return r == UA_STATUSCODE_GOOD && on;
}

static const char *how_many(size_t n) {
    return n == 0 ? "no" : "more than one";
}

/* ---------------- Tests ---------------- */

static UA_StatusCode call2(UA_Client *c, UA_UInt32 method, const UA_Variant *in) {
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = UA_Client_call(c, ns0(TLOBJ), ns0(method), 2, in, &outN, &out);
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

/* A self-signed certificate to add as trusted and remove again. */
static gds_status aud_peer(gds_buf *cert) {
    EVP_PKEY *k = EVP_RSA_gen(2048);
    gds_status gs = k ? st_make_leaf(NULL, k, "aud-peer", "urn:opengds:auditor:aud-peer", -3600,
                                     86400L, false, 0, cert)
                      : GDS_ECRYPTO;
    EVP_PKEY_free(k);
    ERR_clear_error();
    return gs;
}

/* SRV-AUD-01 (12 §7.8.2.13): one TrustListUpdatedAuditEventType per
 * completed trust list update: a write (CloseAndUpdate, ApplyChanges), an
 * AddCertificate and a RemoveCertificate. */
static void t_aud_trustlist(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!auditing(ctx, t))
        return;
    UA_StatusCode r = st_snapshot(t, ctx);
    watcher w = {0};
    if(r == UA_STATUSCODE_GOOD)
        r = watch(t, &w);
    if(r != UA_STATUSCODE_GOOD) {
        unwatch(&w);
        ga_not_tested(ctx, "setup: snapshot and event subscription -> %s", UA_StatusCode_name(r));
        return;
    }
    pump(&w, 300);
    counts_reset(&w);
    /* 1. the applied list written back */
    UA_TrustListDataType l;
    UA_TrustListDataType_init(&l);
    bool acr = false;
    r = st_admin(t);
    if(r == UA_STATUSCODE_GOOD)
        r = st_read_trustlist(t->client, ST_MASK_ALL, &l);
    if(r == UA_STATUSCODE_GOOD) {
        l.specifiedLists = ST_MASK_ALL;
        r = st_write_trustlist(t->client, &l, 16384, &acr, ctx);
    }
    UA_TrustListDataType_clear(&l);
    if(r == UA_STATUSCODE_GOOD && acr)
        r = st_apply(t->client);
    if(r != UA_STATUSCODE_GOOD) {
        unwatch(&w);
        ga_not_tested(ctx, "setup: write the trust list back and apply -> %s (SRV-TL-02 checks it)",
                      UA_StatusCode_name(r));
        return;
    }
    pump(&w, SETTLE_MS);
    size_t write = w.tl;
    counts_reset(&w);
    /* 2. AddCertificate and RemoveCertificate */
    gds_buf peer = {0};
    size_t add = 0, rem = 0;
    bool addDone = false;
    if(aud_peer(&peer) == GDS_OK) {
        UA_ByteString b = {peer.len, peer.data};
        UA_Boolean trusted = true;
        UA_Variant in[2];
        UA_Variant_setScalar(&in[0], &b, &UA_TYPES[UA_TYPES_BYTESTRING]);
        UA_Variant_setScalar(&in[1], &trusted, &UA_TYPES[UA_TYPES_BOOLEAN]);
        UA_StatusCode ra = call2(t->client, TLM(ADDCERTIFICATE), in);
        pump(&w, SETTLE_MS);
        add = w.tl;
        counts_reset(&w);
        char tp[X509_THUMBPRINT_LEN] = "";
        UA_StatusCode rr = UA_STATUSCODE_BADNOTHINGTODO;
        if(ra == UA_STATUSCODE_GOOD && x509_thumbprint(&peer, tp) == GDS_OK) {
            UA_String thumb = UA_STRING(tp);
            UA_Variant_setScalar(&in[0], &thumb, &UA_TYPES[UA_TYPES_STRING]);
            rr = call2(t->client, TLM(REMOVECERTIFICATE), in);
            pump(&w, SETTLE_MS);
            rem = w.tl;
        }
        ga_note(ctx, "AddCertificate -> %s, RemoveCertificate -> %s", UA_StatusCode_name(ra),
                UA_StatusCode_name(rr));
        addDone = ra == UA_STATUSCODE_GOOD && rr == UA_STATUSCODE_GOOD;
    }
    gds_buf_free(&peer);
    unwatch(&w);
    ga_note(ctx, "TrustListUpdatedAuditEventType: write %zu, add %zu, remove %zu", write, add, rem);
    bool ok = write == 1 && (!addDone || (add == 1 && rem == 1));
    if(ok)
        ga_pass(ctx, "one TrustListUpdatedAuditEventType per update (write%s)",
                addDone ? ", AddCertificate, RemoveCertificate" : "; Add/RemoveCertificate not done");
    else
        ga_fail(ctx, "TrustListUpdatedAuditEventType: %zu for the write, %zu for AddCertificate, "
                     "%zu for RemoveCertificate (one each expected)",
                write, add, rem);
}

/* SRV-AUD-02 (12 §7.10.27): one CertificateUpdatedAuditEventType per
 * changed certificate, with SourceNode the ServerConfiguration Object, and
 * none for a failed UpdateCertificate. */
static void t_aud_cert(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!auditing(ctx, t))
        return;
    if(!t->applied) {
        ga_not_tested(ctx, "builds on SRV-TXN-03 (the test CA trusted, t-good in use)");
        return;
    }
    watcher w = {0};
    UA_StatusCode r = watch(t, &w);
    if(r != UA_STATUSCODE_GOOD) {
        unwatch(&w);
        ga_not_tested(ctx, "setup: event subscription -> %s", UA_StatusCode_name(r));
        return;
    }
    pump(&w, 300);
    counts_reset(&w);
    /* 1. a failing call: a certificate for a key the target does not hold */
    gds_buf wrong = {0}, good = {0}, csr = {0};
    EVP_PKEY *k = EVP_RSA_gen(2048);
    gds_status gs = k ? st_make_leaf(&t->ca, k, "t-aud-wrongkey", t->targetUri, -3600, 86400L,
                                     false, 0, &wrong)
                      : GDS_ECRYPTO;
    EVP_PKEY_free(k);
    ERR_clear_error();
    bool acr = false;
    UA_StatusCode bad = gds_status_to_ua(gs);
    if(bad == UA_STATUSCODE_GOOD && (bad = st_admin(t)) == UA_STATUSCODE_GOOD)
        bad = st_update_cert(t, t->client, &wrong, &t->caDer, 1, &acr);
    gds_buf_free(&wrong);
    if(bad == UA_STATUSCODE_GOOD) { /* accepted: SRV-UPD-02 fails it; undo */
        st_close(t);
        unwatch(&w);
        ga_not_tested(ctx, "UpdateCertificate accepted t-aud-wrongkey (SRV-UPD-02 checks it)");
        return;
    }
    pump(&w, SETTLE_MS);
    size_t onFailure = w.cert;
    counts_reset(&w);
    /* 2. a new certificate for the target's key, applied */
    r = st_admin(t);
    if(r == UA_STATUSCODE_GOOD)
        r = st_csr(t, t->client, false, NULL, &csr);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_status_to_ua(testca_sign_csr(&t->ca, &csr, t->targetUri, TESTCA_MAX_DAYS, &good));
    gds_buf_free(&csr);
    if(r == UA_STATUSCODE_GOOD)
        r = st_update_cert(t, t->client, &good, &t->caDer, 1, &acr);
    if(r == UA_STATUSCODE_GOOD && acr)
        r = apply_watching(t->client, &w);
    st_close(t); /* the certificate change closes the channels (§7.10.9) */
    ga_note(ctx, "UpdateCertificate(t-aud-wrongkey) -> %s; t-aud-02 UpdateCertificate and "
                 "ApplyChanges -> %s",
            UA_StatusCode_name(bad), UA_StatusCode_name(r));
    if(r != UA_STATUSCODE_GOOD) {
        gds_buf_free(&good);
        unwatch(&w);
        ga_not_tested(ctx, "setup: put t-aud-02 in use -> %s (SRV-TXN-03 checks it)",
                      UA_StatusCode_name(r));
        return;
    }
    gds_buf now = {0};
    for(long waited = 0;; waited += 200) {
        gds_buf_free(&now);
        UA_StatusCode pr = st_presented(t, &now);
        if((pr == UA_STATUSCODE_GOOD && same(&now, &good)) || waited >= APPLY_WAIT_MS)
            break;
        pump(&w, 200);
    }
    bool inUse = same(&now, &good);
    gds_buf_free(&now);
    if(inUse) { /* the target's certificate from here on */
        gds_buf_free(&t->tGood);
        t->tGood = good;
        good = (gds_buf){0};
    }
    gds_buf_free(&good);
    pump(&w, 200);
    UA_StatusCode rc = rechannel(&w, t->url);
    ga_note(ctx, "event session on a new channel -> %s", UA_StatusCode_name(rc));
    for(long waited = 0; waited < APPLY_WAIT_MS && w.cert == 0; waited += 200)
        pump(&w, 200);
    pump(&w, SETTLE_MS);
    size_t changed = w.cert, wrongSource = w.certWrongSource;
    unwatch(&w);
    ga_note(ctx, "CertificateUpdatedAuditEventType: failed call %zu, change %zu (SourceNode not "
                 "ServerConfiguration: %zu)",
            onFailure, changed, wrongSource);
    if(!inUse)
        ga_not_tested(ctx, "t-aud-02 is not presented after ApplyChanges (SRV-TXN-03 checks it)");
    else if(onFailure)
        ga_fail(ctx, "a CertificateUpdatedAuditEventType for the failed UpdateCertificate");
    else if(changed != 1)
        ga_fail(ctx, "%s CertificateUpdatedAuditEventType for one changed certificate",
                how_many(changed));
    else if(wrongSource)
        ga_fail(ctx, "the CertificateUpdatedAuditEventType's SourceNode is not ServerConfiguration");
    else
        ga_pass(ctx, "one CertificateUpdatedAuditEventType from ServerConfiguration; none for the "
                     "failed call");
}

const ga_test srv_audit_tests[] = {
    {"SRV-AUD-01", "12 §7.8.2.1, §7.8.2.13", "One TrustListUpdatedAuditEventType per update", true,
     false, t_aud_trustlist},
    {"SRV-AUD-02", "12 §7.10.27", "One CertificateUpdatedAuditEventType per changed certificate",
     true, false, t_aud_cert},
};
const size_t srv_audit_count = GDS_ARRAY_SIZE(srv_audit_tests);
