/* THROWAWAY SPIKE (week 1): DialogConditionType approvals on open62541 v1.5.10.
 * Not production code. Findings: docs/spikes/01-dialog-condition-approvals.md
 * SPDX-License-Identifier: MPL-2.0
 *
 * One process: the server runs in a thread, a client in main() subscribes to
 * events on the Server object, runs ConditionRefresh, and answers pending
 * approvals with Respond2 (Part 9 §5.6.4). Each step prints PASS/FAIL. */
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>
#include <open62541/plugin/log_stdout.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PORT 48410
static int failures;
#define CHECK(cond, ...) do { int ok_ = !!(cond); if(!ok_) failures++; \
    printf("%s  ", ok_ ? "PASS" : "FAIL"); printf(__VA_ARGS__); printf("\n"); } while(0)

/* ------------------------------------------------------------------ server */

enum { RESP_APPROVE = 0, RESP_REJECT = 1 };
typedef enum { PENDING, APPROVED, REJECTED } ApprovalState;

typedef struct {
    UA_NodeId condition;
    ApprovalState state;
    char requestId[40];
    UA_String decidedBy;      /* session's user, for the audit trail */
    UA_LocalizedText comment;
} Approval;

#define MAX_APPROVALS 2048
static Approval approvals[MAX_APPROVALS];
static size_t approvalCount;
static UA_NodeId approvalsSource;   /* "Approvals" object, condition source */
static UA_Server *server;
static volatile UA_Boolean running = true;
static unsigned auditEventsEmitted;

static UA_StatusCode
setField(const UA_NodeId cond, const char *field, const void *v, const UA_DataType *t) {
    UA_Variant var;
    UA_Variant_setScalar(&var, (void*)(uintptr_t)v, t);
    return UA_Server_setConditionField(server, cond, &var, UA_QUALIFIEDNAME(0, (char*)(uintptr_t)field));
}

/* UA_Server_setConditionField refuses arrays in v1.5.10 (BadNotImplemented,
 * "TODO implement logic for array variants"). ResponseOptionSet is an array:
 * resolve the field node and write it directly. */
static UA_StatusCode
setFieldArray(const UA_NodeId cond, const char *field, const void *v, size_t n,
              const UA_DataType *t) {
    UA_Variant var;
    UA_Variant_setArray(&var, (void*)(uintptr_t)v, n, t);
    UA_QualifiedName qn = UA_QUALIFIEDNAME(0, (char*)(uintptr_t)field);
    UA_BrowsePathResult bpr = UA_Server_browseSimplifiedBrowsePath(server, cond, 1, &qn);
    UA_StatusCode rv = bpr.statusCode;
    if(rv == UA_STATUSCODE_GOOD)
        rv = UA_Server_writeValue(server, bpr.targets[0].targetId.nodeId, var);
    UA_BrowsePathResult_clear(&bpr);
    return rv;
}

static UA_StatusCode
setTwoState(const UA_NodeId cond, const char *field, UA_Boolean id,
            const char *text) {
    UA_LocalizedText lt = UA_LOCALIZEDTEXT("en", (char*)(uintptr_t)text);
    UA_StatusCode rv = setField(cond, field, &lt, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    UA_Variant var;
    UA_Variant_setScalar(&var, &id, &UA_TYPES[UA_TYPES_BOOLEAN]);
    rv |= UA_Server_setConditionVariableFieldProperty(server, cond, &var,
              UA_QUALIFIEDNAME(0, (char*)(uintptr_t)field), UA_QUALIFIEDNAME(0, "Id"));
    return rv;
}

/* Raise one approval dialog for a pending certificate request. */
static UA_StatusCode
raiseApproval(const char *requestId, const char *applicationUri, UA_NodeId *out) {
    if(approvalCount >= MAX_APPROVALS)
        return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
    Approval *a = &approvals[approvalCount];
    memset(a, 0, sizeof(*a));
    snprintf(a->requestId, sizeof(a->requestId), "%s", requestId);

    char name[64];
    snprintf(name, sizeof(name), "Approve-%s", requestId);
    UA_StatusCode rv = UA_Server_createCondition(server, UA_NODEID_NUMERIC(1, 0),
        UA_NS0ID(DIALOGCONDITIONTYPE), UA_QUALIFIEDNAME(1, name), approvalsSource,
        UA_NS0ID(HASCOMPONENT), &a->condition);
    if(rv != UA_STATUSCODE_GOOD)
        return rv;

    /* Respond2 is Optional on DialogConditionType (ModellingRule i=80), so the
     * instance does not reference it and Call fails BadMethodInvalid.
     * UA_Server_addConditionOptionalField does not do methods (TODO upstream).
     * Reference the type's method node from the instance by hand. */
    rv = UA_Server_addReference(server, a->condition, UA_NS0ID(HASCOMPONENT),
                                UA_EXPANDEDNODEID_NUMERIC(0, UA_NS0ID_DIALOGCONDITIONTYPE_RESPOND2),
                                true);
    if(rv != UA_STATUSCODE_GOOD)
        return rv;

    UA_Server_setNodeContext(server, a->condition, a);

    char msg[200];
    snprintf(msg, sizeof(msg), "Certificate request %s from %s awaits approval",
             requestId, applicationUri);
    UA_LocalizedText message = UA_LOCALIZEDTEXT("en", msg);
    UA_LocalizedText prompt = UA_LOCALIZEDTEXT("en", "Issue a certificate for this application?");
    UA_LocalizedText options[2] = {UA_LOCALIZEDTEXT("en", "Approve"),
                                   UA_LOCALIZEDTEXT("en", "Reject")};
    UA_Int32 def = -1, ok = RESP_APPROVE, cancel = RESP_REJECT, last = -1;
    UA_UInt16 severity = 500;
    UA_Boolean retain = true;
    rv |= setField(a->condition, "Message", &message, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    rv |= setField(a->condition, "Severity", &severity, &UA_TYPES[UA_TYPES_UINT16]);
    rv |= setField(a->condition, "Prompt", &prompt, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    rv |= setFieldArray(a->condition, "ResponseOptionSet", options, 2, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    rv |= setField(a->condition, "DefaultResponse", &def, &UA_TYPES[UA_TYPES_INT32]);
    rv |= setField(a->condition, "OkResponse", &ok, &UA_TYPES[UA_TYPES_INT32]);
    rv |= setField(a->condition, "CancelResponse", &cancel, &UA_TYPES[UA_TYPES_INT32]);
    rv |= setField(a->condition, "LastResponse", &last, &UA_TYPES[UA_TYPES_INT32]);
    rv |= setTwoState(a->condition, "DialogState", true, "Active");
    rv |= setTwoState(a->condition, "EnabledState", true, "Enabled");
    rv |= setField(a->condition, "Retain", &retain, &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(rv != UA_STATUSCODE_GOOD)
        return rv;

    approvalCount++;
    if(out)
        UA_NodeId_copy(&a->condition, out);
    return UA_Server_triggerConditionEvent(server, a->condition, approvalsSource, NULL);
}

/* AuditConditionRespondEventType (Part 9), AlwaysGeneratesEvent of
 * Respond2. v1.5.10 can emit it from a key-value map, no instance node. */
static void
emitRespondAudit(const UA_NodeId *sessionId, const Approval *a, UA_Int32 resp,
                 UA_Boolean status) {
    UA_KeyValuePair kv[5];
    UA_NodeId methodId = UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND2);
    UA_String clientUser = a->decidedBy;
    UA_Variant_setScalar(&kv[0].value, &status, &UA_TYPES[UA_TYPES_BOOLEAN]);
    kv[0].key = UA_QUALIFIEDNAME(0, "/Status");
    UA_Variant_setScalar(&kv[1].value, &resp, &UA_TYPES[UA_TYPES_INT32]);
    kv[1].key = UA_QUALIFIEDNAME(0, "/SelectedResponse");
    UA_Variant_setScalar(&kv[2].value, &methodId, &UA_TYPES[UA_TYPES_NODEID]);
    kv[2].key = UA_QUALIFIEDNAME(0, "/MethodId");
    UA_Variant_setScalar(&kv[3].value, &clientUser, &UA_TYPES[UA_TYPES_STRING]);
    kv[3].key = UA_QUALIFIEDNAME(0, "/ClientUserId");
    UA_DateTime now = UA_DateTime_now();
    UA_Variant_setScalar(&kv[4].value, &now, &UA_TYPES[UA_TYPES_DATETIME]);
    kv[4].key = UA_QUALIFIEDNAME(0, "/ActionTimeStamp");
    (void)sessionId; /* ClientAuditEntryId (String) comes from the request header in OpenGDS */
    UA_KeyValueMap map = {5, kv};
    UA_LocalizedText msg = UA_LOCALIZEDTEXT("en", "Respond2 on approval dialog");
    UA_StatusCode rv = UA_Server_createEvent(server, a->condition,
        UA_NS0ID(AUDITCONDITIONRESPONDEVENTTYPE), 100, msg, &map, NULL, NULL);
    if(rv == UA_STATUSCODE_GOOD)
        auditEventsEmitted++;
    else
        printf("INFO  audit event failed: %s\n", UA_StatusCode_name(rv));
}

static UA_StatusCode
respond2Callback(UA_Server *s, const UA_NodeId *sessionId, void *sessionContext,
                 const UA_NodeId *methodId, void *methodContext,
                 const UA_NodeId *objectId, void *objectContext,
                 size_t inputSize, const UA_Variant *input,
                 size_t outputSize, UA_Variant *output) {
    (void)s; (void)sessionContext; (void)methodId; (void)methodContext;
    (void)output; (void)outputSize;
    /* Arguments are type-checked by the stack against InputArguments. */
    if(inputSize != 2)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    Approval *a = (Approval*)objectContext;
    if(!a || !UA_NodeId_equal(&a->condition, objectId))
        return UA_STATUSCODE_BADNODEIDUNKNOWN; /* method called on a non-approval */
    if(a->state != PENDING)
        return UA_STATUSCODE_BADDIALOGNOTACTIVE;
    UA_Int32 resp = *(UA_Int32*)input[0].data;
    const UA_LocalizedText *comment = (const UA_LocalizedText*)input[1].data;
    if(resp != RESP_APPROVE && resp != RESP_REJECT)
        return UA_STATUSCODE_BADDIALOGRESPONSEINVALID;

    /* In OpenGDS the decision goes to the store first (one transaction), and
     * only then to the address space and events. Here: memory only. */
    a->state = (resp == RESP_APPROVE) ? APPROVED : REJECTED;
    UA_LocalizedText_copy(comment, &a->comment);
    char who[64];
    snprintf(who, sizeof(who), "session %u", sessionId->identifier.numeric);
    a->decidedBy = UA_STRING_ALLOC(who);

    UA_Boolean retain = false;
    UA_String user = a->decidedBy;
    UA_StatusCode rv = UA_STATUSCODE_GOOD;
    rv |= setField(a->condition, "LastResponse", &resp, &UA_TYPES[UA_TYPES_INT32]);
    rv |= setTwoState(a->condition, "DialogState", false, "Inactive");
    rv |= setField(a->condition, "Comment", comment, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    rv |= setField(a->condition, "ClientUserId", &user, &UA_TYPES[UA_TYPES_STRING]);
    rv |= setField(a->condition, "Retain", &retain, &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(rv != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINTERNALERROR;
    rv = UA_Server_triggerConditionEvent(s, a->condition, approvalsSource, NULL);
    emitRespondAudit(sessionId, a, resp, rv == UA_STATUSCODE_GOOD);
    return rv;
}

/* Role gate: in OpenGDS only RegistrationAuthorityAdmin / DiscoveryAdmin
 * may answer. The spike denies execution when denyRespond is set. */
static volatile UA_Boolean denyRespond;
static UA_Boolean (*origExecOnObject)(UA_Server *, UA_AccessControl *, const UA_NodeId *,
                                      void *, const UA_NodeId *, void *,
                                      const UA_NodeId *, void *);
static UA_Boolean
execOnObject(UA_Server *s, UA_AccessControl *ac, const UA_NodeId *sessionId,
             void *sessionContext, const UA_NodeId *methodId, void *methodContext,
             const UA_NodeId *objectId, void *objectContext) {
    UA_NodeId r2 = UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND2);
    if(denyRespond && UA_NodeId_equal(methodId, &r2))
        return false;
    return origExecOnObject(s, ac, sessionId, sessionContext, methodId, methodContext,
                            objectId, objectContext);
}

static void *
serverThread(void *arg) {
    (void)arg;
    UA_Server_run(server, &running);
    return NULL;
}

static void
startServer(void) {
    server = UA_Server_new();
    UA_ServerConfig *cfg = UA_Server_getConfig(server);
    UA_ServerConfig_setMinimal(cfg, PORT, NULL);

    origExecOnObject = cfg->accessControl.getUserExecutableOnObject;
    cfg->accessControl.getUserExecutableOnObject = execOnObject;
    if(getenv("QUEUE_MAX"))
        cfg->queueSizeLimits.max = (UA_UInt32)atoi(getenv("QUEUE_MAX"));

    UA_ObjectAttributes oa = UA_ObjectAttributes_default;
    oa.displayName = UA_LOCALIZEDTEXT("en", "Approvals");
    oa.eventNotifier = UA_EVENTNOTIFIER_SUBSCRIBE_TO_EVENT;
    UA_Server_addObjectNode(server, UA_NODEID_STRING(1, "Approvals"),
        UA_NS0ID(OBJECTSFOLDER), UA_NS0ID(ORGANIZES), UA_QUALIFIEDNAME(1, "Approvals"),
        UA_NS0ID(BASEOBJECTTYPE), oa, NULL, &approvalsSource);
    UA_Server_addReference(server, UA_NS0ID(SERVER), UA_NS0ID(HASNOTIFIER),
        UA_EXPANDEDNODEID_STRING(1, "Approvals"), true);

    /* Respond2 is one method node shared by every DialogCondition instance:
     * one callback, dispatch on objectId / objectContext. */
    UA_StatusCode rv = UA_Server_setMethodNodeCallback(server,
        UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND2), respond2Callback);
    CHECK(rv == UA_STATUSCODE_GOOD, "server: callback bound to DialogConditionType.Respond2 (%s)",
          UA_StatusCode_name(rv));
}

/* ------------------------------------------------------------------ client */

enum { F_EVENTID, F_EVENTTYPE, F_MESSAGE, F_CONDID, F_RETAIN, F_DIALOGSTATE_ID,
       F_PROMPT, F_LASTRESPONSE, F_COMMENT, F_OPTIONS, F_COUNT };

typedef struct {
    UA_NodeId eventType;
    UA_NodeId condition;
    UA_Boolean retain;
    UA_Boolean dialogActive;
    UA_Int32 lastResponse;
    UA_Boolean hasDialogFields;
    size_t optionCount;
} SeenEvent;

static SeenEvent seen[16384];
static size_t seenCount;

static void
onEvent(UA_Client *c, UA_UInt32 subId, void *subCtx, UA_UInt32 monId, void *monCtx,
        const UA_KeyValueMap fields) {
    (void)c; (void)subId; (void)subCtx; (void)monId; (void)monCtx;
    /* v1.5 hands the select-clause results over as a key-value map, in
     * select-clause order. */
    if(fields.mapSize != F_COUNT || seenCount >= 16384)
        return;
    UA_Variant f[F_COUNT];
    for(size_t i = 0; i < F_COUNT; i++)
        f[i] = fields.map[i].value;
    SeenEvent *e = &seen[seenCount++];
    memset(e, 0, sizeof(*e));
    if(UA_Variant_hasScalarType(&f[F_EVENTTYPE], &UA_TYPES[UA_TYPES_NODEID]))
        UA_NodeId_copy((UA_NodeId*)f[F_EVENTTYPE].data, &e->eventType);
    if(UA_Variant_hasScalarType(&f[F_CONDID], &UA_TYPES[UA_TYPES_NODEID]))
        UA_NodeId_copy((UA_NodeId*)f[F_CONDID].data, &e->condition);
    if(UA_Variant_hasScalarType(&f[F_RETAIN], &UA_TYPES[UA_TYPES_BOOLEAN]))
        e->retain = *(UA_Boolean*)f[F_RETAIN].data;
    if(UA_Variant_hasScalarType(&f[F_DIALOGSTATE_ID], &UA_TYPES[UA_TYPES_BOOLEAN])) {
        e->dialogActive = *(UA_Boolean*)f[F_DIALOGSTATE_ID].data;
        e->hasDialogFields = true;
    }
    e->lastResponse = UA_Variant_hasScalarType(&f[F_LASTRESPONSE], &UA_TYPES[UA_TYPES_INT32]) ?
        *(UA_Int32*)f[F_LASTRESPONSE].data : -99;
    if(f[F_OPTIONS].type == &UA_TYPES[UA_TYPES_LOCALIZEDTEXT])
        e->optionCount = f[F_OPTIONS].arrayLength;
}

static void
pump(UA_Client *c, int ms) {
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        UA_Client_run_iterate(c, 20);
        clock_gettime(CLOCK_MONOTONIC, &t1);
    } while((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000 < ms);
}

static size_t
countDialogEvents(size_t from, UA_Boolean active, UA_Boolean retain) {
    size_t n = 0;
    UA_NodeId dct = UA_NS0ID(DIALOGCONDITIONTYPE);
    for(size_t i = from; i < seenCount; i++)
        if(UA_NodeId_equal(&seen[i].eventType, &dct) && seen[i].hasDialogFields &&
           seen[i].dialogActive == active && seen[i].retain == retain)
            n++;
    return n;
}

static size_t
countType(size_t from, UA_UInt32 ns0type) {
    size_t n = 0;
    UA_NodeId t = UA_NODEID_NUMERIC(0, ns0type);
    for(size_t i = from; i < seenCount; i++)
        if(UA_NodeId_equal(&seen[i].eventType, &t))
            n++;
    return n;
}

static UA_StatusCode
callRespond2(UA_Client *c, const UA_NodeId cond, UA_Int32 resp, const char *text) {
    UA_Variant in[2];
    UA_LocalizedText comment = UA_LOCALIZEDTEXT("en", (char*)(uintptr_t)text);
    UA_Variant_setScalar(&in[0], &resp, &UA_TYPES[UA_TYPES_INT32]);
    UA_Variant_setScalar(&in[1], &comment, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    size_t outSize = 0; UA_Variant *out = NULL;
    UA_StatusCode rv = UA_Client_call(c, cond, UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND2),
                                      2, in, &outSize, &out);
    UA_Array_delete(out, outSize, &UA_TYPES[UA_TYPES_VARIANT]);
    return rv;
}

static UA_StatusCode
conditionRefresh(UA_Client *c, UA_UInt32 subId) {
    UA_Variant in;
    UA_Variant_setScalar(&in, &subId, &UA_TYPES[UA_TYPES_UINT32]);
    size_t outSize = 0; UA_Variant *out = NULL;
    return UA_Client_call(c, UA_NS0ID(CONDITIONTYPE), UA_NS0ID(CONDITIONTYPE_CONDITIONREFRESH),
                          1, &in, &outSize, &out);
}

static void
setSao(UA_SimpleAttributeOperand *s, UA_UInt32 typeDef, const char *path,
       UA_UInt32 attr) {
    UA_SimpleAttributeOperand_init(s);
    s->typeDefinitionId = UA_NODEID_NUMERIC(0, typeDef);
    s->attributeId = attr;
    if(!path) return;
    /* path is "A" or "A/B" */
    char buf[64]; snprintf(buf, sizeof(buf), "%s", path);
    char *slash = strchr(buf, '/');
    s->browsePathSize = slash ? 2 : 1;
    s->browsePath = (UA_QualifiedName*)UA_Array_new(s->browsePathSize, &UA_TYPES[UA_TYPES_QUALIFIEDNAME]);
    if(slash) *slash = 0;
    s->browsePath[0] = UA_QUALIFIEDNAME_ALLOC(0, buf);
    if(slash) s->browsePath[1] = UA_QUALIFIEDNAME_ALLOC(0, slash + 1);
}

static double
msSince(const struct timespec *t0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (double)(t1.tv_sec - t0->tv_sec) * 1e3 + (double)(t1.tv_nsec - t0->tv_nsec) / 1e6;
}

int
main(int argc, char **argv) {
    size_t bulk = (argc > 1) ? (size_t)atoi(argv[1]) : 1000;
    if(bulk > MAX_APPROVALS - 8) bulk = MAX_APPROVALS - 8;
    startServer();

    /* Two approvals exist before any client connects. */
    UA_NodeId c1, c2;
    UA_StatusCode rv = raiseApproval("REQ-1", "urn:example:plc1", &c1);
    CHECK(rv == UA_STATUSCODE_GOOD, "server: DialogConditionType instance created and triggered (%s)",
          UA_StatusCode_name(rv));
    rv = raiseApproval("REQ-2", "urn:example:hmi2", &c2);
    CHECK(rv == UA_STATUSCODE_GOOD, "server: second instance (%s)", UA_StatusCode_name(rv));

    pthread_t th;
    pthread_create(&th, NULL, serverThread, NULL);

    UA_Client *client = UA_Client_new();
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    UA_ClientConfig_setDefault(cc);
    char url[64]; snprintf(url, sizeof(url), "opc.tcp://localhost:%d", PORT);
    for(int i = 0; i < 50 && UA_Client_connect(client, url) != UA_STATUSCODE_GOOD; i++)
        pump(client, 50);

    /* Event subscription on the Server object. */
    UA_CreateSubscriptionRequest sreq = UA_CreateSubscriptionRequest_default();
    sreq.requestedPublishingInterval = 50;
    UA_CreateSubscriptionResponse sresp =
        UA_Client_Subscriptions_create(client, sreq, NULL, NULL, NULL);
    UA_UInt32 subId = sresp.subscriptionId;
    CHECK(sresp.responseHeader.serviceResult == UA_STATUSCODE_GOOD, "client: subscription created");

    UA_SimpleAttributeOperand sel[F_COUNT];
    setSao(&sel[F_EVENTID], UA_NS0ID_BASEEVENTTYPE, "EventId", UA_ATTRIBUTEID_VALUE);
    setSao(&sel[F_EVENTTYPE], UA_NS0ID_BASEEVENTTYPE, "EventType", UA_ATTRIBUTEID_VALUE);
    setSao(&sel[F_MESSAGE], UA_NS0ID_BASEEVENTTYPE, "Message", UA_ATTRIBUTEID_VALUE);
    setSao(&sel[F_CONDID], UA_NS0ID_CONDITIONTYPE, NULL, UA_ATTRIBUTEID_NODEID);
    setSao(&sel[F_RETAIN], UA_NS0ID_CONDITIONTYPE, "Retain", UA_ATTRIBUTEID_VALUE);
    setSao(&sel[F_DIALOGSTATE_ID], UA_NS0ID_DIALOGCONDITIONTYPE, "DialogState/Id", UA_ATTRIBUTEID_VALUE);
    setSao(&sel[F_PROMPT], UA_NS0ID_DIALOGCONDITIONTYPE, "Prompt", UA_ATTRIBUTEID_VALUE);
    setSao(&sel[F_LASTRESPONSE], UA_NS0ID_DIALOGCONDITIONTYPE, "LastResponse", UA_ATTRIBUTEID_VALUE);
    setSao(&sel[F_COMMENT], UA_NS0ID_CONDITIONTYPE, "Comment", UA_ATTRIBUTEID_VALUE);
    setSao(&sel[F_OPTIONS], UA_NS0ID_DIALOGCONDITIONTYPE, "ResponseOptionSet", UA_ATTRIBUTEID_VALUE);

    UA_EventFilter filter;
    UA_EventFilter_init(&filter);
    filter.selectClauses = sel;
    filter.selectClausesSize = F_COUNT;
    UA_MonitoredItemCreateRequest item = UA_MonitoredItemCreateRequest_default(UA_NS0ID(SERVER));
    item.itemToMonitor.attributeId = UA_ATTRIBUTEID_EVENTNOTIFIER;
    item.monitoringMode = UA_MONITORINGMODE_REPORTING;
    UA_ExtensionObject_setValue(&item.requestedParameters.filter, &filter,
                                &UA_TYPES[UA_TYPES_EVENTFILTER]);
    item.requestedParameters.queueSize = 10000;
    UA_MonitoredItemCreateResult mres =
        UA_Client_MonitoredItems_createEvent(client, subId, UA_TIMESTAMPSTORETURN_BOTH,
                                             item, NULL, onEvent, NULL);
    CHECK(mres.statusCode == UA_STATUSCODE_GOOD, "client: event monitored item on Server (%s)",
          UA_StatusCode_name(mres.statusCode));
    printf("INFO  requested queue size 10000, revised to %u\n", mres.revisedQueueSize);
    pump(client, 200);

    /* 1. Pending dialogs raised before the client connected are only visible
     *    through ConditionRefresh. */
    size_t mark = seenCount;
    rv = conditionRefresh(client, subId);
    pump(client, 300);
    CHECK(rv == UA_STATUSCODE_GOOD, "client: ConditionRefresh call (%s)", UA_StatusCode_name(rv));
    CHECK(countType(mark, UA_NS0ID_REFRESHSTARTEVENTTYPE) == 1 &&
          countType(mark, UA_NS0ID_REFRESHENDEVENTTYPE) == 1,
          "refresh: RefreshStart and RefreshEnd events delivered");
    CHECK(countDialogEvents(mark, true, true) == 2,
          "refresh: both pending dialogs delivered with DialogState/Id=true, Retain=true (got %zu)",
          countDialogEvents(mark, true, true));
    {
        UA_Boolean opts = false;
        for(size_t i = mark; i < seenCount; i++) if(seen[i].optionCount == 2) opts = true;
        CHECK(opts, "refresh: ResponseOptionSet [Approve, Reject] readable through the event filter");
    }

    /* 2. Live: a new dialog raised while subscribed arrives without refresh. */
    mark = seenCount;
    UA_NodeId c3;
    rv = raiseApproval("REQ-3", "urn:example:gw3", &c3);
    pump(client, 300);
    CHECK(rv == UA_STATUSCODE_GOOD && countDialogEvents(mark, true, true) == 1,
          "live: new dialog event delivered (%s)", UA_StatusCode_name(rv));

    /* 3. Respond2 approve. */
    mark = seenCount;
    rv = callRespond2(client, c1, RESP_APPROVE, "Checked the CSR against the order sheet");
    pump(client, 300);
    CHECK(rv == UA_STATUSCODE_GOOD, "Respond2(Approve) on dialog 1 (%s)", UA_StatusCode_name(rv));
    CHECK(approvals[0].state == APPROVED, "server: request state is APPROVED");
    CHECK(countDialogEvents(mark, false, false) == 1,
          "Respond2: event with DialogState/Id=false, Retain=false delivered");
    CHECK(countType(mark, UA_NS0ID_AUDITCONDITIONRESPONDEVENTTYPE) == 1,
          "Respond2: AuditConditionRespondEventType delivered");
    {
        UA_Variant v; UA_Variant_init(&v);
        UA_Int32 lr = -99;
        /* read LastResponse through the browse path to check the address space */
        UA_BrowsePath bp; UA_BrowsePath_init(&bp);
        UA_RelativePathElement el; UA_RelativePathElement_init(&el);
        el.referenceTypeId = UA_NS0ID(HASPROPERTY);
        el.includeSubtypes = true;
        el.targetName = UA_QUALIFIEDNAME(0, "LastResponse");
        bp.startingNode = c1; bp.relativePath.elementsSize = 1; bp.relativePath.elements = &el;
        UA_TranslateBrowsePathsToNodeIdsRequest tr; UA_TranslateBrowsePathsToNodeIdsRequest_init(&tr);
        tr.browsePaths = &bp; tr.browsePathsSize = 1;
        UA_TranslateBrowsePathsToNodeIdsResponse trr =
            UA_Client_Service_translateBrowsePathsToNodeIds(client, tr);
        if(trr.resultsSize == 1 && trr.results[0].targetsSize >= 1 &&
           UA_Client_readValueAttribute(client, trr.results[0].targets[0].targetId.nodeId, &v)
               == UA_STATUSCODE_GOOD && UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_INT32]))
            lr = *(UA_Int32*)v.data;
        UA_TranslateBrowsePathsToNodeIdsResponse_clear(&trr);
        UA_Variant_clear(&v);
        CHECK(lr == RESP_APPROVE, "address space: LastResponse=0 readable after Respond2");
    }

    /* 4. Second answer is refused. */
    rv = callRespond2(client, c1, RESP_REJECT, "too late");
    CHECK(rv == UA_STATUSCODE_BADDIALOGNOTACTIVE, "Respond2 again -> BadDialogNotActive (%s)",
          UA_StatusCode_name(rv));
    /* 5. Out-of-range answer. */
    rv = callRespond2(client, c2, 7, "?");
    CHECK(rv == UA_STATUSCODE_BADDIALOGRESPONSEINVALID,
          "Respond2(7) -> BadDialogResponseInvalid (%s)", UA_StatusCode_name(rv));
    /* 6. Respond2 on a non-dialog object. */
    rv = callRespond2(client, UA_NS0ID(SERVER), RESP_APPROVE, "x");
    CHECK(rv == UA_STATUSCODE_BADMETHODINVALID, "Respond2 on Server object -> BadMethodInvalid (%s)",
          UA_StatusCode_name(rv));
    /* 7. Wrong argument type is rejected by the stack before our callback. */
    {
        UA_Variant in[2]; UA_String s = UA_STRING("approve"); UA_LocalizedText lt = UA_LOCALIZEDTEXT("en","x");
        UA_Variant_setScalar(&in[0], &s, &UA_TYPES[UA_TYPES_STRING]);
        UA_Variant_setScalar(&in[1], &lt, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        size_t os = 0; UA_Variant *o = NULL;
        rv = UA_Client_call(client, c2, UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND2), 2, in, &os, &o);
        CHECK(rv == UA_STATUSCODE_BADINVALIDARGUMENT || rv == UA_STATUSCODE_BADTYPEMISMATCH,
              "Respond2(String) -> rejected by stack (%s)", UA_StatusCode_name(rv));
    }
    /* 8. Old Respond (mandatory) has no callback in the stack. */
    {
        UA_Variant in; UA_Int32 r = 0;
        UA_Variant_setScalar(&in, &r, &UA_TYPES[UA_TYPES_INT32]);
        size_t os = 0; UA_Variant *o = NULL;
        rv = UA_Client_call(client, c2, UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND), 1, &in, &os, &o);
        printf("INFO  Respond (v1, no callback bound) -> %s\n", UA_StatusCode_name(rv));
    }

    /* 8b. Role gate through the access control plugin. */
    denyRespond = true;
    rv = callRespond2(client, c2, RESP_APPROVE, "not my role");
    denyRespond = false;
    CHECK(rv == UA_STATUSCODE_BADUSERACCESSDENIED && approvals[1].state == PENDING,
          "Respond2 by a session without the role -> BadUserAccessDenied (%s)",
          UA_StatusCode_name(rv));

    /* 9. Reject dialog 2, then refresh: only dialog 3 is still retained. */
    rv = callRespond2(client, c2, RESP_REJECT, "Unknown device");
    CHECK(rv == UA_STATUSCODE_GOOD && approvals[1].state == REJECTED, "Respond2(Reject) on dialog 2");
    pump(client, 200);
    mark = seenCount;
    conditionRefresh(client, subId);
    pump(client, 300);
    CHECK(countDialogEvents(mark, true, true) == 1 && countDialogEvents(mark, false, false) == 0,
          "refresh after decisions: only the one pending dialog is resent (got %zu active)",
          countDialogEvents(mark, true, true));

    /* 10. Delete a decided condition. */
    rv = UA_Server_deleteCondition(server, c1, approvalsSource);
    CHECK(rv == UA_STATUSCODE_GOOD, "deleteCondition on decided dialog (%s)", UA_StatusCode_name(rv));
    rv = callRespond2(client, c1, RESP_APPROVE, "x");
    CHECK(rv == UA_STATUSCODE_BADNODEIDUNKNOWN, "Respond2 on deleted dialog -> BadNodeIdUnknown (%s)",
          UA_StatusCode_name(rv));

    /* 11. Scale: bulk create N dialogs while the server runs, then refresh. */
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    UA_StatusCode bulkRv = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < bulk; i++) {
        char id[32]; snprintf(id, sizeof(id), "BULK-%zu", i);
        bulkRv |= raiseApproval(id, "urn:example:bulk", NULL);
    }
    double createMs = msSince(&t0);
    CHECK(bulkRv == UA_STATUSCODE_GOOD, "scale: %zu dialogs created in %.0f ms (%.2f ms each)",
          bulk, createMs, createMs / (double)bulk);
    pump(client, 1500);
    mark = seenCount;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    rv = conditionRefresh(client, subId);
    double refreshMs = msSince(&t0);
    pump(client, getenv("PUMP_MS") ? atoi(getenv("PUMP_MS")) : 2000);
    CHECK(rv == UA_STATUSCODE_GOOD, "scale: ConditionRefresh over %zu retained dialogs took %.0f ms "
          "(server-side, in the call)", bulk + 1, refreshMs);
    printf("INFO  refresh delivered %zu of %zu dialog events, RefreshEnd seen: %s, "
           "EventQueueOverflow events: %zu\n", countDialogEvents(mark, true, true), bulk + 1,
           countType(mark, UA_NS0ID_REFRESHENDEVENTTYPE) ? "yes" : "no",
           countType(mark, UA_NS0ID_EVENTQUEUEOVERFLOWEVENTTYPE));
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for(size_t i = 3; i < 3 + 100 && i < approvalCount; i++)
        callRespond2(client, approvals[i].condition, RESP_APPROVE, "bulk");
    double respMs = msSince(&t0);
    printf("INFO  100 sequential Respond2 round trips: %.0f ms (%.2f ms each)\n", respMs, respMs / 100);
    printf("INFO  audit events emitted: %u\n", auditEventsEmitted);

    UA_Client_disconnect(client);
    UA_Client_delete(client);
    running = false;
    pthread_join(th, NULL);
    UA_Server_delete(server);
    for(size_t i = 0; i < seenCount; i++) {
        UA_NodeId_clear(&seen[i].eventType);
        UA_NodeId_clear(&seen[i].condition);
    }
    for(size_t i = 0; i < approvalCount; i++) {
        UA_String_clear(&approvals[i].decidedBy);
        UA_LocalizedText_clear(&approvals[i].comment);
    }
    for(size_t i = 0; i < F_COUNT; i++)
        UA_SimpleAttributeOperand_clear(&sel[i]);
    printf("\n%s: %d failure(s)\n", failures ? "FAILED" : "ALL PASS", failures);
    return failures ? 1 : 0;
}
