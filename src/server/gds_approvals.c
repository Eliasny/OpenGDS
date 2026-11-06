/* OpenGDS - approvals: one Part 9 DialogCondition per certificate request
 * that waits for an administrator (OPC 10000-12 leaves approval to the
 * implementation; the plan fills the gap with standard types only).
 *
 * The store is the truth and the condition a view of it
 * (docs/spikes/01-dialog-condition-approvals.md):
 * - a request in state Pending has a dialog with DialogState Active and
 *   Retain true; at start every Pending request gets its dialog again,
 *   before the endpoint opens;
 * - Respond2 (Part 9 v1.05 §5.6.4) and Respond (§5.6.3, behaving as
 *   Respond2 with a NULL Comment, decision D3) share one handler; the
 *   decision is committed to the store first, then the dialog goes
 *   Inactive, Retain false, its last event is sent and it is deleted;
 * - every call emits AuditConditionRespondEventType, failed ones too.
 * The dialog's NodeId is ns=1;g=<RequestId>, so it names its request.
 * Who may answer is decided in access control (RegistrationAuthorityAdmin,
 * gds_access.c); the handler checks again.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>

#include <stdio.h>
#include <string.h>

#include "common/limits.h"
#include "gds_internal.h"
#include "common/banned.h"

#define APP_NS 1 /* the server's own namespace */
#define RESP_APPROVE 0
#define RESP_REJECT 1
#define DIALOG_SEVERITY 500
#define MAX_COMMENT 1024 /* characters, Part 9 §5.6.4 Bad_InvalidArgument beyond */

/* ---- condition fields ---- */

static UA_StatusCode set_field(UA_Server *ua, UA_NodeId c, const char *field, const void *v,
                               const UA_DataType *t) {
    UA_Variant var;
    UA_Variant_setScalar(&var, (void *)(uintptr_t)v, t);
    return UA_Server_setConditionField(ua, c, &var,
                                       UA_QUALIFIEDNAME(0, (char *)(uintptr_t)field));
}

/* UA_Server_setConditionField refuses arrays in v1.5.10: write the
 * variable directly (spike workaround 2). */
static UA_StatusCode set_field_array(UA_Server *ua, UA_NodeId c, const char *field,
                                     const void *v, size_t n, const UA_DataType *t) {
    UA_Variant var;
    UA_Variant_setArray(&var, (void *)(uintptr_t)v, n, t);
    UA_QualifiedName qn = UA_QUALIFIEDNAME(0, (char *)(uintptr_t)field);
    UA_BrowsePathResult bpr = UA_Server_browseSimplifiedBrowsePath(ua, c, 1, &qn);
    UA_StatusCode r = bpr.statusCode;
    if(r == UA_STATUSCODE_GOOD && bpr.targetsSize == 1)
        r = UA_Server_writeValue(ua, bpr.targets[0].targetId.nodeId, var);
    else if(r == UA_STATUSCODE_GOOD)
        r = UA_STATUSCODE_BADNOTFOUND;
    UA_BrowsePathResult_clear(&bpr);
    return r;
}

static UA_StatusCode set_two_state(UA_Server *ua, UA_NodeId c, const char *field, UA_Boolean id,
                                   const char *text) {
    UA_LocalizedText lt = UA_LOCALIZEDTEXT("en", (char *)(uintptr_t)text);
    UA_StatusCode r = set_field(ua, c, field, &lt, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    UA_Variant var;
    UA_Variant_setScalar(&var, &id, &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_setConditionVariableFieldProperty(
            ua, c, &var, UA_QUALIFIEDNAME(0, (char *)(uintptr_t)field), UA_QUALIFIEDNAME(0, "Id"));
    return r;
}

static UA_NodeId source_id(void) {
    return UA_NODEID_STRING(APP_NS, "Approvals");
}

/* ---- raise ---- */

static UA_StatusCode dialog_fields(UA_Server *ua, UA_NodeId c, const gds_request *q,
                                   const UA_String *appUri) {
    char rid[40], msg[GDS_MAX_APPLICATION_URI + 128];
    UA_String ridStr = UA_STRING_NULL;
    if(UA_Guid_print(&q->id, &ridStr) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    gds_status st = gds_path(rid, sizeof(rid), "%.*s", (int)ridStr.length,
                             (const char *)ridStr.data);
    UA_String_clear(&ridStr);
    if(st != GDS_OK || gds_path(msg, sizeof(msg), "Certificate request %s from %.*s awaits approval", rid,
                (int)appUri->length, (const char *)appUri->data) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_LocalizedText message = UA_LOCALIZEDTEXT("en", msg);
    UA_LocalizedText prompt = UA_LOCALIZEDTEXT("en", "Issue a certificate for this application?");
    UA_LocalizedText options[2] = {UA_LOCALIZEDTEXT("en", "Approve"),
                                   UA_LOCALIZEDTEXT("en", "Reject")};
    UA_Int32 def = -1, ok = RESP_APPROVE, cancel = RESP_REJECT, last = -1;
    UA_UInt16 severity = DIALOG_SEVERITY;
    UA_Boolean retain = true;
    UA_StatusCode r = set_field(ua, c, "Message", &message, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    if(r == UA_STATUSCODE_GOOD)
        r = set_field(ua, c, "Severity", &severity, &UA_TYPES[UA_TYPES_UINT16]);
    if(r == UA_STATUSCODE_GOOD)
        r = set_field(ua, c, "Prompt", &prompt, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    if(r == UA_STATUSCODE_GOOD)
        r = set_field_array(ua, c, "ResponseOptionSet", options, 2,
                            &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    if(r == UA_STATUSCODE_GOOD)
        r = set_field(ua, c, "DefaultResponse", &def, &UA_TYPES[UA_TYPES_INT32]);
    if(r == UA_STATUSCODE_GOOD)
        r = set_field(ua, c, "OkResponse", &ok, &UA_TYPES[UA_TYPES_INT32]);
    if(r == UA_STATUSCODE_GOOD)
        r = set_field(ua, c, "CancelResponse", &cancel, &UA_TYPES[UA_TYPES_INT32]);
    if(r == UA_STATUSCODE_GOOD)
        r = set_field(ua, c, "LastResponse", &last, &UA_TYPES[UA_TYPES_INT32]);
    if(r == UA_STATUSCODE_GOOD)
        r = set_two_state(ua, c, "DialogState", true, "Active");
    if(r == UA_STATUSCODE_GOOD)
        r = set_two_state(ua, c, "EnabledState", true, "Enabled");
    if(r == UA_STATUSCODE_GOOD)
        r = set_field(ua, c, "Retain", &retain, &UA_TYPES[UA_TYPES_BOOLEAN]);
    return r;
}

UA_StatusCode gds_approvals_raise(gds_server *s, const gds_request *q, const UA_String *appUri) {
    UA_Server *ua = s->ua;
    UA_NodeId src = source_id(), c = UA_NODEID_NULL;
    UA_NodeId want = UA_NODEID_GUID(APP_NS, q->id);
    UA_StatusCode r = UA_Server_createCondition(ua, want, UA_NS0ID(DIALOGCONDITIONTYPE),
                                                UA_QUALIFIEDNAME(APP_NS, "CertificateRequest"),
                                                src, UA_NS0ID(HASCOMPONENT), &c);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    /* Respond2 is Optional on DialogConditionType and not instantiated
     * (spike workaround 1): reference the type's method from the dialog. */
    r = UA_Server_addReference(ua, c, UA_NS0ID(HASCOMPONENT),
                               UA_EXPANDEDNODEID_NUMERIC(0, UA_NS0ID_DIALOGCONDITIONTYPE_RESPOND2),
                               true);
    if(r == UA_STATUSCODE_GOOD)
        r = dialog_fields(ua, c, q, appUri);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_triggerConditionEvent(ua, c, src, NULL);
    if(r == UA_STATUSCODE_GOOD)
        s->pendingApprovals++;
    else
        (void)UA_Server_deleteCondition(ua, c, src);
    UA_NodeId_clear(&c);
    return r;
}

/* ---- respond ---- */

typedef struct {
    const UA_NodeId *dialog;
    UA_Int32 response;
    UA_Boolean status;
    const char *user;
} respond_audit;

/* AuditConditionRespondEventType (Part 9 §5.10.6), for every call. */
static void emit_audit(UA_Server *ua, const respond_audit *a, bool respond2) {
    UA_NodeId method = respond2 ? UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND2)
                                : UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND);
    UA_String user = UA_STRING((char *)(uintptr_t)a->user);
    UA_DateTime now = UA_DateTime_now();
    UA_Boolean status = a->status;
    UA_Int32 resp = a->response;
    UA_KeyValuePair kv[5];
    kv[0].key = UA_QUALIFIEDNAME(0, "/Status");
    UA_Variant_setScalar(&kv[0].value, &status, &UA_TYPES[UA_TYPES_BOOLEAN]);
    kv[1].key = UA_QUALIFIEDNAME(0, "/SelectedResponse");
    UA_Variant_setScalar(&kv[1].value, &resp, &UA_TYPES[UA_TYPES_INT32]);
    kv[2].key = UA_QUALIFIEDNAME(0, "/MethodId");
    UA_Variant_setScalar(&kv[2].value, &method, &UA_TYPES[UA_TYPES_NODEID]);
    kv[3].key = UA_QUALIFIEDNAME(0, "/ClientUserId");
    UA_Variant_setScalar(&kv[3].value, &user, &UA_TYPES[UA_TYPES_STRING]);
    kv[4].key = UA_QUALIFIEDNAME(0, "/ActionTimeStamp");
    UA_Variant_setScalar(&kv[4].value, &now, &UA_TYPES[UA_TYPES_DATETIME]);
    UA_KeyValueMap map = {5, kv};
    UA_LocalizedText msg = UA_LOCALIZEDTEXT("en", respond2 ? "Respond2 on an approval dialog"
                                                           : "Respond on an approval dialog");
    UA_StatusCode r = UA_Server_createEvent(ua, *a->dialog, UA_NS0ID(AUDITCONDITIONRESPONDEVENTTYPE),
                                            100, msg, &map, NULL, NULL);
    if(r != UA_STATUSCODE_GOOD)
        fprintf(stderr, "opengds: audit event for an approval: %s\n", UA_StatusCode_name(r));
}

/* The decision, in the store first. Bad_DialogNotActive when the request
 * is no longer Pending (decided already, or not a dialog of ours). */
static UA_StatusCode decide(gds_server *s, const UA_Guid *reqId, UA_Int32 resp) {
    gds_request q;
    memset(&q, 0, sizeof(q));
    gds_lock(s);
    gds_status st = gds_store_req_get(s->store, reqId, &q);
    if(st == GDS_OK && q.state != GDS_REQ_PENDING)
        st = GDS_ESTATE;
    if(st == GDS_OK)
        st = resp == RESP_APPROVE
                 ? gds_store_req_set_state(s->store, reqId, GDS_REQ_RECEIVED, NULL,
                                           UA_STATUSCODE_GOOD)
                 : gds_store_req_set_state(s->store, reqId, GDS_REQ_FAILED, NULL,
                                           UA_STATUSCODE_BADREQUESTNOTALLOWED);
    gds_unlock(s);
    gds_request_clear(&q);
    if(st == GDS_ENOTFOUND || st == GDS_ESTATE)
        return UA_STATUSCODE_BADDIALOGNOTACTIVE;
    return st == GDS_OK ? UA_STATUSCODE_GOOD : gds_status_to_ua(st);
}

/* The dialog after the decision: Inactive, Retain false, its last event,
 * then gone (decided dialogs are not kept). */
static UA_StatusCode close_dialog(UA_Server *ua, UA_NodeId c, UA_Int32 resp,
                                  const UA_LocalizedText *comment, const char *user) {
    UA_Boolean retain = false;
    UA_String u = UA_STRING((char *)(uintptr_t)user);
    UA_StatusCode r = set_field(ua, c, "LastResponse", &resp, &UA_TYPES[UA_TYPES_INT32]);
    if(r == UA_STATUSCODE_GOOD)
        r = set_two_state(ua, c, "DialogState", false, "Inactive");
    /* §5.6.4: a NULL Comment is ignored; an empty text with a locale resets it */
    if(r == UA_STATUSCODE_GOOD && comment &&
       (comment->locale.length > 0 || comment->text.length > 0))
        r = set_field(ua, c, "Comment", comment, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    if(r == UA_STATUSCODE_GOOD)
        r = set_field(ua, c, "ClientUserId", &u, &UA_TYPES[UA_TYPES_STRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = set_field(ua, c, "Retain", &retain, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_NodeId src = source_id();
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_triggerConditionEvent(ua, c, src, NULL);
    (void)UA_Server_deleteCondition(ua, c, src);
    return r;
}

static UA_StatusCode respond(gds_server *s, const UA_NodeId *objectId, const void *sessionContext,
                             UA_Int32 resp, const UA_LocalizedText *comment, bool respond2) {
    const gds_session *sess = gds_session_get(sessionContext);
    const char *user = sess && sess->user[0] ? sess->user : "";
    respond_audit a = {objectId, resp, false, user};
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    if(objectId->namespaceIndex != APP_NS || objectId->identifierType != UA_NODEIDTYPE_GUID)
        r = UA_STATUSCODE_BADMETHODINVALID; /* not one of our dialogs */
    else if(!gds_session_has(sessionContext, GDS_ROLE_REGISTRATION_AUTHORITY_ADMIN))
        r = UA_STATUSCODE_BADUSERACCESSDENIED;
    else if(gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        r = UA_STATUSCODE_BADINVALIDSTATE;
    else if(resp != RESP_APPROVE && resp != RESP_REJECT)
        r = UA_STATUSCODE_BADDIALOGRESPONSEINVALID;
    else if(comment && comment->text.length > MAX_COMMENT)
        r = UA_STATUSCODE_BADINVALIDARGUMENT;
    if(r == UA_STATUSCODE_GOOD)
        r = decide(s, &objectId->identifier.guid, resp);
    if(r == UA_STATUSCODE_GOOD) {
        if(s->pendingApprovals > 0)
            s->pendingApprovals--;
        a.status = true;
        /* committed: a failure from here on leaves a stale view, not a
         * wrong decision; the request's state is what FinishRequest reads */
        UA_StatusCode v = close_dialog(s->ua, *objectId, resp, comment, user);
        if(v != UA_STATUSCODE_GOOD)
            fprintf(stderr, "opengds: closing an approval dialog: %s\n", UA_StatusCode_name(v));
        if(resp == RESP_APPROVE)
            gds_worker_kick(s);
    }
    emit_audit(s->ua, &a, respond2);
    return r;
}

static GDS_METHOD(respond2_cb) {
    (void)server, (void)sessionId, (void)methodId, (void)objectContext, (void)output,
        (void)outputSize;
    if(inputSize < 2)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    if(inputSize > 2)
        return UA_STATUSCODE_BADTOOMANYARGUMENTS;
    if(!UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_INT32]) ||
       !UA_Variant_hasScalarType(&input[1], &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    return respond(gds_ctx(methodContext), objectId, sessionContext,
                   *(const UA_Int32 *)input[0].data, input[1].data, true);
}

static GDS_METHOD(respond_cb) {
    (void)server, (void)sessionId, (void)methodId, (void)objectContext, (void)output,
        (void)outputSize;
    if(inputSize < 1)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    if(inputSize > 1)
        return UA_STATUSCODE_BADTOOMANYARGUMENTS;
    if(!UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_INT32]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    return respond(gds_ctx(methodContext), objectId, sessionContext,
                   *(const UA_Int32 *)input[0].data, NULL, false);
}

/* ---- install and rebuild ---- */

typedef struct {
    gds_server *s;
    UA_StatusCode r;
    size_t n;
} rebuild_ctx;

static bool rebuild_one(void *ctx, const gds_request *q) {
    rebuild_ctx *rc = ctx;
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    UA_String none = UA_STRING("an unknown application");
    gds_status st = gds_store_app_get(rc->s->store, &q->appId, &rec);
    rc->r = gds_approvals_raise(rc->s, q, st == GDS_OK ? &rec.applicationUri : &none);
    UA_ApplicationRecordDataType_clear(&rec);
    rc->n++;
    return rc->r == UA_STATUSCODE_GOOD;
}

UA_StatusCode gds_approvals_install(gds_server *s) {
    UA_Server *ua = s->ua;
    UA_ObjectAttributes oa = UA_ObjectAttributes_default;
    oa.displayName = UA_LOCALIZEDTEXT("en", "Approvals");
    oa.description = UA_LOCALIZEDTEXT("en", "Certificate requests waiting for an administrator");
    oa.eventNotifier = UA_EVENTNOTIFIER_SUBSCRIBE_TO_EVENT;
    UA_StatusCode r = UA_Server_addObjectNode(ua, source_id(), UA_NS0ID(OBJECTSFOLDER),
                                              UA_NS0ID(ORGANIZES),
                                              UA_QUALIFIEDNAME(APP_NS, "Approvals"),
                                              UA_NS0ID(BASEOBJECTTYPE), oa, NULL, NULL);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_addReference(ua, UA_NS0ID(SERVER), UA_NS0ID(HASNOTIFIER),
                                   UA_EXPANDEDNODEID_STRING(APP_NS, "Approvals"), true);
    /* one method node serves every dialog: the context is the server */
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_setMethodNodeCallback(ua, UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND2), respond2_cb);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_setNodeContext(ua, UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND2), s);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_setMethodNodeCallback(ua, UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND), respond_cb);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_setNodeContext(ua, UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND), s);
    /* D1: one ConditionRefresh carries every pending dialog */
    UA_ServerConfig *cfg = UA_Server_getConfig(ua);
    if(cfg->queueSizeLimits.max < GDS_MAX_PENDING_APPROVALS + 2u) /* + RefreshStart/End */
        cfg->queueSizeLimits.max = GDS_MAX_PENDING_APPROVALS + 2u;
    if(r != UA_STATUSCODE_GOOD)
        return r;
    rebuild_ctx rc = {s, UA_STATUSCODE_GOOD, 0};
    gds_lock(s);
    gds_status st = gds_store_req_scan(s->store, GDS_REQ_PENDING, rebuild_one, &rc);
    gds_unlock(s);
    if(st != GDS_OK)
        return gds_status_to_ua(st);
    if(rc.n)
        fprintf(stderr, "opengds: %zu certificate request(s) wait for approval\n", rc.n);
    return rc.r;
}
