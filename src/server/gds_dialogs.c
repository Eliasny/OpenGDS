/* OpenGDS - plugin dialogs (UASM ask A19): Part 9 DialogConditionType
 * instances that a plugin opens to ask an operator a question, such as
 * "Register and manage this server?" for a server fleet discovery found.
 *
 * - gds_server_add_dialog creates the condition as a HasComponent child of
 *   the plugin's source object, with EnabledState Enabled, DialogState
 *   Active, Retain true, its Prompt, ResponseOptionSet and
 *   Ok/Cancel/DefaultResponse (OPC 10000-9 §5.6.2), and fires its event.
 *   With visibleTo, gds_cond_restrict keeps its events (and the audit
 *   events whose SourceNode it is) to sessions holding those Roles.
 * - Respond and Respond2 (§5.6.3, §5.6.4) arrive through the
 *   DialogConditionType method callbacks of gds_approvals.c. The checks
 *   are made on the server thread; the plugin's callback runs on a plugin
 *   worker (gds_embed_defer) and its answer completes the call. On Good
 *   the dialog is closed: LastResponse, Comment, ClientUserId, DialogState
 *   Inactive, Retain false, an event. Every call is audited as
 *   AuditConditionRespondEventType (§5.10.6).
 * - gds_server_remove_dialog closes an active dialog first, then deletes
 *   it.
 * dialogLock (a leaf lock) guards the list and each dialog's active and
 * busy flags; open62541 calls are never made under it.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/limits.h"
#include "gds_internal.h"
#include "common/banned.h"

#define MAX_COMMENT 1024 /* characters, Part 9 §5.6.4 Bad_InvalidArgument beyond */

struct gds_dialog {
    UA_NodeId id, source;
    UA_NodeId respondId; /* the instance's copy of Respond */
    unsigned respondBits;
    bool respondAnon, respondAuth;
    size_t nOptions;
    gds_dialog_fn fn;
    void *ctx;
    bool active, busy; /* dialogLock */
};

static void dialog_free(gds_dialog *d) {
    if(!d)
        return;
    UA_NodeId_clear(&d->id);
    UA_NodeId_clear(&d->source);
    UA_NodeId_clear(&d->respondId);
    free(d);
}

/* dialogLock held */
static gds_dialog *find_locked(gds_server *s, const UA_NodeId *id) {
    for(size_t i = 0; id && i < s->nDialogs; i++)
        if(UA_NodeId_equal(&s->dialogs[i]->id, id))
            return s->dialogs[i];
    return NULL;
}

bool gds_dialog_is(gds_server *s, const UA_NodeId *objectId) {
    if(!s)
        return false;
    pthread_mutex_lock(&s->dialogLock);
    bool r = find_locked(s, objectId) != NULL;
    pthread_mutex_unlock(&s->dialogLock);
    return r;
}

static bool is_respond(const gds_dialog *d, const UA_NodeId *m) {
    if(m->namespaceIndex == 0 && m->identifierType == UA_NODEIDTYPE_NUMERIC &&
       (m->identifier.numeric == UA_NS0ID_DIALOGCONDITIONTYPE_RESPOND ||
        m->identifier.numeric == UA_NS0ID_DIALOGCONDITIONTYPE_RESPOND2))
        return true;
    return UA_NodeId_equal(&d->respondId, m);
}

static bool may_respond(const gds_dialog *d, const gds_session *ss) {
    if(!ss || ss->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return false;
    bool anon = gds_session_anonymous(ss);
    return d->respondAnon || (d->respondAuth && !anon) ||
           (gds_session_roles(ss) & d->respondBits) != 0;
}

bool gds_dialog_may_call(gds_server *s, const void *sessionContext, const UA_NodeId *objectId,
                         const UA_NodeId *methodId) {
    const gds_session *ss = gds_session_get(sessionContext);
    pthread_mutex_lock(&s->dialogLock);
    const gds_dialog *d = find_locked(s, objectId);
    /* only Respond and Respond2; the ConditionType methods stay closed */
    bool r = d && is_respond(d, methodId) && may_respond(d, ss);
    pthread_mutex_unlock(&s->dialogLock);
    return r;
}

/* ---- events ---- */

/* AuditConditionRespondEventType (Part 9 §5.10.6), SourceNode the dialog,
 * so it reaches only the sessions its events reach. */
static void respond_audit(gds_server *s, const UA_NodeId *dialog, UA_Int32 resp, bool status,
                          const char *user, bool respond2) {
    UA_NodeId method = respond2 ? UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND2)
                                : UA_NS0ID(DIALOGCONDITIONTYPE_RESPOND);
    UA_String u = UA_STRING((char *)(uintptr_t)user);
    UA_DateTime now = UA_DateTime_now();
    UA_Boolean st = status;
    UA_KeyValuePair kv[5];
    kv[0].key = UA_QUALIFIEDNAME(0, "/Status");
    UA_Variant_setScalar(&kv[0].value, &st, &UA_TYPES[UA_TYPES_BOOLEAN]);
    kv[1].key = UA_QUALIFIEDNAME(0, "/SelectedResponse");
    UA_Variant_setScalar(&kv[1].value, &resp, &UA_TYPES[UA_TYPES_INT32]);
    kv[2].key = UA_QUALIFIEDNAME(0, "/MethodId");
    UA_Variant_setScalar(&kv[2].value, &method, &UA_TYPES[UA_TYPES_NODEID]);
    kv[3].key = UA_QUALIFIEDNAME(0, "/ClientUserId");
    UA_Variant_setScalar(&kv[3].value, &u, &UA_TYPES[UA_TYPES_STRING]);
    kv[4].key = UA_QUALIFIEDNAME(0, "/ActionTimeStamp");
    UA_Variant_setScalar(&kv[4].value, &now, &UA_TYPES[UA_TYPES_DATETIME]);
    UA_KeyValueMap map = {5, kv};
    UA_LocalizedText msg =
        UA_LOCALIZEDTEXT("en", respond2 ? "Respond2 on a dialog" : "Respond on a dialog");
    UA_StatusCode r = UA_Server_createEvent(s->ua, *dialog, UA_NS0ID(AUDITCONDITIONRESPONDEVENTTYPE),
                                            100, msg, &map, NULL, NULL);
    if(r != UA_STATUSCODE_GOOD)
        fprintf(stderr, "opengds: audit event for a dialog: %s\n", UA_StatusCode_name(r));
}

/* Inactive, Retain false and the event; resp -1 for a closed dialog that
 * nobody answered. */
static UA_StatusCode close_fields(gds_server *s, const UA_NodeId *id, const UA_NodeId *source,
                                  UA_Int32 resp, const UA_LocalizedText *comment,
                                  const char *user) {
    UA_Server *ua = s->ua;
    UA_Boolean retain = false;
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    if(resp >= 0) {
        UA_String u = UA_STRING((char *)(uintptr_t)user);
        r = gds_cond_set_field(ua, *id, "LastResponse", &resp, &UA_TYPES[UA_TYPES_INT32]);
        /* §5.6.4: a NULL Comment is ignored; an empty text with a locale resets it */
        if(r == UA_STATUSCODE_GOOD && comment &&
           (comment->locale.length > 0 || comment->text.length > 0))
            r = gds_cond_set_field(ua, *id, "Comment", comment, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        if(r == UA_STATUSCODE_GOOD)
            r = gds_cond_set_field(ua, *id, "ClientUserId", &u, &UA_TYPES[UA_TYPES_STRING]);
    }
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_two_state(ua, *id, "DialogState", false, "Inactive");
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_field(ua, *id, "Retain", &retain, &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_triggerConditionEvent(ua, *id, *source, NULL);
    return r;
}

/* ---- Respond ---- */

typedef struct {
    gds_server *s;
    UA_NodeId id;
    UA_Int32 resp;
    UA_LocalizedText comment;
    bool hasComment, respond2;
    char user[sizeof(((gds_session *)0)->user)];
    gds_dialog_fn fn;
    void *fnCtx;
} respond_job;

static void job_free(void *p) {
    respond_job *j = p;
    if(!j)
        return;
    UA_NodeId_clear(&j->id);
    UA_LocalizedText_clear(&j->comment);
    free(j);
}

/* plugin worker */
static UA_StatusCode job_run(void *p, const gds_caller *caller, size_t nIn, const UA_Variant *in) {
    (void)nIn, (void)in;
    respond_job *j = p;
    UA_StatusCode r =
        j->fn(j->fnCtx, caller, &j->id, j->resp, j->hasComment ? &j->comment : NULL);
    return UA_StatusCode_isBad(r) ? r : UA_STATUSCODE_GOOD;
}

/* server thread */
static UA_StatusCode job_done(gds_server *s, void *p, UA_StatusCode status) {
    respond_job *j = p;
    UA_NodeId source = UA_NODEID_NULL;
    bool close = false;
    pthread_mutex_lock(&s->dialogLock);
    gds_dialog *d = find_locked(s, &j->id);
    if(d) {
        d->busy = false;
        close = status == UA_STATUSCODE_GOOD && d->active;
        if(close) {
            d->active = false;
            close = UA_NodeId_copy(&d->source, &source) == UA_STATUSCODE_GOOD;
        }
    }
    pthread_mutex_unlock(&s->dialogLock);
    if(close) {
        UA_StatusCode r = close_fields(s, &j->id, &source, j->resp,
                                       j->hasComment ? &j->comment : NULL, j->user);
        if(r != UA_STATUSCODE_GOOD)
            fprintf(stderr, "opengds: closing a dialog: %s\n", UA_StatusCode_name(r));
    }
    UA_NodeId_clear(&source);
    respond_audit(s, &j->id, j->resp, status == UA_STATUSCODE_GOOD, j->user, j->respond2);
    job_free(j);
    return status;
}

/* The checks, in the order of §5.6.3: who, the response, the comment,
 * then whether the dialog is active. */
static UA_StatusCode check(gds_server *s, gds_dialog *d, const gds_session *ss, UA_Int32 resp,
                           const UA_LocalizedText *comment) {
    if(!may_respond(d, ss))
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    if(gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDSTATE;
    if(resp < 0 || (size_t)resp >= d->nOptions)
        return UA_STATUSCODE_BADDIALOGRESPONSEINVALID;
    if(comment && comment->text.length > MAX_COMMENT)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(!d->active || d->busy)
        return UA_STATUSCODE_BADDIALOGNOTACTIVE;
    return UA_STATUSCODE_GOOD;
}

static respond_job *job_new(gds_server *s, const gds_dialog *d, const gds_session *ss,
                            UA_Int32 resp, const UA_LocalizedText *comment, bool respond2) {
    respond_job *j = calloc(1, sizeof(*j));
    if(!j)
        return NULL;
    j->s = s;
    j->resp = resp;
    j->respond2 = respond2;
    j->fn = d->fn;
    j->fnCtx = d->ctx;
    if(ss)
        memcpy(j->user, ss->user, sizeof(j->user) - 1);
    UA_StatusCode r = UA_NodeId_copy(&d->id, &j->id);
    if(r == UA_STATUSCODE_GOOD && comment) {
        j->hasComment = true;
        r = UA_LocalizedText_copy(comment, &j->comment);
    }
    if(r != UA_STATUSCODE_GOOD) {
        job_free(j);
        return NULL;
    }
    return j;
}

UA_StatusCode gds_dialog_respond(gds_server *s, const UA_NodeId *sessionId, void *sessionContext,
                                 const UA_NodeId *objectId, UA_Int32 response,
                                 const UA_LocalizedText *comment, bool respond2,
                                 UA_Variant *output) {
    if(!objectId)
        return UA_STATUSCODE_BADMETHODINVALID; /* and no audit event without a source */
    const gds_session *ss = gds_session_get(sessionContext);
    const char *user = ss && ss->user[0] ? ss->user : "";
    respond_job *j = NULL;
    pthread_mutex_lock(&s->dialogLock);
    gds_dialog *d = find_locked(s, objectId);
    UA_StatusCode r = d ? check(s, d, ss, response, comment) : UA_STATUSCODE_BADMETHODINVALID;
    if(r == UA_STATUSCODE_GOOD) {
        j = job_new(s, d, ss, response, comment, respond2);
        if(j)
            d->busy = true;
        else
            r = UA_STATUSCODE_BADOUTOFMEMORY;
    }
    pthread_mutex_unlock(&s->dialogLock);
    if(r == UA_STATUSCODE_GOOD) {
        r = gds_embed_defer(s, sessionId, sessionContext, objectId, 0, NULL, output, job_run,
                            job_done, job_free, j);
        if(r == UA_STATUSCODE_GOODCOMPLETESASYNCHRONOUSLY)
            return r; /* job_done audits */
        job_free(j);
        pthread_mutex_lock(&s->dialogLock);
        d = find_locked(s, objectId);
        if(d)
            d->busy = false;
        pthread_mutex_unlock(&s->dialogLock);
    }
    respond_audit(s, objectId, response, false, user, respond2);
    return r;
}

/* ---- the plugin API ---- */

static bool options_ok(const gds_dialog_def *d) {
    if(d->responseOptionsSize == 0 || d->responseOptionsSize > GDS_MAX_DIALOG_OPTIONS ||
       !d->responseOptions)
        return false;
    for(size_t i = 0; i < d->responseOptionsSize; i++) {
        const char *o = d->responseOptions[i];
        if(!o || !o[0] || strnlen(o, GDS_MAX_STRING + 1) > GDS_MAX_STRING)
            return false;
    }
    int32_t n = (int32_t)d->responseOptionsSize;
    return d->defaultResponse >= -1 && d->defaultResponse < n && d->okResponse >= -1 &&
           d->okResponse < n && d->cancelResponse >= -1 && d->cancelResponse < n;
}

static bool text_ok(const char *t, bool optional) {
    if(!t)
        return optional;
    return strnlen(t, GDS_MAX_STRING + 1) <= GDS_MAX_STRING;
}

static bool def_ok(const gds_dialog_def *d) {
    return d && d->abi_major == GDS_PLUGIN_ABI_MAJOR &&
           d->struct_size >= offsetof(gds_dialog_def, ctx) + sizeof(void *) && d->name &&
           d->name[0] && text_ok(d->name, false) && text_ok(d->message, true) &&
           text_ok(d->prompt, false) && options_ok(d) && d->severity >= 1 &&
           d->severity <= 1000 && d->respondRolesSize > 0 &&
           d->respondRolesSize <= GDS_MAX_CALLER_ROLES && d->respondRoles &&
           d->visibleToSize <= GDS_MAX_CALLER_ROLES && (d->visibleToSize == 0 || d->visibleTo) &&
           d->respond && !UA_NodeId_isNull(&d->sourceNode);
}

static UA_StatusCode set_fields(UA_Server *ua, UA_NodeId c, const gds_dialog_def *def) {
    UA_LocalizedText options[GDS_MAX_DIALOG_OPTIONS];
    for(size_t i = 0; i < def->responseOptionsSize; i++)
        options[i] = UA_LOCALIZEDTEXT("", (char *)(uintptr_t)def->responseOptions[i]);
    UA_LocalizedText message =
        UA_LOCALIZEDTEXT("", (char *)(uintptr_t)(def->message ? def->message : ""));
    UA_LocalizedText prompt = UA_LOCALIZEDTEXT("", (char *)(uintptr_t)def->prompt);
    UA_Int32 dflt = def->defaultResponse, ok = def->okResponse, cancel = def->cancelResponse;
    UA_Int32 last = -1;
    UA_UInt16 sev = def->severity;
    UA_Boolean retain = true;
    /* the core fires the events itself: one per state change */
    UA_StatusCode r = gds_cond_detach_hook(ua, c, "EnabledState", "Id");
    /* open62541's Severity hook fires an event and overwrites Message
     * ("The alarm severity has increased"); Severity first, then Message */
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_detach_hook(ua, c, "Severity", NULL);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_field(ua, c, "Severity", &sev, &UA_TYPES[UA_TYPES_UINT16]);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_field(ua, c, "Message", &message, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_field(ua, c, "Prompt", &prompt, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_array(ua, c, "ResponseOptionSet", options, def->responseOptionsSize,
                               &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_field(ua, c, "DefaultResponse", &dflt, &UA_TYPES[UA_TYPES_INT32]);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_field(ua, c, "OkResponse", &ok, &UA_TYPES[UA_TYPES_INT32]);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_field(ua, c, "CancelResponse", &cancel, &UA_TYPES[UA_TYPES_INT32]);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_field(ua, c, "LastResponse", &last, &UA_TYPES[UA_TYPES_INT32]);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_two_state(ua, c, "DialogState", true, "Active");
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_two_state(ua, c, "EnabledState", true, "Enabled");
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_field(ua, c, "Retain", &retain, &UA_TYPES[UA_TYPES_BOOLEAN]);
    return r;
}

static UA_NodeId respond_child(UA_Server *ua, const UA_NodeId *c) {
    UA_QualifiedName qn = UA_QUALIFIEDNAME(0, "Respond");
    UA_BrowsePathResult bp = UA_Server_browseSimplifiedBrowsePath(ua, *c, 1, &qn);
    UA_NodeId id = UA_NODEID_NULL;
    if(bp.statusCode == UA_STATUSCODE_GOOD && bp.targetsSize == 1)
        (void)UA_NodeId_copy(&bp.targets[0].targetId.nodeId, &id);
    UA_BrowsePathResult_clear(&bp);
    return id;
}

/* The condition, restricted before its first event. */
static gds_status create(gds_server *s, const gds_dialog_def *def, gds_dialog *d) {
    UA_NodeId want = UA_NodeId_isNull(&def->dialogId)
                         ? UA_NODEID_NUMERIC(def->sourceNode.namespaceIndex, 0)
                         : def->dialogId;
    UA_QualifiedName qn =
        UA_QUALIFIEDNAME(def->sourceNode.namespaceIndex, (char *)(uintptr_t)def->name);
    UA_StatusCode r = UA_Server_createCondition(s->ua, want, UA_NS0ID(DIALOGCONDITIONTYPE), qn,
                                                def->sourceNode, UA_NS0ID(HASCOMPONENT), &d->id);
    (void)gds_alarms_bind_ack(s); /* createCondition rebound open62541's */
    if(r != UA_STATUSCODE_GOOD)
        return r == UA_STATUSCODE_BADNODEIDEXISTS ? GDS_EEXISTS : GDS_EINVAL;
    gds_status st = UA_NodeId_copy(&def->sourceNode, &d->source) == UA_STATUSCODE_GOOD
                        ? GDS_OK
                        : GDS_ENOMEM;
    if(st == GDS_OK)
        st = gds_cond_restrict(s, &d->id, def->visibleTo, def->visibleToSize);
    /* Respond2 is Optional and not instantiated (as for approvals) */
    if(st == GDS_OK &&
       (UA_Server_addReference(
            s->ua, d->id, UA_NS0ID(HASCOMPONENT),
            UA_EXPANDEDNODEID_NUMERIC(0, UA_NS0ID_DIALOGCONDITIONTYPE_RESPOND2),
            true) != UA_STATUSCODE_GOOD ||
        set_fields(s->ua, d->id, def) != UA_STATUSCODE_GOOD))
        st = GDS_EINVAL;
    if(st == GDS_OK)
        d->respondId = respond_child(s->ua, &d->id);
    if(st != GDS_OK) {
        gds_cond_unrestrict(s, &d->id);
        (void)UA_Server_deleteCondition(s->ua, d->id, def->sourceNode);
    }
    return st;
}

static gds_status insert(gds_server *s, gds_dialog *d) {
    gds_status st = GDS_OK;
    pthread_mutex_lock(&s->dialogLock);
    if(s->nDialogs == s->capDialogs) {
        size_t cap = s->capDialogs ? 2 * s->capDialogs : 16;
        gds_dialog **nd = (gds_dialog **)realloc((void *)s->dialogs, cap * sizeof(gds_dialog *));
        if(nd) {
            s->dialogs = nd;
            s->capDialogs = cap;
        }
    }
    if(s->nDialogs < s->capDialogs)
        s->dialogs[s->nDialogs++] = d;
    else
        st = GDS_ENOMEM;
    pthread_mutex_unlock(&s->dialogLock);
    return st;
}

static gds_status reserve(gds_server *s, int delta) {
    pthread_mutex_lock(&s->dialogLock);
    gds_status st = GDS_OK;
    if(delta > 0 && s->nDialogs + s->dialogsReserved >= GDS_MAX_DIALOGS)
        st = GDS_ETOOBIG;
    else if(delta > 0)
        s->dialogsReserved++;
    else if(s->dialogsReserved > 0)
        s->dialogsReserved--;
    pthread_mutex_unlock(&s->dialogLock);
    return st;
}

gds_status gds_server_add_dialog(gds_server *s, const gds_dialog_def *def, UA_NodeId *dialogId) {
    if(dialogId)
        UA_NodeId_init(dialogId);
    if(!s || !dialogId || !def_ok(def))
        return GDS_EINVAL;
    if(def->sourceNode.namespaceIndex == 0 || def->sourceNode.namespaceIndex == s->ns ||
       (!UA_NodeId_isNull(&def->dialogId) &&
        (def->dialogId.namespaceIndex == 0 || def->dialogId.namespaceIndex == s->ns)))
        return GDS_EDENIED;
    UA_NodeClass nc = UA_NODECLASS_UNSPECIFIED;
    if(UA_Server_readNodeClass(s->ua, def->sourceNode, &nc) != UA_STATUSCODE_GOOD ||
       nc != UA_NODECLASS_OBJECT)
        return GDS_ENOTFOUND;
    gds_status ps = gds_embed_pool_start(s); /* Respond runs on a worker */
    if(ps != GDS_OK)
        return ps;
    if(reserve(s, 1) != GDS_OK)
        return GDS_ETOOBIG;
    gds_dialog *d = calloc(1, sizeof(*d));
    gds_status st = d ? GDS_OK : GDS_ENOMEM;
    if(st == GDS_OK) {
        d->nOptions = def->responseOptionsSize;
        d->fn = def->respond;
        d->ctx = def->ctx;
        d->active = true;
        st = gds_role_bits(s, def->respondRoles, def->respondRolesSize, &d->respondBits,
                           &d->respondAnon, &d->respondAuth);
    }
    bool created = false;
    if(st == GDS_OK) {
        st = create(s, def, d);
        created = st == GDS_OK;
    }
    if(st == GDS_OK && UA_NodeId_copy(&d->id, dialogId) != UA_STATUSCODE_GOOD)
        st = GDS_ENOMEM;
    if(st == GDS_OK)
        st = insert(s, d);
    (void)reserve(s, -1);
    if(st == GDS_OK) {
        UA_StatusCode r = UA_Server_triggerConditionEvent(s->ua, d->id, d->source, NULL);
        if(r != UA_STATUSCODE_GOOD)
            fprintf(stderr, "opengds: a dialog's first event: %s\n", UA_StatusCode_name(r));
        return GDS_OK;
    }
    UA_NodeId_clear(dialogId);
    if(created) {
        gds_cond_unrestrict(s, &d->id);
        (void)UA_Server_deleteCondition(s->ua, d->id, d->source);
    }
    dialog_free(d);
    return st;
}

gds_status gds_server_remove_dialog(gds_server *s, const UA_NodeId *dialogId) {
    if(!s || !dialogId)
        return GDS_EINVAL;
    gds_dialog *d = NULL;
    pthread_mutex_lock(&s->dialogLock);
    for(size_t i = 0; i < s->nDialogs; i++) {
        if(UA_NodeId_equal(&s->dialogs[i]->id, dialogId)) {
            d = s->dialogs[i];
            s->dialogs[i] = s->dialogs[--s->nDialogs];
            break;
        }
    }
    bool active = d && d->active;
    pthread_mutex_unlock(&s->dialogLock);
    if(!d)
        return GDS_ENOTFOUND;
    if(active) {
        UA_StatusCode r = close_fields(s, &d->id, &d->source, -1, NULL, NULL);
        if(r != UA_STATUSCODE_GOOD)
            fprintf(stderr, "opengds: closing a removed dialog: %s\n", UA_StatusCode_name(r));
    }
    (void)UA_Server_deleteCondition(s->ua, d->id, d->source);
    gds_cond_unrestrict(s, &d->id);
    dialog_free(d);
    return GDS_OK;
}

void gds_dialogs_free(gds_server *s) {
    for(size_t i = 0; i < s->nDialogs; i++)
        dialog_free(s->dialogs[i]);
    free((void *)s->dialogs);
    s->dialogs = NULL;
    s->nDialogs = s->capDialogs = 0;
}
