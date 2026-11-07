/* OpenGDS - plugin alarms (UASM ask A16): Part 9 AlarmConditionType
 * instances that a plugin raises and clears, such as the SKS running out
 * of pre-generated keys without a majority or a cluster node losing its
 * majority.
 *
 * - gds_server_add_alarm creates the condition (OffNormalAlarmType by
 *   default) as a HasComponent child of the plugin's source object, with
 *   EnabledState Enabled, ActiveState Inactive, AckedState Acknowledged and
 *   Retain false. open62541 links the source to the Server object with
 *   HasEventSource, so events reach subscribers of the Server object.
 * - gds_server_set_alarm queues the new state; the server thread applies it
 *   in call order: ActiveState, LastSeverity, Severity, Message, AckedState
 *   (Unacknowledged on each activation of an alarm that needs
 *   acknowledgement) and Retain (OPC 10000-9 §5.5.2: TRUE while Active or
 *   not yet acknowledged), then the event (§5.8: every state change is
 *   reported by an event of the alarm's type).
 * - Acknowledge (§5.7.3) is OpenGDS's own handler, for plugin alarms only
 *   (open62541 binds its own to the type's method at every
 *   UA_Server_createCondition, so it is bound again after each one):
 *   the EventId must be the alarm's last one (Bad_EventIdUnknown), the
 *   alarm must be retained (Bad_ConditionDisabled) and unacknowledged
 *   (Bad_ConditionBranchAlreadyAcked). The caller needs one of the alarm's
 *   ackRoles over a SignAndEncrypt session. It emits
 *   AuditConditionAcknowledgeEventType (§5.10.4) through the audit log,
 *   visible to the ackRoles.
 * - ConditionRefresh (§5.5.7) is open62541's: it replays every retained
 *   condition between RefreshStart and RefreshEnd.
 * The alarm state lives on the server thread; alarmLock (a leaf lock)
 * guards only the alarm list and the queue.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/limits.h"
#include "gds_internal.h"
#include "common/banned.h"

struct gds_alarm {
    gds_server *s;
    UA_NodeId id;     /* the condition */
    UA_NodeId source; /* its source object */
    bool needsAck;
    unsigned ackBits; /* gds_role bits of ackRoles */
    bool ackAnon, ackAuth;
    UA_NodeId *ackRoles; /* for the audit event's visibleTo */
    size_t nAckRoles;
    /* server thread only */
    bool active, acked;
    UA_UInt16 severity;
    UA_ByteString lastEventId;
};

/* ---- condition fields (shared with gds_approvals.c) ---- */

UA_StatusCode gds_cond_set_field(UA_Server *ua, UA_NodeId c, const char *field, const void *v,
                                 const UA_DataType *t) {
    UA_Variant var;
    UA_Variant_setScalar(&var, (void *)(uintptr_t)v, t);
    return UA_Server_setConditionField(ua, c, &var,
                                       UA_QUALIFIEDNAME(0, (char *)(uintptr_t)field));
}

UA_StatusCode gds_cond_set_two_state(UA_Server *ua, UA_NodeId c, const char *field, UA_Boolean id,
                                     const char *text) {
    UA_LocalizedText lt = UA_LOCALIZEDTEXT("en", (char *)(uintptr_t)text);
    UA_StatusCode r = gds_cond_set_field(ua, c, field, &lt, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    UA_Variant var;
    UA_Variant_setScalar(&var, &id, &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_setConditionVariableFieldProperty(
            ua, c, &var, UA_QUALIFIEDNAME(0, (char *)(uintptr_t)field), UA_QUALIFIEDNAME(0, "Id"));
    return r;
}

/* UA_Server_setConditionField refuses arrays in v1.5.10: write the
 * variable directly (spike workaround 2). */
UA_StatusCode gds_cond_set_array(UA_Server *ua, UA_NodeId c, const char *field, const void *v,
                                 size_t n, const UA_DataType *t) {
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

/* ---- who receives a condition's events (A19) ----
 * Conditions with visibleTo Roles are in s->vis; open62541 asks
 * gds_cond_may_receive (through the access control's allowReceiveEvent,
 * patch 0006) for each MonitoredItem an event would reach, live and in
 * ConditionRefresh. visLock is a leaf lock, taken under open62541's
 * service mutex. */

struct gds_cond_vis {
    UA_NodeId cond;
    unsigned bits;
    bool anon, auth;
};

gds_status gds_cond_restrict(gds_server *s, const UA_NodeId *cond, const UA_NodeId *roles,
                             size_t n) {
    if(n == 0)
        return GDS_OK;
    gds_cond_vis v;
    memset(&v, 0, sizeof(v));
    gds_status st = gds_role_bits(s, roles, n, &v.bits, &v.anon, &v.auth);
    if(st != GDS_OK)
        return st;
    if(UA_NodeId_copy(cond, &v.cond) != UA_STATUSCODE_GOOD)
        return GDS_ENOMEM;
    pthread_mutex_lock(&s->visLock);
    if(s->nVis == s->capVis) {
        size_t cap = s->capVis ? 2 * s->capVis : 16;
        gds_cond_vis *nv = realloc(s->vis, cap * sizeof(*nv));
        if(nv) {
            s->vis = nv;
            s->capVis = cap;
        }
    }
    if(s->nVis < s->capVis)
        s->vis[s->nVis++] = v;
    else
        st = GDS_ENOMEM;
    pthread_mutex_unlock(&s->visLock);
    if(st != GDS_OK)
        UA_NodeId_clear(&v.cond);
    return st;
}

void gds_cond_unrestrict(gds_server *s, const UA_NodeId *cond) {
    pthread_mutex_lock(&s->visLock);
    for(size_t i = 0; i < s->nVis; i++) {
        if(UA_NodeId_equal(&s->vis[i].cond, cond)) {
            UA_NodeId_clear(&s->vis[i].cond);
            s->vis[i] = s->vis[--s->nVis];
            break;
        }
    }
    pthread_mutex_unlock(&s->visLock);
}

static const gds_cond_vis *vis_of(const gds_server *s, const UA_NodeId *id) {
    for(size_t i = 0; id && i < s->nVis; i++)
        if(UA_NodeId_equal(&s->vis[i].cond, id))
            return &s->vis[i];
    return NULL;
}

bool gds_cond_may_receive(gds_server *s, const void *sessionContext, const UA_NodeId *source,
                          const UA_NodeId *instance) {
    if(!s)
        return true;
    const gds_session *ss = gds_session_get(sessionContext);
    bool anon = !ss || gds_session_anonymous(ss);
    unsigned roles = ss ? gds_session_roles(ss) : 0;
    pthread_mutex_lock(&s->visLock);
    bool ok = true;
    /* the condition's own events, and events about it (its audit events) */
    const gds_cond_vis *v[2] = {vis_of(s, instance), vis_of(s, source)};
    for(size_t i = 0; i < 2 && ok; i++)
        if(v[i])
            ok = ss && (v[i]->anon || (v[i]->auth && !anon) || (roles & v[i]->bits) != 0);
    pthread_mutex_unlock(&s->visLock);
    return ok;
}

void gds_cond_vis_free(gds_server *s) {
    for(size_t i = 0; i < s->nVis; i++)
        UA_NodeId_clear(&s->vis[i].cond);
    free(s->vis);
    s->vis = NULL;
    s->nVis = s->capVis = 0;
}

/* ---- lookup ---- */

static gds_alarm *find_locked(gds_server *s, const UA_NodeId *id) {
    for(size_t i = 0; id && i < s->nAlarms; i++)
        if(UA_NodeId_equal(&s->alarms[i]->id, id))
            return s->alarms[i];
    return NULL;
}

static gds_alarm *find(gds_server *s, const UA_NodeId *id) {
    pthread_mutex_lock(&s->alarmLock);
    gds_alarm *a = find_locked(s, id);
    pthread_mutex_unlock(&s->alarmLock);
    return a; /* alarms live as long as the server */
}

bool gds_alarm_may_ack(gds_server *s, const void *sessionContext, const UA_NodeId *conditionId) {
    const gds_session *ss = gds_session_get(sessionContext);
    gds_alarm *a = s ? find(s, conditionId) : NULL;
    if(!a || !a->needsAck || !ss || ss->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return false;
    bool anon = gds_session_anonymous(ss);
    return a->ackAnon || (a->ackAuth && !anon) || (gds_session_roles(ss) & a->ackBits) != 0;
}

/* ---- apply a state, on the server thread ---- */

static UA_StatusCode trigger(gds_alarm *a) {
    UA_ByteString id = UA_BYTESTRING_NULL;
    UA_StatusCode r = UA_Server_triggerConditionEvent(a->s->ua, a->id, a->source, &id);
    if(r == UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(&a->lastEventId);
        a->lastEventId = id;
    }
    return r;
}

static UA_StatusCode set_retain(gds_alarm *a) {
    UA_Boolean retain = a->active || !a->acked;
    return gds_cond_set_field(a->s->ua, a->id, "Retain", &retain, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static UA_StatusCode apply(const gds_alarm_op *op) {
    gds_alarm *a = op->a;
    UA_Server *ua = a->s->ua;
    bool rising = op->active && !a->active;
    UA_LocalizedText msg =
        UA_LOCALIZEDTEXT("", op->message ? op->message : (char *)(uintptr_t)"");
    UA_UInt16 last = a->severity, sev = op->severity;
    UA_StatusCode r = gds_cond_set_two_state(ua, a->id, "ActiveState", op->active,
                                             op->active ? "Active" : "Inactive");
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_field(ua, a->id, "LastSeverity", &last, &UA_TYPES[UA_TYPES_UINT16]);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_field(ua, a->id, "Severity", &sev, &UA_TYPES[UA_TYPES_UINT16]);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_field(ua, a->id, "Message", &msg, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    if(r == UA_STATUSCODE_GOOD && rising && a->needsAck) {
        r = gds_cond_set_two_state(ua, a->id, "AckedState", false, "Unacknowledged");
        if(r == UA_STATUSCODE_GOOD)
            a->acked = false;
    }
    if(r == UA_STATUSCODE_GOOD) {
        a->active = op->active;
        a->severity = sev;
        r = set_retain(a);
    }
    if(r == UA_STATUSCODE_GOOD)
        r = trigger(a);
    return r;
}

static void drain_cb(UA_Server *ua, void *data) {
    (void)ua;
    gds_server *s = data;
    for(;;) {
        gds_alarm_op op;
        pthread_mutex_lock(&s->alarmLock);
        bool have = s->nAlarmOps > 0;
        if(have) {
            op = s->alarmOps[s->alarmOpHead];
            s->alarmOpHead = (s->alarmOpHead + 1) % GDS_ALARM_QUEUE;
            s->nAlarmOps--;
        } else {
            s->alarmDrainScheduled = false;
        }
        pthread_mutex_unlock(&s->alarmLock);
        if(!have)
            return;
        UA_StatusCode r = apply(&op);
        if(r != UA_STATUSCODE_GOOD)
            fprintf(stderr, "opengds: alarm state not applied: %s\n", UA_StatusCode_name(r));
        free(op.message);
    }
}

/* ---- the plugin API ---- */

/* visibleTo came with A19: older plugins pass a shorter struct. */
static bool has_visible_to(const gds_alarm_def *d) {
    return d->struct_size >= offsetof(gds_alarm_def, visibleToSize) + sizeof(size_t) &&
           d->visibleToSize > 0;
}

static bool def_ok(const gds_alarm_def *d) {
    return d && d->abi_major == GDS_PLUGIN_ABI_MAJOR &&
           d->struct_size >= offsetof(gds_alarm_def, ackRolesSize) + sizeof(size_t) && d->name &&
           d->name[0] && strnlen(d->name, GDS_MAX_STRING + 1) <= GDS_MAX_STRING &&
           d->ackRolesSize <= GDS_MAX_CALLER_ROLES && (d->ackRolesSize == 0 || d->ackRoles) &&
           !UA_NodeId_isNull(&d->sourceNode) &&
           (!has_visible_to(d) || d->visibleToSize <= GDS_MAX_CALLER_ROLES);
}

static gds_status set_ack_roles(gds_server *s, const gds_alarm_def *def, gds_alarm *a) {
    a->needsAck = def->ackRolesSize > 0;
    if(!a->needsAck)
        return GDS_OK;
    gds_status st = gds_role_bits(s, def->ackRoles, def->ackRolesSize, &a->ackBits, &a->ackAnon,
                                  &a->ackAuth);
    if(st != GDS_OK)
        return st;
    a->ackRoles = calloc(def->ackRolesSize, sizeof(UA_NodeId));
    if(!a->ackRoles)
        return GDS_ENOMEM;
    for(size_t i = 0; i < def->ackRolesSize; i++)
        if(UA_NodeId_copy(&def->ackRoles[i], &a->ackRoles[a->nAckRoles++]) != UA_STATUSCODE_GOOD)
            return GDS_ENOMEM;
    return GDS_OK;
}

static void alarm_free(gds_alarm *a) {
    if(!a)
        return;
    UA_NodeId_clear(&a->id);
    UA_NodeId_clear(&a->source);
    UA_Array_delete(a->ackRoles, a->nAckRoles, &UA_TYPES[UA_TYPES_NODEID]);
    UA_ByteString_clear(&a->lastEventId);
    free(a);
}

/* open62541 hangs its own state machine on the Id of EnabledState,
 * ActiveState and AckedState and on Severity: a write fires events and
 * rewrites Message and other fields (and is undone while Retain is
 * false). OpenGDS drives these alarms itself, so the hooks go. */
UA_StatusCode gds_cond_detach_hook(UA_Server *ua, UA_NodeId c, const char *field,
                                   const char *sub) {
    UA_QualifiedName path[2] = {UA_QUALIFIEDNAME(0, (char *)(uintptr_t)field),
                                UA_QUALIFIEDNAME(0, (char *)(uintptr_t)(sub ? sub : ""))};
    UA_BrowsePathResult bp = UA_Server_browseSimplifiedBrowsePath(ua, c, sub ? 2 : 1, path);
    UA_StatusCode r = bp.statusCode;
    if(r == UA_STATUSCODE_GOOD && bp.targetsSize != 1)
        r = UA_STATUSCODE_BADNOTFOUND;
    if(r == UA_STATUSCODE_GOOD) {
        UA_ValueCallback none = {NULL, NULL};
        r = UA_Server_setVariableNode_valueCallback(ua, bp.targets[0].targetId.nodeId, none);
    }
    UA_BrowsePathResult_clear(&bp);
    return r;
}

static UA_StatusCode detach_hooks(UA_Server *ua, UA_NodeId c) {
    static const char *const fields[][2] = {{"EnabledState", "Id"},
                                            {"ActiveState", "Id"},
                                            {"AckedState", "Id"},
                                            {"Severity", NULL}};
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < 4 && r == UA_STATUSCODE_GOOD; i++)
        r = gds_cond_detach_hook(ua, c, fields[i][0], fields[i][1]);
    return r;
}

/* The initial fields; ActiveState fails for a type that is no alarm. */
static UA_StatusCode initial_fields(gds_alarm *a) {
    UA_Server *ua = a->s->ua;
    UA_UInt16 sev = a->severity;
    UA_LocalizedText none = UA_LOCALIZEDTEXT("", "");
    UA_StatusCode r = detach_hooks(ua, a->id);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_two_state(ua, a->id, "EnabledState", true, "Enabled");
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_two_state(ua, a->id, "ActiveState", false, "Inactive");
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_two_state(ua, a->id, "AckedState", true, "Acknowledged");
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_field(ua, a->id, "Severity", &sev, &UA_TYPES[UA_TYPES_UINT16]);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_field(ua, a->id, "LastSeverity", &sev, &UA_TYPES[UA_TYPES_UINT16]);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_cond_set_field(ua, a->id, "Message", &none, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    if(r == UA_STATUSCODE_GOOD)
        r = set_retain(a);
    return r;
}

static gds_status create(gds_server *s, const gds_alarm_def *def, gds_alarm *a) {
    UA_NodeId type = UA_NodeId_isNull(&def->alarmType) ? UA_NS0ID(OFFNORMALALARMTYPE)
                                                       : def->alarmType;
    UA_NodeId want = UA_NodeId_isNull(&def->alarmId)
                         ? UA_NODEID_NUMERIC(def->sourceNode.namespaceIndex, 0)
                         : def->alarmId;
    UA_QualifiedName qn =
        UA_QUALIFIEDNAME(def->sourceNode.namespaceIndex, (char *)(uintptr_t)def->name);
    UA_StatusCode r = UA_Server_createCondition(s->ua, want, type, qn, def->sourceNode,
                                                UA_NS0ID(HASCOMPONENT), &a->id);
    (void)gds_alarms_bind_ack(s);
    if(r != UA_STATUSCODE_GOOD)
        return r == UA_STATUSCODE_BADNODEIDEXISTS ? GDS_EEXISTS : GDS_EINVAL;
    if(UA_NodeId_copy(&def->sourceNode, &a->source) != UA_STATUSCODE_GOOD) {
        (void)UA_Server_deleteCondition(s->ua, a->id, def->sourceNode);
        return GDS_ENOMEM;
    }
    a->acked = true;
    a->severity = 1;
    if(initial_fields(a) != UA_STATUSCODE_GOOD) {
        (void)UA_Server_deleteCondition(s->ua, a->id, a->source);
        return GDS_EINVAL;
    }
    return GDS_OK;
}

gds_status gds_server_add_alarm(gds_server *s, const gds_alarm_def *def, gds_alarm **out) {
    if(out)
        *out = NULL;
    if(!s || !out || !def_ok(def))
        return GDS_EINVAL;
    if(def->sourceNode.namespaceIndex == s->ns ||
       (!UA_NodeId_isNull(&def->alarmId) && def->alarmId.namespaceIndex == s->ns))
        return GDS_EDENIED;
    UA_NodeClass nc = UA_NODECLASS_UNSPECIFIED;
    if(UA_Server_readNodeClass(s->ua, def->sourceNode, &nc) != UA_STATUSCODE_GOOD ||
       nc != UA_NODECLASS_OBJECT)
        return GDS_ENOTFOUND;
    pthread_mutex_lock(&s->alarmLock);
    bool full = s->nAlarms == GDS_MAX_ALARMS;
    if(!full)
        s->nAlarms++; /* reserve the slot */
    pthread_mutex_unlock(&s->alarmLock);
    if(full)
        return GDS_ETOOBIG;
    gds_alarm *a = calloc(1, sizeof(*a));
    gds_status st = a ? GDS_OK : GDS_ENOMEM;
    if(st == GDS_OK) {
        a->s = s;
        st = set_ack_roles(s, def, a);
    }
    if(st == GDS_OK)
        st = create(s, def, a);
    if(st == GDS_OK && has_visible_to(def)) {
        st = gds_cond_restrict(s, &a->id, def->visibleTo, def->visibleToSize);
        if(st != GDS_OK)
            (void)UA_Server_deleteCondition(s->ua, a->id, a->source);
    }
    pthread_mutex_lock(&s->alarmLock);
    s->nAlarms--;
    if(st == GDS_OK)
        s->alarms[s->nAlarms++] = a;
    pthread_mutex_unlock(&s->alarmLock);
    if(st != GDS_OK) {
        alarm_free(a);
        return st;
    }
    *out = a;
    return GDS_OK;
}

gds_status gds_server_set_alarm(gds_alarm *a, bool active, uint16_t severity,
                                const char *message) {
    if(!a || severity < 1 || severity > 1000 ||
       (message && strnlen(message, GDS_MAX_STRING + 1) > GDS_MAX_STRING))
        return GDS_EINVAL;
    char *copy = NULL;
    if(message) {
        size_t n = strlen(message);
        copy = malloc(n + 1);
        if(!copy)
            return GDS_ENOMEM;
        memcpy(copy, message, n + 1);
    }
    gds_server *s = a->s;
    pthread_mutex_lock(&s->alarmLock);
    if(s->nAlarmOps == GDS_ALARM_QUEUE) {
        pthread_mutex_unlock(&s->alarmLock);
        free(copy);
        return GDS_ETOOBIG;
    }
    size_t tail = (s->alarmOpHead + s->nAlarmOps) % GDS_ALARM_QUEUE;
    s->alarmOps[tail] = (gds_alarm_op){a, active, severity, copy};
    s->nAlarmOps++;
    bool schedule = !s->alarmDrainScheduled;
    s->alarmDrainScheduled = true;
    pthread_mutex_unlock(&s->alarmLock);
    if(schedule &&
       UA_Server_addTimedCallback(s->ua, drain_cb, s, UA_DateTime_nowMonotonic(), NULL) !=
           UA_STATUSCODE_GOOD) {
        pthread_mutex_lock(&s->alarmLock);
        s->alarmDrainScheduled = false; /* the next call tries again */
        pthread_mutex_unlock(&s->alarmLock);
        return GDS_ENOMEM;
    }
    return GDS_OK;
}

/* ---- Acknowledge (OPC 10000-9 §5.7.3) ---- */

static void ack_audit(gds_alarm *a, const gds_session *ss, const UA_ByteString *eventId,
                      const UA_LocalizedText *comment, bool ok) {
    gds_caller c;
    memset(&c, 0, sizeof(c));
    c.abi_major = GDS_PLUGIN_ABI_MAJOR;
    c.abi_minor = GDS_PLUGIN_ABI_MINOR;
    c.struct_size = sizeof(c);
    c.userName = gds_session_anonymous(ss) ? NULL : ss->user;
    gds_event_field f[2];
    memset(f, 0, sizeof(f));
    f[0].name = "ConditionEventId";
    UA_Variant_setScalar(&f[0].value, (void *)(uintptr_t)eventId, &UA_TYPES[UA_TYPES_BYTESTRING]);
    f[1].name = "Comment";
    UA_Variant_setScalar(&f[1].value, (void *)(uintptr_t)comment,
                         &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    gds_audit_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.abi_major = GDS_PLUGIN_ABI_MAJOR;
    ev.abi_minor = GDS_PLUGIN_ABI_MINOR;
    ev.struct_size = sizeof(ev);
    ev.eventType = UA_NS0ID(AUDITCONDITIONACKNOWLEDGEEVENTTYPE);
    ev.sourceNode = a->id;
    ev.severity = 500;
    ev.message = ok ? "Alarm acknowledged" : "Alarm acknowledgement refused";
    ev.status = ok;
    ev.fields = f;
    ev.fieldsSize = 2;
    ev.visibleTo = a->ackRoles;
    ev.visibleToSize = a->nAckRoles;
    if(gds_server_raise_audit_event(a->s, &c, &ev, NULL) != GDS_OK)
        fprintf(stderr, "opengds: alarm acknowledgement not audited\n");
}

static UA_StatusCode ack_apply(gds_alarm *a, const UA_LocalizedText *comment) {
    UA_Server *ua = a->s->ua;
    UA_StatusCode r = gds_cond_set_two_state(ua, a->id, "AckedState", true, "Acknowledged");
    if(r == UA_STATUSCODE_GOOD && comment->text.length > 0)
        r = gds_cond_set_field(ua, a->id, "Comment", comment, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    if(r == UA_STATUSCODE_GOOD) {
        a->acked = true;
        r = set_retain(a);
    }
    if(r == UA_STATUSCODE_GOOD)
        r = trigger(a);
    return r;
}

static GDS_METHOD(acknowledge) {
    GDS_METHOD_UNUSED, (void)output;
    gds_server *s = gds_ctx(methodContext);
    if(inputSize != 2 || !UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_BYTESTRING]) ||
       !UA_Variant_hasScalarType(&input[1], &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]))
        return inputSize < 2 ? UA_STATUSCODE_BADARGUMENTSMISSING
               : inputSize > 2 ? UA_STATUSCODE_BADTOOMANYARGUMENTS
                               : UA_STATUSCODE_BADTYPEMISMATCH;
    gds_alarm *a = find(s, objectId);
    if(!a)
        return UA_STATUSCODE_BADMETHODINVALID;
    if(!gds_alarm_may_ack(s, sessionContext, objectId))
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    const UA_ByteString *eventId = input[0].data;
    const UA_LocalizedText *comment = input[1].data;
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    if(!UA_ByteString_equal(eventId, &a->lastEventId))
        r = UA_STATUSCODE_BADEVENTIDUNKNOWN;
    else if(!(a->active || !a->acked))
        r = UA_STATUSCODE_BADCONDITIONDISABLED; /* not retained */
    else if(a->acked)
        r = UA_STATUSCODE_BADCONDITIONBRANCHALREADYACKED;
    else
        r = ack_apply(a, comment);
    ack_audit(a, gds_session_get(sessionContext), eventId, comment, r == UA_STATUSCODE_GOOD);
    return r;
}

UA_StatusCode gds_alarm_last_event_id(const gds_alarm *a, UA_ByteString *out) {
    return UA_ByteString_copy(&a->lastEventId, out);
}

/* ---- lifecycle ---- */

UA_StatusCode gds_alarms_bind_ack(gds_server *s) {
    UA_StatusCode r = UA_Server_setMethodNodeCallback(
        s->ua, UA_NS0ID(ACKNOWLEDGEABLECONDITIONTYPE_ACKNOWLEDGE), acknowledge);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_setNodeContext(s->ua, UA_NS0ID(ACKNOWLEDGEABLECONDITIONTYPE_ACKNOWLEDGE), s);
    return r;
}

UA_StatusCode gds_alarms_install(gds_server *s) {
    UA_Server *ua = s->ua;
    UA_StatusCode r = gds_alarms_bind_ack(s);
    /* one ConditionRefresh carries every retained alarm and dialog */
    UA_ServerConfig *cfg = UA_Server_getConfig(ua);
    size_t need = GDS_MAX_PENDING_APPROVALS + GDS_MAX_ALARMS + 2u; /* + RefreshStart/End */
    if(cfg->queueSizeLimits.max < need)
        cfg->queueSizeLimits.max = (UA_UInt32)need;
    return r;
}

void gds_alarms_free(gds_server *s) {
    for(size_t i = 0; i < s->nAlarms; i++)
        alarm_free(s->alarms[i]);
    s->nAlarms = 0;
    for(size_t i = 0; i < s->nAlarmOps; i++)
        free(s->alarmOps[(s->alarmOpHead + i) % GDS_ALARM_QUEUE].message);
    s->nAlarmOps = 0;
}
