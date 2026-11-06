/* OpenGDS - audit events of other parts (UASM ask A7, issue #18).
 *
 * Order: check the event, encode it, append it to the store's audit log
 * (one transaction, hash-chained), and only then raise it, once per
 * permitted session (UA_Server_createEventEx with a sessionId). A refused
 * commit raises nothing, so every delivered audit event is in the log.
 *
 * Log body: the OPC UA binary encoding of a Variant array
 *   [0] ExpandedNodeId  eventType (with its namespace URI)
 *   [1] ExpandedNodeId  sourceNode
 *   [2] UInt16          severity
 *   [3] String          message
 *   [4] Boolean         status
 *   [5] String          serverId
 *   [6] String          clientUserId
 *   [7] String[]        field names, "<namespace URI>#<BrowseName>"
 *   [8] Variant[]       field values
 * Namespace URIs, not indexes, so the log reads the same after a restart.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gds_internal.h"
#include "common/banned.h"

#define MAX_SUBTYPE_DEPTH 32
#define MAX_AUDIT_SESSIONS 1024
#define BODY_ITEMS 9

/* Is t AuditEventType or one of its subtypes (inverse HasSubtype)? */
static bool is_audit_type(UA_Server *ua, const UA_NodeId *t) {
    UA_NodeId audit = UA_NODEID_NUMERIC(0, UA_NS0ID_AUDITEVENTTYPE);
    UA_NodeId cur;
    if(UA_NodeId_copy(t, &cur) != UA_STATUSCODE_GOOD)
        return false;
    bool found = false;
    for(int depth = 0; depth < MAX_SUBTYPE_DEPTH && !found; depth++) {
        if(UA_NodeId_equal(&cur, &audit)) {
            found = true;
            break;
        }
        UA_BrowseDescription bd;
        UA_BrowseDescription_init(&bd);
        bd.nodeId = cur;
        bd.browseDirection = UA_BROWSEDIRECTION_INVERSE;
        bd.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASSUBTYPE);
        bd.includeSubtypes = false;
        bd.resultMask = UA_BROWSERESULTMASK_NONE;
        UA_BrowseResult br = UA_Server_browse(ua, 1, &bd);
        bool up = br.statusCode == UA_STATUSCODE_GOOD && br.referencesSize == 1 &&
                  UA_ExpandedNodeId_isLocal(&br.references[0].nodeId);
        UA_NodeId next = UA_NODEID_NULL;
        if(up && UA_NodeId_copy(&br.references[0].nodeId.nodeId, &next) != UA_STATUSCODE_GOOD)
            up = false;
        UA_BrowseResult_clear(&br);
        UA_NodeId_clear(&cur);
        if(!up)
            return false;
        cur = next;
    }
    UA_NodeId_clear(&cur);
    return found;
}

static UA_StatusCode expanded(UA_Server *ua, const UA_NodeId *id, UA_ExpandedNodeId *out) {
    UA_ExpandedNodeId_init(out);
    UA_StatusCode r = UA_NodeId_copy(id, &out->nodeId);
    if(r == UA_STATUSCODE_GOOD && id->namespaceIndex != 0)
        r = UA_Server_getNamespaceByIndex(ua, id->namespaceIndex, &out->namespaceUri);
    return r;
}

static UA_StatusCode field_name(UA_Server *ua, const gds_event_field *f, UA_String *out) {
    UA_String uri = UA_STRING_NULL;
    UA_StatusCode r = UA_Server_getNamespaceByIndex(ua, f->nsIndex, &uri);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    size_t nl = strlen(f->name);
    *out = UA_STRING_NULL;
    out->data = UA_malloc(uri.length + 1 + nl);
    if(!out->data) {
        UA_String_clear(&uri);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    if(uri.length)
        memcpy(out->data, uri.data, uri.length);
    out->data[uri.length] = '#';
    memcpy(out->data + uri.length + 1, f->name, nl);
    out->length = uri.length + 1 + nl;
    UA_String_clear(&uri);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode encode_body(gds_server *s, const gds_audit_event *ev, const UA_NodeId *source,
                                 const UA_String *clientUser, UA_ByteString *out) {
    UA_Variant items[BODY_ITEMS];
    for(size_t i = 0; i < BODY_ITEMS; i++)
        UA_Variant_init(&items[i]);
    UA_ExpandedNodeId type, src;
    UA_StatusCode r = expanded(s->ua, &ev->eventType, &type);
    if(r == UA_STATUSCODE_GOOD)
        r = expanded(s->ua, source, &src);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&items[0], &type, &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&items[1], &src, &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
    UA_ExpandedNodeId_clear(&type);
    UA_ExpandedNodeId_clear(&src);
    UA_String msg = ev->message ? UA_STRING((char *)(uintptr_t)ev->message) : UA_STRING_NULL;
    UA_Boolean status = ev->status;
    const UA_String *serverId = &UA_Server_getConfig(s->ua)->applicationDescription.applicationUri;
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&items[2], &ev->severity, &UA_TYPES[UA_TYPES_UINT16]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&items[3], &msg, &UA_TYPES[UA_TYPES_STRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&items[4], &status, &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&items[5], serverId, &UA_TYPES[UA_TYPES_STRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&items[6], clientUser, &UA_TYPES[UA_TYPES_STRING]);
    UA_String *names = NULL;
    UA_Variant *values = NULL;
    if(r == UA_STATUSCODE_GOOD && ev->fieldsSize > 0) {
        names = UA_Array_new(ev->fieldsSize, &UA_TYPES[UA_TYPES_STRING]);
        values = UA_Array_new(ev->fieldsSize, &UA_TYPES[UA_TYPES_VARIANT]);
        if(!names || !values)
            r = UA_STATUSCODE_BADOUTOFMEMORY;
        for(size_t i = 0; i < ev->fieldsSize && r == UA_STATUSCODE_GOOD; i++) {
            r = field_name(s->ua, &ev->fields[i], &names[i]);
            if(r == UA_STATUSCODE_GOOD)
                r = UA_Variant_copy(&ev->fields[i].value, &values[i]);
        }
    }
    if(r == UA_STATUSCODE_GOOD) {
        UA_Variant_setArray(&items[7], names, ev->fieldsSize, &UA_TYPES[UA_TYPES_STRING]);
        UA_Variant_setArray(&items[8], values, ev->fieldsSize, &UA_TYPES[UA_TYPES_VARIANT]);
        names = NULL;
        values = NULL;
        UA_Variant all;
        UA_Variant_setArray(&all, items, BODY_ITEMS, &UA_TYPES[UA_TYPES_VARIANT]);
        *out = UA_BYTESTRING_NULL;
        r = UA_encodeBinary(&all, &UA_TYPES[UA_TYPES_VARIANT], out, NULL);
    }
    if(names)
        UA_Array_delete(names, ev->fieldsSize, &UA_TYPES[UA_TYPES_STRING]);
    if(values)
        UA_Array_delete(values, ev->fieldsSize, &UA_TYPES[UA_TYPES_VARIANT]);
    for(size_t i = 0; i < BODY_ITEMS; i++)
        UA_Variant_clear(&items[i]);
    return r;
}

/* The OPC UA event's fields: AuditEventType's (OPC 10000-5 §6.4.3) and
 * the plugin's. Values are borrowed from ev and the locals of raise(). */
static UA_StatusCode event_fields(const gds_audit_event *ev, UA_DateTime *now, UA_Boolean *status,
                                  UA_String *serverId, UA_String *clientUser,
                                  UA_KeyValueMap *map) {
    char path[GDS_MAX_STRING + 2];
    UA_StatusCode r = UA_KeyValueMap_setScalar(map, UA_QUALIFIEDNAME(0, "/ActionTimeStamp"), now,
                                               &UA_TYPES[UA_TYPES_DATETIME]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_KeyValueMap_setScalar(map, UA_QUALIFIEDNAME(0, "/Status"), status,
                                     &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_KeyValueMap_setScalar(map, UA_QUALIFIEDNAME(0, "/ServerId"), serverId,
                                     &UA_TYPES[UA_TYPES_STRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_KeyValueMap_setScalar(map, UA_QUALIFIEDNAME(0, "/ClientUserId"), clientUser,
                                     &UA_TYPES[UA_TYPES_STRING]);
    for(size_t i = 0; i < ev->fieldsSize && r == UA_STATUSCODE_GOOD; i++) {
        int n = snprintf(path, sizeof(path), "/%s", ev->fields[i].name);
        if(n < 0 || (size_t)n >= sizeof(path))
            return UA_STATUSCODE_BADINVALIDARGUMENT;
        r = UA_KeyValueMap_set(map, UA_QUALIFIEDNAME(ev->fields[i].nsIndex, path),
                               &ev->fields[i].value);
    }
    return r;
}

static bool fields_ok(const gds_audit_event *ev) {
    if(ev->fieldsSize > GDS_MAX_AUDIT_FIELDS || (ev->fieldsSize && !ev->fields))
        return false;
    for(size_t i = 0; i < ev->fieldsSize; i++) {
        const char *n = ev->fields[i].name;
        size_t len = n ? strnlen(n, GDS_MAX_STRING + 1) : 0;
        if(len == 0 || len > GDS_MAX_STRING || strchr(n, '/'))
            return false;
    }
    return true;
}

static gds_status deliver(gds_server *s, const gds_audit_event *ev, const UA_NodeId *source,
                          unsigned bits, bool anon, bool auth, UA_KeyValueMap *map) {
    UA_NodeId *ids = calloc(MAX_AUDIT_SESSIONS, sizeof(*ids));
    if(!ids)
        return GDS_ENOMEM;
    size_t n = gds_access_sessions_with(bits, anon, auth, ids, MAX_AUDIT_SESSIONS);
    UA_LocalizedText msg =
        UA_LOCALIZEDTEXT("", ev->message ? (char *)(uintptr_t)ev->message : (char *)(uintptr_t)"");
    gds_status st = GDS_OK;
    for(size_t i = 0; i < n; i++) {
        UA_EventDescription ed;
        memset(&ed, 0, sizeof(ed));
        ed.sourceNode = *source;
        ed.eventType = ev->eventType;
        ed.severity = ev->severity;
        ed.message = msg;
        ed.eventFields = map;
        ed.sessionId = &ids[i];
        if(UA_Server_createEventEx(s->ua, &ed, NULL) != UA_STATUSCODE_GOOD)
            st = GDS_EIO; /* logged; the audit log already has it */
        UA_NodeId_clear(&ids[i]);
    }
    free(ids);
    return st;
}

gds_status gds_server_raise_audit_event(gds_server *s, const gds_caller *caller,
                                        const gds_audit_event *ev, int64_t *seq) {
    if(!s || !ev || ev->abi_major != GDS_PLUGIN_ABI_MAJOR ||
       ev->struct_size < offsetof(gds_audit_event, visibleToSize) + sizeof(size_t) ||
       ev->severity < 1 || ev->severity > 1000 || ev->visibleToSize == 0 || !fields_ok(ev) ||
       (ev->message && strnlen(ev->message, GDS_MAX_STRING + 1) > GDS_MAX_STRING) ||
       !is_audit_type(s->ua, &ev->eventType))
        return GDS_EINVAL;
    unsigned bits = 0;
    bool anon = false, auth = false;
    gds_status st = gds_role_bits(s, ev->visibleTo, ev->visibleToSize, &bits, &anon, &auth);
    if(st != GDS_OK)
        return st;
    UA_NodeId source = UA_NodeId_isNull(&ev->sourceNode) ? UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER)
                                                         : ev->sourceNode;
    UA_String clientUser = caller && caller->userName
                               ? UA_STRING((char *)(uintptr_t)caller->userName)
                               : UA_STRING_NULL;
    UA_ByteString body = UA_BYTESTRING_NULL;
    if(encode_body(s, ev, &source, &clientUser, &body) != UA_STATUSCODE_GOOD)
        return GDS_EINVAL;
    UA_DateTime now = UA_DateTime_now();
    gds_buf b = {body.data, body.length};
    int64_t got = 0;
    gds_lock(s);
    st = gds_store_audit_append(s->store, now, &b, &got);
    gds_unlock(s);
    UA_ByteString_clear(&body);
    if(st != GDS_OK)
        return st; /* not in the log: not raised */
    if(seq)
        *seq = got;

    UA_KeyValueMap map = UA_KEYVALUEMAP_NULL;
    UA_Boolean status = ev->status;
    UA_String serverId = UA_Server_getConfig(s->ua)->applicationDescription.applicationUri;
    if(event_fields(ev, &now, &status, &serverId, &clientUser, &map) == UA_STATUSCODE_GOOD)
        st = deliver(s, ev, &source, bits, anon, auth, &map);
    else
        st = GDS_EINVAL;
    UA_KeyValueMap_clear(&map);
    if(st != GDS_OK)
        fprintf(stderr, "opengds: audit event %lld logged but not raised: %s\n", (long long)got,
                gds_status_name(st));
    return GDS_OK; /* the log is the record; delivery is best effort */
}
