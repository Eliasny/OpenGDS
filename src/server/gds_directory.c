/* OpenGDS - Directory methods (OPC 10000-12 §6.5): FindApplications,
 * RegisterApplication, UpdateApplication, UnregisterApplication,
 * GetApplication, QueryApplications.
 * Access: changes need DiscoveryAdmin; GetApplication needs DiscoveryAdmin
 * or the application itself; Find and Query are open to every session on
 * an encrypted channel (§6.2).
 * SPDX-License-Identifier: MPL-2.0 */
#include <stdlib.h>
#include <string.h>

#include "common/ids.h"
#include "common/limits.h"
#include "gds_internal.h"
#include "common/banned.h"

static const UA_DataType *rec_type(void) {
    return &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE];
}

/* ---- FindApplications ---- */

static GDS_METHOD(find_applications) {
    GDS_METHOD_UNUSED;
    (void)sessionContext;
    gds_server *s = gds_ctx(methodContext);
    if(inputSize < 1)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const UA_String *uri = NULL;
    UA_StatusCode r = gds_arg_string(&input[0], GDS_MAX_APPLICATION_URI, &uri);
    if(r != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_ApplicationRecordDataType *found = NULL;
    size_t n = 0;
    gds_lock(s);
    gds_status st = gds_store_app_find_uri(s->store, uri, GDS_MAX_QUERY_RECORDS, &found, &n);
    gds_unlock(s);
    if(st != GDS_OK)
        return gds_status_to_ua(st);
    for(size_t i = 0; i < n; i++)
        found[i].applicationId.namespaceIndex = s->ns;
    if(n == 0) {
        UA_Variant_setArray(&output[0], UA_EMPTY_ARRAY_SENTINEL, 0, rec_type());
        return UA_STATUSCODE_GOOD;
    }
    UA_Variant_setArray(&output[0], found, n, rec_type());
    return UA_STATUSCODE_GOOD;
}

/* ---- RegisterApplication / UpdateApplication / UnregisterApplication ---- */

static GDS_METHOD(register_application) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    if(gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDSTATE;
    if(!gds_session_has(sessionContext, GDS_ROLE_DISCOVERY_ADMIN))
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    const UA_ApplicationRecordDataType *rec = NULL;
    UA_StatusCode r = gds_in_record(inputSize, input, 0, &rec);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_validate_record(rec);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_Guid id;
    if(gds_guid_random(&id) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    gds_lock(s);
    gds_status st = gds_store_app_insert(s->store, &id, rec);
    gds_unlock(s);
    if(st != GDS_OK)
        return gds_status_to_ua(st); /* duplicate ApplicationUri: Bad_AlreadyExists (G4) */
    UA_NodeId nid = UA_NODEID_GUID(s->ns, id);
    return UA_Variant_setScalarCopy(&output[0], &nid, &UA_TYPES[UA_TYPES_NODEID]);
}

static GDS_METHOD(update_application) {
    GDS_METHOD_UNUSED;
    (void)output;
    gds_server *s = gds_ctx(methodContext);
    if(gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDSTATE;
    if(!gds_session_has(sessionContext, GDS_ROLE_DISCOVERY_ADMIN))
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    const UA_ApplicationRecordDataType *rec = NULL;
    UA_StatusCode r = gds_in_record(inputSize, input, 0, &rec);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_validate_record(rec);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(rec->applicationId.identifierType != UA_NODEIDTYPE_GUID ||
       rec->applicationId.namespaceIndex != s->ns)
        return UA_STATUSCODE_BADNOTFOUND;
    gds_lock(s);
    gds_status st = gds_store_app_update(s->store, &rec->applicationId.identifier.guid, rec);
    gds_unlock(s);
    return gds_status_to_ua(st);
}

static GDS_METHOD(unregister_application) {
    GDS_METHOD_UNUSED;
    (void)output;
    gds_server *s = gds_ctx(methodContext);
    if(gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDSTATE;
    if(!gds_session_has(sessionContext, GDS_ROLE_DISCOVERY_ADMIN))
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    UA_Guid id;
    UA_StatusCode r = gds_in_guid(s, inputSize, input, 0, &id);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    gds_lock(s);
    gds_status st = gds_store_app_delete(s->store, &id);
    gds_unlock(s);
    return gds_status_to_ua(st);
}

/* ---- GetApplication ---- */

static GDS_METHOD(get_application) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    UA_Guid id;
    UA_StatusCode r = gds_in_guid(s, inputSize, input, 0, &id);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_ApplicationRecordDataType *rec = UA_new(rec_type());
    if(!rec)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    r = gds_load_app(s, &id, rec);
    if(r == UA_STATUSCODE_GOOD && !gds_session_has(sessionContext, GDS_ROLE_DISCOVERY_ADMIN) &&
       !gds_session_is_app(sessionContext, &rec->applicationUri))
        r = UA_STATUSCODE_BADUSERACCESSDENIED;
    if(r != UA_STATUSCODE_GOOD) {
        UA_delete(rec, rec_type());
        return r;
    }
    UA_Variant_setScalar(&output[0], rec, rec_type());
    return UA_STATUSCODE_GOOD;
}

/* ---- QueryApplications ---- */

/* LIKE pattern (OPC 10000-4 FilterOperator Like): '%' any run, '_' any one
 * character, '\' escapes the next one. Greedy with one backtrack point:
 * O(pattern * text), no recursion. */
static size_t token_len(const UA_Byte *p, size_t pn, size_t pi) {
    return (p[pi] == '\\' && pi + 1 < pn) ? 2 : 1;
}

static bool token_matches(const UA_Byte *p, size_t pn, size_t pi, UA_Byte c) {
    if(p[pi] == '\\' && pi + 1 < pn)
        return p[pi + 1] == c;
    return p[pi] == '_' || p[pi] == c;
}

static bool like(const UA_Byte *p, size_t pn, const UA_Byte *t, size_t tn) {
    size_t pi = 0, ti = 0, star = SIZE_MAX, mark = 0;
    while(ti < tn) {
        if(pi < pn && p[pi] == '%') {
            star = pi++;
            mark = ti;
        } else if(pi < pn && token_matches(p, pn, pi, t[ti])) {
            pi += token_len(p, pn, pi);
            ti++;
        } else if(star != SIZE_MAX) {
            pi = star + 1;
            ti = ++mark;
        } else {
            return false;
        }
    }
    while(pi < pn && p[pi] == '%')
        pi++;
    return pi == pn;
}

static bool match(const UA_String *pattern, const UA_String *text) {
    return pattern->length == 0 || like(pattern->data, pattern->length, text->data, text->length);
}

typedef struct {
    const UA_String *name, *uri, *product;
    UA_UInt32 typeMask;
    const UA_String *caps;
    size_t capsN;
    size_t max;
    UA_ApplicationDescription *out;
    size_t n;
    int64_t next;
    UA_StatusCode r;
} query_ctx;

static bool type_ok(UA_UInt32 mask, UA_ApplicationType t) {
    if(mask == 0)
        return true;
    bool server = t != UA_APPLICATIONTYPE_CLIENT, client = t == UA_APPLICATIONTYPE_CLIENT ||
                                                          t == UA_APPLICATIONTYPE_CLIENTANDSERVER;
    return ((mask & 1u) && server) || ((mask & 2u) && client);
}

static bool record_matches(const query_ctx *c, const UA_ApplicationRecordDataType *rec) {
    if(!type_ok(c->typeMask, rec->applicationType) || !match(c->uri, &rec->applicationUri) ||
       !match(c->product, &rec->productUri))
        return false;
    bool nameOk = c->name->length == 0;
    for(size_t i = 0; i < rec->applicationNamesSize && !nameOk; i++)
        nameOk = match(c->name, &rec->applicationNames[i].text);
    for(size_t i = 0; i < c->capsN && nameOk; i++) {
        bool has = false;
        for(size_t j = 0; j < rec->serverCapabilitiesSize && !has; j++)
            has = UA_String_equal(&c->caps[i], &rec->serverCapabilities[j]);
        nameOk = has;
    }
    return nameOk;
}

static UA_StatusCode describe(const UA_ApplicationRecordDataType *rec, UA_ApplicationDescription *d) {
    UA_ApplicationDescription_init(d);
    UA_StatusCode r = UA_String_copy(&rec->applicationUri, &d->applicationUri);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_String_copy(&rec->productUri, &d->productUri);
    if(r == UA_STATUSCODE_GOOD && rec->applicationNamesSize > 0)
        r = UA_LocalizedText_copy(&rec->applicationNames[0], &d->applicationName);
    d->applicationType = rec->applicationType;
    if(r == UA_STATUSCODE_GOOD && rec->discoveryUrlsSize > 0)
        r = UA_Array_copy(rec->discoveryUrls, rec->discoveryUrlsSize, (void **)&d->discoveryUrls,
                          &UA_TYPES[UA_TYPES_STRING]);
    if(r == UA_STATUSCODE_GOOD)
        d->discoveryUrlsSize = rec->discoveryUrlsSize;
    if(r != UA_STATUSCODE_GOOD)
        UA_ApplicationDescription_clear(d);
    return r;
}

static bool query_cb(void *p, int64_t recordId, const UA_ApplicationRecordDataType *rec) {
    query_ctx *c = p;
    if(!record_matches(c, rec))
        return true;
    if(c->n == c->max) {
        c->next = recordId; /* first record of the next page */
        return false;
    }
    c->r = describe(rec, &c->out[c->n]);
    if(c->r != UA_STATUSCODE_GOOD)
        return false;
    c->n++;
    return true;
}

static UA_StatusCode query_inputs(size_t inputSize, const UA_Variant *input, query_ctx *c,
                                  UA_UInt32 *start) {
    if(inputSize < 7)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const void *p = NULL;
    UA_StatusCode r = gds_arg_scalar(&input[0], &UA_TYPES[UA_TYPES_UINT32], &p);
    if(r == UA_STATUSCODE_GOOD) {
        *start = *(const UA_UInt32 *)p;
        r = gds_arg_scalar(&input[1], &UA_TYPES[UA_TYPES_UINT32], &p);
    }
    if(r == UA_STATUSCODE_GOOD) {
        UA_UInt32 max = *(const UA_UInt32 *)p;
        c->max = (max == 0 || max > GDS_MAX_QUERY_RECORDS) ? GDS_MAX_QUERY_RECORDS : max;
        r = gds_arg_string(&input[2], GDS_MAX_STRING, &c->name);
    }
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_string(&input[3], GDS_MAX_APPLICATION_URI, &c->uri);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_scalar(&input[4], &UA_TYPES[UA_TYPES_UINT32], &p);
    if(r == UA_STATUSCODE_GOOD) {
        c->typeMask = *(const UA_UInt32 *)p;
        r = gds_arg_string(&input[5], GDS_MAX_APPLICATION_URI, &c->product);
    }
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_array(&input[6], &UA_TYPES[UA_TYPES_STRING], GDS_MAX_ARRAY_FIELD, &p,
                          &c->capsN);
    if(r == UA_STATUSCODE_GOOD)
        c->caps = p;
    return r == UA_STATUSCODE_GOOD ? r : UA_STATUSCODE_BADINVALIDARGUMENT;
}

static GDS_METHOD(query_applications) {
    GDS_METHOD_UNUSED;
    (void)sessionContext;
    gds_server *s = gds_ctx(methodContext);
    query_ctx c;
    memset(&c, 0, sizeof(c));
    UA_UInt32 start = 0;
    UA_StatusCode r = query_inputs(inputSize, input, &c, &start);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    c.out = (UA_ApplicationDescription *)UA_Array_new(c.max,
                                                      &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
    if(!c.out)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    gds_lock(s);
    gds_status st = gds_store_app_scan(s->store, start, query_cb, &c);
    gds_unlock(s);
    r = st != GDS_OK ? gds_status_to_ua(st) : c.r;
    UA_UInt32 next = c.next > 0 && c.next <= (int64_t)UINT32_MAX ? (UA_UInt32)c.next : 0;
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&output[0], &s->counterReset, &UA_TYPES[UA_TYPES_DATETIME]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&output[1], &next, &UA_TYPES[UA_TYPES_UINT32]);
    if(r != UA_STATUSCODE_GOOD) {
        UA_Array_delete(c.out, c.max, &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
        return r;
    }
    if(c.n == 0) {
        UA_Array_delete(c.out, c.max, &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
        UA_Variant_setArray(&output[2], UA_EMPTY_ARRAY_SENTINEL, 0,
                            &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
        return UA_STATUSCODE_GOOD;
    }
    /* the unused tail entries are empty (zeroed); the array keeps them out */
    UA_Variant_setArray(&output[2], c.out, c.n, &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode gds_directory_install(gds_server *s) {
    static const gds_method_entry m[] = {
        {UA_GDSID_DIRECTORY_FINDAPPLICATIONS, find_applications},
        {UA_GDSID_DIRECTORY_REGISTERAPPLICATION, register_application},
        {UA_GDSID_DIRECTORY_UPDATEAPPLICATION, update_application},
        {UA_GDSID_DIRECTORY_UNREGISTERAPPLICATION, unregister_application},
        {UA_GDSID_DIRECTORY_GETAPPLICATION, get_application},
        {UA_GDSID_DIRECTORY_QUERYAPPLICATIONS, query_applications},
    };
    return gds_install_methods(s, m, GDS_ARRAY_SIZE(m));
}
