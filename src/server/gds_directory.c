/* OpenGDS - Directory methods (OPC 10000-12 §6.5): FindApplications,
 * RegisterApplication, UpdateApplication, UnregisterApplication,
 * GetApplication, QueryApplications, QueryServers.
 * Access: changes need DiscoveryAdmin; GetApplication needs DiscoveryAdmin
 * or the application itself; Find and Query are open to every session on
 * an encrypted channel (§6.2).
 * SPDX-License-Identifier: MPL-2.0 */
#include <stdio.h>
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

/* ApplicationRegistrationChangedAuditEventType (§6.5.12) for a Register,
 * Update or Unregister an administrator was allowed to make, with its
 * outcome in Status. */
static void audit_registration(gds_server *s, void *sessionContext, UA_UInt32 method,
                               size_t inputSize, const UA_Variant *input, UA_StatusCode r) {
    if(!gds_audit_result(r))
        return;
    static const char *const msg[] = {"application registered", "application updated",
                                      "application unregistered"};
    size_t i = method == UA_GDSID_DIRECTORY_REGISTERAPPLICATION ? 0
               : method == UA_GDSID_DIRECTORY_UPDATEAPPLICATION ? 1
                                                                : 2;
    gds_status a = gds_method_audit(s, gds_session_actor(sessionContext),
                                    UA_GDSID_APPLICATIONREGISTRATIONCHANGEDAUDITEVENTTYPE, method,
                                    UA_GDSID_WELLKNOWNROLE_DISCOVERYADMIN, NULL, 0, input,
                                    inputSize < 1 ? inputSize : 1, r == UA_STATUSCODE_GOOD,
                                    r == UA_STATUSCODE_GOOD ? msg[i] : UA_StatusCode_name(r));
    if(a != GDS_OK && a != GDS_EUNSUPPORTED)
        fprintf(stderr, "opengds: audit of a registration change: %s\n", gds_status_name(a));
}

static UA_StatusCode register_impl(gds_server *s, void *sessionContext, size_t inputSize,
                                   const UA_Variant *input, UA_Variant *output) {
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

static UA_StatusCode update_impl(gds_server *s, void *sessionContext, size_t inputSize,
                                 const UA_Variant *input) {
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

static UA_StatusCode unregister_impl(gds_server *s, void *sessionContext, size_t inputSize,
                                     const UA_Variant *input) {
    if(gds_refuse_on_standby(s) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADINVALIDSTATE;
    if(!gds_session_has(sessionContext, GDS_ROLE_DISCOVERY_ADMIN))
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    UA_Guid id;
    UA_StatusCode r = gds_in_guid(s, inputSize, input, 0, &id);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    /* §6.5.8: its certificates are revoked first; deleting the record
     * deletes their rows, after which the signer could not check them */
    r = gds_revoke_app_certs(s, &id);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    gds_lock(s);
    gds_status st = gds_store_app_delete(s->store, &id);
    gds_unlock(s);
    return gds_status_to_ua(st);
}

static GDS_METHOD(register_application) {
    GDS_METHOD_UNUSED;
    gds_server *s = gds_ctx(methodContext);
    UA_StatusCode r = register_impl(s, sessionContext, inputSize, input, output);
    audit_registration(s, sessionContext, UA_GDSID_DIRECTORY_REGISTERAPPLICATION, inputSize, input, r);
    return r;
}

static GDS_METHOD(update_application) {
    GDS_METHOD_UNUSED;
    (void)output;
    gds_server *s = gds_ctx(methodContext);
    UA_StatusCode r = update_impl(s, sessionContext, inputSize, input);
    audit_registration(s, sessionContext, UA_GDSID_DIRECTORY_UPDATEAPPLICATION, inputSize, input, r);
    return r;
}

static GDS_METHOD(unregister_application) {
    GDS_METHOD_UNUSED;
    (void)output;
    gds_server *s = gds_ctx(methodContext);
    UA_StatusCode r = unregister_impl(s, sessionContext, inputSize, input);
    audit_registration(s, sessionContext, UA_GDSID_DIRECTORY_UNREGISTERAPPLICATION, inputSize,
                       input, r);
    return r;
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

/* QueryApplications (§6.5.10) and QueryServers (§6.5.11) share the scan:
 * records with an identifier greater than StartingRecordId, in identifier
 * order, filters ANDed, never a record whose ServerCapabilities include NA.
 * NextRecordId (QueryApplications) is the identifier of the last record
 * returned when more match, else 0. */
typedef enum { Q_APPS, Q_SERVERS } query_kind;

typedef struct {
    query_kind kind;
    const UA_String *name, *uri, *product;
    UA_UInt32 typeMask; /* Q_APPS; Q_SERVERS: Servers only */
    const UA_String *caps;
    size_t capsN;
    const UA_String *locales; /* the Session's preferred locales */
    size_t localesN;
    size_t max;   /* entries */
    void *out;    /* UA_ApplicationDescription or UA_ServerOnNetwork [max] */
    size_t n;
    int64_t last; /* identifier of the last record returned */
    bool more;
    UA_StatusCode r;
} query_ctx;

static bool type_ok(UA_UInt32 mask, UA_ApplicationType t) {
    if(mask == 0)
        return true;
    bool server = t != UA_APPLICATIONTYPE_CLIENT, client = t == UA_APPLICATIONTYPE_CLIENT ||
                                                          t == UA_APPLICATIONTYPE_CLIENTANDSERVER;
    return ((mask & 1u) && server) || ((mask & 2u) && client);
}

static bool has_cap(const UA_ApplicationRecordDataType *rec, const UA_String *cap) {
    for(size_t j = 0; j < rec->serverCapabilitiesSize; j++)
        if(UA_String_equal(cap, &rec->serverCapabilities[j]))
            return true;
    return false;
}

static bool record_matches(const query_ctx *c, const UA_ApplicationRecordDataType *rec) {
    static const UA_String na = {2, (UA_Byte *)(uintptr_t)"NA"};
    if(c->kind == Q_SERVERS && rec->applicationType == UA_APPLICATIONTYPE_CLIENT)
        return false;
    if(!type_ok(c->typeMask, rec->applicationType) || !match(c->uri, &rec->applicationUri) ||
       !match(c->product, &rec->productUri) || has_cap(rec, &na))
        return false;
    /* "The filter is only applied to the default ApplicationName" */
    if(c->name->length > 0 &&
       (rec->applicationNamesSize == 0 || !match(c->name, &rec->applicationNames[0].text)))
        return false;
    for(size_t i = 0; i < c->capsN; i++)
        if(!has_cap(rec, &c->caps[i]))
            return false;
    return true;
}

/* The name in the Session's first preferred locale that the record has, else
 * the first (the default) one (§6.5.10). */
static const UA_LocalizedText *pick_name(const query_ctx *c,
                                         const UA_ApplicationRecordDataType *rec) {
    if(rec->applicationNamesSize == 0)
        return NULL;
    for(size_t i = 0; i < c->localesN; i++)
        for(size_t j = 0; j < rec->applicationNamesSize; j++)
            if(UA_String_equal(&c->locales[i], &rec->applicationNames[j].locale))
                return &rec->applicationNames[j];
    return &rec->applicationNames[0];
}

static UA_StatusCode describe(const query_ctx *c, const UA_ApplicationRecordDataType *rec,
                              UA_ApplicationDescription *d) {
    UA_ApplicationDescription_init(d);
    UA_StatusCode r = UA_String_copy(&rec->applicationUri, &d->applicationUri);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_String_copy(&rec->productUri, &d->productUri);
    const UA_LocalizedText *name = pick_name(c, rec);
    if(r == UA_STATUSCODE_GOOD && name)
        r = UA_LocalizedText_copy(name, &d->applicationName);
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

/* §6.5.11: one ServerOnNetwork per DiscoveryUrl, with the record's
 * identifier, name and ServerCapabilities */
static UA_StatusCode on_network(const query_ctx *c, int64_t recordId,
                                const UA_ApplicationRecordDataType *rec, size_t url,
                                UA_ServerOnNetwork *o) {
    UA_ServerOnNetwork_init(o);
    o->recordId = (UA_UInt32)recordId;
    const UA_LocalizedText *name = pick_name(c, rec);
    UA_StatusCode r = name ? UA_String_copy(&name->text, &o->serverName) : UA_STATUSCODE_GOOD;
    if(r == UA_STATUSCODE_GOOD)
        r = UA_String_copy(&rec->discoveryUrls[url], &o->discoveryUrl);
    if(r == UA_STATUSCODE_GOOD && rec->serverCapabilitiesSize > 0)
        r = UA_Array_copy(rec->serverCapabilities, rec->serverCapabilitiesSize,
                          (void **)&o->serverCapabilities, &UA_TYPES[UA_TYPES_STRING]);
    if(r == UA_STATUSCODE_GOOD)
        o->serverCapabilitiesSize = rec->serverCapabilitiesSize;
    if(r != UA_STATUSCODE_GOOD)
        UA_ServerOnNetwork_clear(o);
    return r;
}

static bool query_cb(void *p, int64_t recordId, const UA_ApplicationRecordDataType *rec) {
    query_ctx *c = p;
    if(recordId <= 0 || recordId > (int64_t)UINT32_MAX) {
        c->r = UA_STATUSCODE_BADINTERNALERROR; /* identifiers are UInt32 on the wire */
        return false;
    }
    if(!record_matches(c, rec))
        return true;
    size_t need = c->kind == Q_APPS ? 1 : rec->discoveryUrlsSize;
    if(need == 0)
        return true;
    if(c->n + need > c->max) {
        if(c->n == 0) { /* one record with more URLs than a page: what fits */
            need = c->max;
        } else {
            c->more = true;
            return false;
        }
    }
    for(size_t i = 0; i < need && c->r == UA_STATUSCODE_GOOD; i++) {
        if(c->kind == Q_APPS)
            c->r = describe(c, rec, &((UA_ApplicationDescription *)c->out)[c->n]);
        else
            c->r = on_network(c, recordId, rec, i, &((UA_ServerOnNetwork *)c->out)[c->n]);
        if(c->r == UA_STATUSCODE_GOOD)
            c->n++;
    }
    c->last = recordId;
    return c->r == UA_STATUSCODE_GOOD;
}

static UA_StatusCode arg_u32(const UA_Variant *v, UA_UInt32 *out) {
    const void *p = NULL;
    UA_StatusCode r = gds_arg_scalar(v, &UA_TYPES[UA_TYPES_UINT32], &p);
    if(r == UA_STATUSCODE_GOOD)
        *out = *(const UA_UInt32 *)p;
    return r;
}

/* QueryApplications: StartingRecordId, MaxRecordsToReturn, ApplicationName,
 * ApplicationUri, ApplicationType, ProductUri, Capabilities.
 * QueryServers: the same without ApplicationType. */
static UA_StatusCode query_inputs(size_t inputSize, const UA_Variant *input, query_ctx *c,
                                  UA_UInt32 *start) {
    size_t want = c->kind == Q_APPS ? 7 : 6;
    if(inputSize < want)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    UA_UInt32 max = 0;
    UA_StatusCode r = arg_u32(&input[0], start);
    if(r == UA_STATUSCODE_GOOD)
        r = arg_u32(&input[1], &max);
    /* 0 is "no limit"; a page is still bounded, and NextRecordId (or the
     * last recordId of QueryServers) continues */
    c->max = (max == 0 || max > GDS_MAX_QUERY_RECORDS) ? GDS_MAX_QUERY_RECORDS : max;
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_string(&input[2], GDS_MAX_STRING, &c->name);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_string(&input[3], GDS_MAX_APPLICATION_URI, &c->uri);
    size_t i = 4;
    if(r == UA_STATUSCODE_GOOD && c->kind == Q_APPS)
        r = arg_u32(&input[i++], &c->typeMask);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_string(&input[i++], GDS_MAX_APPLICATION_URI, &c->product);
    const void *p = NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_array(&input[i], &UA_TYPES[UA_TYPES_STRING], GDS_MAX_ARRAY_FIELD, &p,
                          &c->capsN);
    if(r == UA_STATUSCODE_GOOD)
        c->caps = p;
    return r == UA_STATUSCODE_GOOD ? r : UA_STATUSCODE_BADINVALIDARGUMENT;
}

static const UA_DataType *out_type(query_kind k) {
    return k == Q_APPS ? &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]
                       : &UA_TYPES[UA_TYPES_SERVERONNETWORK];
}

static UA_StatusCode query(UA_Server *server, const UA_NodeId *sessionId, gds_server *s,
                           query_kind kind, size_t inputSize, const UA_Variant *input,
                           UA_Variant *output) {
    query_ctx c;
    memset(&c, 0, sizeof(c));
    c.kind = kind;
    UA_UInt32 start = 0;
    UA_StatusCode r = query_inputs(inputSize, input, &c, &start);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_Variant locales;
    UA_Variant_init(&locales);
    if(UA_Server_getSessionAttributeCopy(server, sessionId, UA_QUALIFIEDNAME(0, "localeIds"),
                                         &locales) == UA_STATUSCODE_GOOD &&
       UA_Variant_hasArrayType(&locales, &UA_TYPES[UA_TYPES_STRING])) {
        c.locales = locales.data;
        c.localesN = locales.arrayLength;
    }
    const UA_DataType *t = out_type(kind);
    c.out = UA_Array_new(c.max, t);
    if(!c.out) {
        UA_Variant_clear(&locales);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    gds_lock(s);
    gds_status st = gds_store_app_scan(s->store, start, query_cb, &c);
    gds_unlock(s);
    UA_Variant_clear(&locales);
    r = st != GDS_OK ? gds_status_to_ua(st) : c.r;
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Variant_setScalarCopy(&output[0], &s->counterReset, &UA_TYPES[UA_TYPES_DATETIME]);
    size_t res = 1;
    if(r == UA_STATUSCODE_GOOD && kind == Q_APPS) {
        UA_UInt32 next = c.more ? (UA_UInt32)c.last : 0;
        r = UA_Variant_setScalarCopy(&output[1], &next, &UA_TYPES[UA_TYPES_UINT32]);
        res = 2;
    }
    if(r != UA_STATUSCODE_GOOD || c.n == 0) {
        UA_Array_delete(c.out, c.max, t);
        if(r == UA_STATUSCODE_GOOD)
            UA_Variant_setArray(&output[res], UA_EMPTY_ARRAY_SENTINEL, 0, t);
        return r;
    }
    /* the unused tail entries are empty (zeroed); the array keeps them out */
    UA_Variant_setArray(&output[res], c.out, c.n, t);
    return UA_STATUSCODE_GOOD;
}

static GDS_METHOD(query_applications) {
    GDS_METHOD_UNUSED;
    (void)sessionContext;
    return query(server, sessionId, gds_ctx(methodContext), Q_APPS, inputSize, input, output);
}

/* Deprecated, but Mandatory on the Directory (§6.5.11) */
static GDS_METHOD(query_servers) {
    GDS_METHOD_UNUSED;
    (void)sessionContext;
    return query(server, sessionId, gds_ctx(methodContext), Q_SERVERS, inputSize, input, output);
}

UA_StatusCode gds_directory_install(gds_server *s) {
    static const gds_method_entry m[] = {
        {UA_GDSID_DIRECTORY_FINDAPPLICATIONS, find_applications},
        {UA_GDSID_DIRECTORY_REGISTERAPPLICATION, register_application},
        {UA_GDSID_DIRECTORY_UPDATEAPPLICATION, update_application},
        {UA_GDSID_DIRECTORY_UNREGISTERAPPLICATION, unregister_application},
        {UA_GDSID_DIRECTORY_GETAPPLICATION, get_application},
        {UA_GDSID_DIRECTORY_QUERYAPPLICATIONS, query_applications},
        {UA_GDSID_DIRECTORY_QUERYSERVERS, query_servers},
    };
    return gds_install_methods(s, m, GDS_ARRAY_SIZE(m));
}
