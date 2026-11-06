/* OpenGDS - method input checks and the ApplicationRecord rules
 * (OPC 10000-12 §6.5.6 RegisterApplication, §6.5.7 UpdateApplication).
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>

#include "ca_x509.h"
#include "common/limits.h"
#include "gds_internal.h"
#include "common/banned.h"

#define MAX_LOCALE 64
#define MAX_CAPABILITY 64

UA_StatusCode gds_in_nodeid(size_t inputSize, const UA_Variant *input, size_t i,
                            const UA_NodeId **out) {
    if(inputSize <= i)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const void *p = NULL;
    UA_StatusCode r = gds_arg_scalar(&input[i], &UA_TYPES[UA_TYPES_NODEID], &p);
    *out = p;
    return r == UA_STATUSCODE_GOOD ? r : UA_STATUSCODE_BADINVALIDARGUMENT;
}

UA_StatusCode gds_in_guid(const gds_server *s, size_t inputSize, const UA_Variant *input,
                          size_t i, UA_Guid *out) {
    const UA_NodeId *id = NULL;
    UA_StatusCode r = gds_in_nodeid(inputSize, input, i, &id);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    /* ids we hand out are GUIDs in the GDS namespace; anything else is unknown */
    if(id->identifierType != UA_NODEIDTYPE_GUID || id->namespaceIndex != s->ns)
        return UA_STATUSCODE_BADNOTFOUND;
    *out = id->identifier.guid;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode gds_in_record(size_t inputSize, const UA_Variant *input, size_t i,
                            const UA_ApplicationRecordDataType **out) {
    if(inputSize <= i)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    const void *p = NULL;
    UA_StatusCode r =
        gds_arg_scalar(&input[i], &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE], &p);
    *out = p;
    return r == UA_STATUSCODE_GOOD ? r : UA_STATUSCODE_BADINVALIDARGUMENT;
}

static bool string_ok(const UA_String *s, size_t min, size_t max) {
    return s->length >= min && s->length <= max && (s->length == 0 || !memchr(s->data, 0, s->length));
}

/* The URI goes into an IA5String SAN: printable ASCII without spaces. */
static bool uri_ok(const UA_String *u) {
    if(u->length == 0 || u->length > GDS_MAX_APPLICATION_URI)
        return false;
    for(size_t i = 0; i < u->length; i++)
        if(u->data[i] < 0x21 || u->data[i] > 0x7e)
            return false;
    return memchr(u->data, ':', u->length) != NULL;
}

static bool names_ok(const UA_ApplicationRecordDataType *rec) {
    if(rec->applicationNamesSize == 0 || rec->applicationNamesSize > GDS_MAX_ARRAY_FIELD)
        return false;
    for(size_t i = 0; i < rec->applicationNamesSize; i++) {
        const UA_LocalizedText *n = &rec->applicationNames[i];
        if(!string_ok(&n->text, 1, GDS_MAX_STRING) || !string_ok(&n->locale, 0, MAX_LOCALE))
            return false;
    }
    return true;
}

static bool is_server_type(UA_ApplicationType t) {
    return t == UA_APPLICATIONTYPE_SERVER || t == UA_APPLICATIONTYPE_CLIENTANDSERVER ||
           t == UA_APPLICATIONTYPE_DISCOVERYSERVER;
}

static bool urls_ok(const UA_ApplicationRecordDataType *rec) {
    if(rec->discoveryUrlsSize > GDS_MAX_ARRAY_FIELD)
        return false;
    /* a Server must say where it can be reached */
    if(is_server_type(rec->applicationType) && rec->discoveryUrlsSize == 0)
        return false;
    for(size_t i = 0; i < rec->discoveryUrlsSize; i++) {
        char host[256];
        bool isIp = false;
        if(!string_ok(&rec->discoveryUrls[i], 1, GDS_MAX_STRING) ||
           cax_url_host(&rec->discoveryUrls[i], host, sizeof(host), &isIp) != GDS_OK)
            return false;
    }
    return true;
}

static bool capabilities_ok(const UA_ApplicationRecordDataType *rec) {
    if(rec->serverCapabilitiesSize > GDS_MAX_ARRAY_FIELD)
        return false;
    for(size_t i = 0; i < rec->serverCapabilitiesSize; i++)
        if(!string_ok(&rec->serverCapabilities[i], 1, MAX_CAPABILITY))
            return false;
    return true;
}

UA_StatusCode gds_validate_record(const UA_ApplicationRecordDataType *rec) {
    if((int)rec->applicationType < (int)UA_APPLICATIONTYPE_SERVER ||
       (int)rec->applicationType > (int)UA_APPLICATIONTYPE_DISCOVERYSERVER)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(!uri_ok(&rec->applicationUri) || !string_ok(&rec->productUri, 0, GDS_MAX_APPLICATION_URI) ||
       !names_ok(rec) || !urls_ok(rec) || !capabilities_ok(rec))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode gds_load_app(gds_server *s, const UA_Guid *id, UA_ApplicationRecordDataType *out) {
    gds_lock(s);
    gds_status r = gds_store_app_get(s->store, id, out);
    gds_unlock(s);
    if(r != GDS_OK)
        return gds_status_to_ua(r);
    out->applicationId = UA_NODEID_GUID(s->ns, *id);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode gds_install_methods(gds_server *s, const gds_method_entry *m, size_t n) {
    for(size_t i = 0; i < n; i++) {
        UA_NodeId id = UA_NODEID_NUMERIC(s->ns, m[i].id);
        UA_StatusCode r = UA_Server_setMethodNodeCallback(s->ua, id, m[i].cb);
        if(r == UA_STATUSCODE_GOOD)
            r = UA_Server_setNodeContext(s->ua, id, s);
        if(r != UA_STATUSCODE_GOOD)
            return r;
    }
    return UA_STATUSCODE_GOOD;
}
