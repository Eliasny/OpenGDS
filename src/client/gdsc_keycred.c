/* OpenGDS libgdsclient - KeyCredential wrappers (OPC 10000-12 v1.05.07
 * §8.5, §8.6).
 * SPDX-License-Identifier: MPL-2.0 */
#include "gdsc_keycred.h"

#include <open62541/client_highlevel.h>
#include <open62541/nodeids_gds.h>

#include <openssl/crypto.h>

#include <stdint.h>
#include <string.h>
#include <time.h>

#include "common/limits.h"
#include "common/ua_args.h"
#include "common/banned.h"

#define POLL_STEP_MS 500L

static UA_NodeId ns0(UA_UInt32 id) {
    return UA_NODEID_NUMERIC(0, id);
}

/* parent/ns:name (TranslateBrowsePathsToNodeIds) */
static UA_StatusCode child(UA_Client *c, const UA_NodeId *parent, UA_UInt16 ns,
                           const char *name, UA_NodeId *out) {
    UA_NodeId_init(out);
    UA_RelativePathElement el;
    UA_RelativePathElement_init(&el);
    el.referenceTypeId = ns0(UA_NS0ID_HIERARCHICALREFERENCES);
    el.includeSubtypes = true;
    el.targetName = UA_QUALIFIEDNAME(ns, (char *)(uintptr_t)name);
    UA_BrowsePath bp;
    UA_BrowsePath_init(&bp);
    bp.startingNode = *parent;
    bp.relativePath.elements = &el;
    bp.relativePath.elementsSize = 1;
    UA_TranslateBrowsePathsToNodeIdsRequest req;
    UA_TranslateBrowsePathsToNodeIdsRequest_init(&req);
    req.browsePaths = &bp;
    req.browsePathsSize = 1;
    UA_TranslateBrowsePathsToNodeIdsResponse resp =
        UA_Client_Service_translateBrowsePathsToNodeIds(c, req);
    UA_StatusCode r = resp.responseHeader.serviceResult;
    if(r == UA_STATUSCODE_GOOD && resp.resultsSize != 1)
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    else if(r == UA_STATUSCODE_GOOD && resp.results[0].statusCode != UA_STATUSCODE_GOOD)
        r = resp.results[0].statusCode;
    else if(r == UA_STATUSCODE_GOOD && resp.results[0].targetsSize < 1)
        r = UA_STATUSCODE_BADNOTFOUND;
    if(r == UA_STATUSCODE_GOOD)
        r = UA_NodeId_copy(&resp.results[0].targets[0].targetId.nodeId, out);
    UA_TranslateBrowsePathsToNodeIdsResponse_clear(&resp);
    if(r == UA_STATUSCODE_BADNOMATCH)
        r = UA_STATUSCODE_BADNOTFOUND;
    return r;
}

/* Call parent/ns:method; on Good at least minOut outputs */
static UA_StatusCode call(UA_Client *c, const UA_NodeId *obj, UA_UInt16 ns, const char *method,
                          size_t inN, const UA_Variant *in, size_t minOut, UA_Variant **out,
                          size_t *outN) {
    *out = NULL;
    *outN = 0;
    UA_NodeId m;
    UA_StatusCode r = child(c, obj, ns, method, &m);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Client_call(c, *obj, m, inN, in, outN, out);
    UA_NodeId_clear(&m);
    if(r == UA_STATUSCODE_GOOD && *outN < minOut)
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    if(r != UA_STATUSCODE_GOOD && *out) {
        UA_Array_delete(*out, *outN, &UA_TYPES[UA_TYPES_VARIANT]);
        *out = NULL;
        *outN = 0;
    }
    return r;
}

static void out_free(UA_Variant *out, size_t outN) {
    if(out)
        UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
}

/* s into dst (NUL-terminated); Bad_EncodingLimitsExceeded if too long */
static UA_StatusCode copy_str(const UA_String *s, char *dst, size_t dstLen) {
    if(s->length >= dstLen)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
    if(s->length)
        memcpy(dst, s->data, s->length);
    dst[s->length] = '\0';
    return UA_STATUSCODE_GOOD;
}

/* The Value of parent/ns:name */
static UA_StatusCode read_prop(UA_Client *c, const UA_NodeId *parent, UA_UInt16 ns,
                               const char *name, UA_Variant *v) {
    UA_Variant_init(v);
    UA_NodeId n;
    UA_StatusCode r = child(c, parent, ns, name, &n);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Client_readValueAttribute(c, n, v);
    UA_NodeId_clear(&n);
    return r;
}

/* A String Property into dst */
static UA_StatusCode read_str(UA_Client *c, const UA_NodeId *parent, UA_UInt16 ns,
                              const char *name, char *dst, size_t dstLen) {
    UA_Variant v;
    UA_StatusCode r = read_prop(c, parent, ns, name, &v);
    const UA_String *s = NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_string(&v, dstLen - 1, &s);
    if(r == UA_STATUSCODE_GOOD)
        r = copy_str(s, dst, dstLen);
    UA_Variant_clear(&v);
    return r;
}

/* ---------------- The GDS (§8.5) ---------------- */

void gdsc_kc_service_clear(gdsc_kc_service *s) {
    UA_NodeId_clear(&s->node);
    memset(s, 0, sizeof(*s));
}

/* The first entry of the ProfileUris Property (String[]) */
static UA_StatusCode first_profile(UA_Client *c, gdsc_kc_service *s) {
    UA_Variant v;
    UA_StatusCode r = read_prop(c, &s->node, s->ns, "ProfileUris", &v);
    const void *arr = NULL;
    size_t n = 0;
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_array(&v, &UA_TYPES[UA_TYPES_STRING], GDS_MAX_ARRAY_FIELD, &arr, &n);
    if(r == UA_STATUSCODE_GOOD && n == 0)
        r = UA_STATUSCODE_BADNOTFOUND;
    if(r == UA_STATUSCODE_GOOD)
        r = copy_str((const UA_String *)arr, s->profileUri, sizeof(s->profileUri));
    UA_Variant_clear(&v);
    return r;
}

UA_StatusCode gdsc_kc_service_find(UA_Client *c, UA_UInt16 ns, const char *name,
                                   gdsc_kc_service *out) {
    memset(out, 0, sizeof(*out));
    out->ns = ns;
    const UA_NodeId folder = UA_NODEID_NUMERIC(ns, UA_GDSID_KEYCREDENTIALMANAGEMENT);
    UA_StatusCode r = child(c, &folder, ns, name, &out->node);
    if(r == UA_STATUSCODE_GOOD)
        r = read_str(c, &out->node, ns, "ResourceUri", out->resourceUri,
                     sizeof(out->resourceUri));
    if(r == UA_STATUSCODE_GOOD)
        r = first_profile(c, out);
    if(r != UA_STATUSCODE_GOOD) {
        gdsc_kc_service_clear(out);
        out->ns = ns;
    }
    return r;
}

static UA_StatusCode kc_start(UA_Client *c, const gdsc_kc_service *svc,
                              const char *applicationUri, UA_NodeId *requestId) {
    UA_String uri = UA_STRING((char *)(uintptr_t)applicationUri);
    UA_ByteString key = UA_BYTESTRING_NULL;
    UA_String policy = UA_STRING_NULL;
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], &uri, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &key, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&in[2], &policy, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setArray(&in[3], NULL, 0, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant *out = NULL;
    size_t outN = 0;
    UA_StatusCode r = call(c, &svc->node, svc->ns, "StartRequest", 4, in, 1, &out, &outN);
    const void *id = NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_scalar(&out[0], &UA_TYPES[UA_TYPES_NODEID], &id);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_NodeId_copy(id, requestId);
    out_free(out, outN);
    return r;
}

/* FinishRequest(requestId, FALSE) once */
static UA_StatusCode kc_finish(UA_Client *c, const gdsc_kc_service *svc,
                               const UA_NodeId *requestId, char *credentialId, gds_buf *secret) {
    UA_Boolean cancel = false;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)requestId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &cancel, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Variant *out = NULL;
    size_t outN = 0;
    UA_StatusCode r = call(c, &svc->node, svc->ns, "FinishRequest", 2, in, 2, &out, &outN);
    const UA_String *id = NULL;
    const UA_ByteString *sec = NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_string(&out[0], GDSC_KC_ID_MAX, &id);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_bytes(&out[1], GDSC_KC_SECRET_MAX, &sec);
    if(r == UA_STATUSCODE_GOOD && (id->length == 0 || sec->length == 0))
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    if(r == UA_STATUSCODE_GOOD)
        r = copy_str(id, credentialId, GDSC_KC_ID_MAX + 1);
    if(r == UA_STATUSCODE_GOOD && gds_buf_dup(sec->data, sec->length, secret) != GDS_OK)
        r = UA_STATUSCODE_BADOUTOFMEMORY;
    if(out && outN > 1 && out[1].type == &UA_TYPES[UA_TYPES_BYTESTRING] &&
       UA_Variant_isScalar(&out[1])) {
        UA_ByteString *b = out[1].data; /* wipe the copy the client decoded */
        if(b->length)
            OPENSSL_cleanse(b->data, b->length);
    }
    out_free(out, outN);
    return r;
}

UA_StatusCode gdsc_kc_request(UA_Client *c, const gdsc_kc_service *svc,
                              const char *applicationUri, unsigned pollSeconds,
                              char credentialId[GDSC_KC_ID_MAX + 1], gds_buf *secret) {
    credentialId[0] = '\0';
    memset(secret, 0, sizeof(*secret));
    UA_NodeId req;
    UA_StatusCode r = kc_start(c, svc, applicationUri, &req);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const struct timespec step = {POLL_STEP_MS / 1000, (POLL_STEP_MS % 1000) * 1000000L};
    for(long waited = 0;; waited += POLL_STEP_MS) {
        r = kc_finish(c, svc, &req, credentialId, secret);
        if(r != UA_STATUSCODE_BADREQUESTNOTCOMPLETE || waited >= (long)pollSeconds * 1000L)
            break;
        nanosleep(&step, NULL); /* §8.5.6: not complete while waiting for approval */
    }
    UA_NodeId_clear(&req);
    return r;
}

UA_StatusCode gdsc_kc_revoke(UA_Client *c, const gdsc_kc_service *svc,
                             const char *credentialId) {
    UA_String id = UA_STRING((char *)(uintptr_t)credentialId);
    UA_Variant in;
    UA_Variant_setScalar(&in, &id, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant *out = NULL;
    size_t outN = 0;
    UA_StatusCode r = call(c, &svc->node, svc->ns, "Revoke", 1, &in, 0, &out, &outN);
    out_free(out, outN);
    return r;
}

/* ---------------- A managed Server (§8.6) ---------------- */

static UA_StatusCode browse_folder(UA_Client *c, UA_BrowseResponse *resp) {
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = ns0(UA_NS0ID_KEYCREDENTIALCONFIGURATION);
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.referenceTypeId = ns0(UA_NS0ID_HASCOMPONENT);
    bd.includeSubtypes = true;
    bd.nodeClassMask = UA_NODECLASS_OBJECT;
    bd.resultMask = UA_BROWSERESULTMASK_NONE;
    UA_BrowseRequest req;
    UA_BrowseRequest_init(&req);
    req.nodesToBrowse = &bd;
    req.nodesToBrowseSize = 1;
    req.requestedMaxReferencesPerNode = GDSC_KC_MAX_OBJECTS;
    *resp = UA_Client_Service_browse(c, req);
    UA_StatusCode r = resp->responseHeader.serviceResult;
    if(r == UA_STATUSCODE_GOOD && resp->resultsSize != 1)
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    else if(r == UA_STATUSCODE_GOOD)
        r = resp->results[0].statusCode;
    if(r == UA_STATUSCODE_BADNODEIDUNKNOWN)
        r = UA_STATUSCODE_BADNOTSUPPORTED;
    return r;
}

UA_StatusCode gdsc_kc_config_find(UA_Client *c, const char *resourceUri, UA_NodeId *out) {
    UA_NodeId_init(out);
    UA_BrowseResponse resp;
    UA_StatusCode r = browse_folder(c, &resp);
    bool found = false;
    for(size_t i = 0; r == UA_STATUSCODE_GOOD && !found && i < resp.results[0].referencesSize;
        i++) {
        const UA_NodeId *n = &resp.results[0].references[i].nodeId.nodeId;
        char uri[GDSC_KC_URI_MAX + 1];
        if(read_str(c, n, 0, "ResourceUri", uri, sizeof(uri)) != UA_STATUSCODE_GOOD ||
           strcmp(uri, resourceUri) != 0)
            continue; /* not a credential Object, or another resource */
        r = UA_NodeId_copy(n, out);
        found = r == UA_STATUSCODE_GOOD;
    }
    UA_BrowseResponse_clear(&resp);
    return r == UA_STATUSCODE_GOOD && !found ? UA_STATUSCODE_BADNOTFOUND : r;
}

UA_StatusCode gdsc_kc_config_create(UA_Client *c, const char *name, const char *resourceUri,
                                    const char *profileUri, const char *const *endpointUrls,
                                    size_t endpointUrlsN, UA_NodeId *out) {
    UA_NodeId_init(out);
    if(endpointUrlsN > GDS_MAX_ARRAY_FIELD)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_String s[3] = {UA_STRING((char *)(uintptr_t)name),
                      UA_STRING((char *)(uintptr_t)resourceUri),
                      UA_STRING((char *)(uintptr_t)profileUri)};
    UA_String urls[GDS_MAX_ARRAY_FIELD];
    for(size_t i = 0; i < endpointUrlsN; i++)
        urls[i] = UA_STRING((char *)(uintptr_t)endpointUrls[i]);
    UA_Variant in[4];
    for(size_t i = 0; i < 3; i++)
        UA_Variant_setScalar(&in[i], &s[i], &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setArray(&in[3], endpointUrlsN ? urls : NULL, endpointUrlsN,
                        &UA_TYPES[UA_TYPES_STRING]);
    const UA_NodeId folder = ns0(UA_NS0ID_KEYCREDENTIALCONFIGURATION);
    UA_Variant *o = NULL;
    size_t oN = 0;
    UA_StatusCode r = call(c, &folder, 0, "CreateCredential", 4, in, 1, &o, &oN);
    const void *id = NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_scalar(&o[0], &UA_TYPES[UA_TYPES_NODEID], &id);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_NodeId_copy(id, out);
    out_free(o, oN);
    return r;
}

UA_StatusCode gdsc_kc_config_key(UA_Client *c, const UA_NodeId *obj, const char *credentialId,
                                 const char *requestedPolicy, gds_buf *key,
                                 char policy[GDSC_KC_URI_MAX + 1]) {
    memset(key, 0, sizeof(*key));
    policy[0] = '\0';
    UA_String a[2] = {UA_STRING((char *)(uintptr_t)credentialId),
                      UA_STRING((char *)(uintptr_t)(requestedPolicy ? requestedPolicy : ""))};
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &a[0], &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &a[1], &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant *out = NULL;
    size_t outN = 0;
    UA_StatusCode r = call(c, obj, 0, "GetEncryptingKey", 2, in, 2, &out, &outN);
    const UA_ByteString *k = NULL;
    const UA_String *p = NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_bytes(&out[0], GDS_MAX_CERT_SIZE, &k);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_string(&out[1], GDSC_KC_URI_MAX, &p);
    if(r == UA_STATUSCODE_GOOD)
        r = copy_str(p, policy, GDSC_KC_URI_MAX + 1);
    if(r == UA_STATUSCODE_GOOD && k->length &&
       gds_buf_dup(k->data, k->length, key) != GDS_OK)
        r = UA_STATUSCODE_BADOUTOFMEMORY;
    out_free(out, outN);
    return r;
}

UA_StatusCode gdsc_kc_config_update(UA_Client *c, const UA_NodeId *obj, const char *credentialId,
                                    const gds_buf *secret, const char *thumbprint,
                                    const char *policy) {
    UA_String id = UA_STRING((char *)(uintptr_t)credentialId);
    UA_ByteString sec = {secret->len, secret->data};
    UA_String tp = UA_STRING((char *)(uintptr_t)thumbprint);
    UA_String pol = UA_STRING((char *)(uintptr_t)policy);
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], &id, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &sec, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&in[2], &tp, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[3], &pol, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant *out = NULL;
    size_t outN = 0;
    UA_StatusCode r = call(c, obj, 0, "UpdateCredential", 4, in, 0, &out, &outN);
    out_free(out, outN);
    return r;
}

UA_StatusCode gdsc_kc_config_delete(UA_Client *c, const UA_NodeId *obj) {
    UA_Variant *out = NULL;
    size_t outN = 0;
    UA_StatusCode r = call(c, obj, 0, "DeleteCredential", 0, NULL, 0, &out, &outN);
    out_free(out, outN);
    return r;
}

UA_StatusCode gdsc_kc_config_id(UA_Client *c, const UA_NodeId *obj,
                                char id[GDSC_KC_ID_MAX + 1]) {
    id[0] = '\0';
    UA_StatusCode r = read_str(c, obj, 0, "CredentialId", id, GDSC_KC_ID_MAX + 1);
    if(r == UA_STATUSCODE_BADNOTFOUND) /* Optional (§8.6.5) */
        r = UA_STATUSCODE_GOOD;
    return r;
}
