/* OpenGDS Auditor GDS profile - the GDS under test.
 * SPDX-License-Identifier: MPL-2.0 */
#include "gds_target.h"

#include <open62541/client_highlevel.h>
#include <open62541/nodeids_gds.h>
#include <openssl/crypto.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common/limits.h"
#include "x509util.h"
#include "common/banned.h"

#define GDS_NS_URI "http://opcfoundation.org/UA/GDS/"

static UA_DataTypeArray gdsTypes = {NULL, UA_TYPES_GDS_COUNT, UA_TYPES_GDS, false};

const UA_DataType *gt_record_type(void) {
    return &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE];
}

UA_NodeId gt_node(const gds_target *t, UA_UInt32 id) {
    return UA_NODEID_NUMERIC(t->ns, id);
}

UA_NodeId gt_default_group(const gds_target *t) {
    return gt_node(t, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
}

UA_NodeId gt_rsa_type(void) {
    return UA_NODEID_NUMERIC(0, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);
}

UA_Client *gt_new_client(gds_target *t) {
    UA_Client *c = uac_new_secure(&t->cert, &t->key, t->trust, t->trustN, t->crls, t->crlN,
                                  t->appUri);
    if(c)
        UA_Client_getConfig(c)->customDataTypes = &gdsTypes;
    return c;
}

UA_StatusCode gt_session(gds_target *t) {
    if(t->client) {
        UA_SecureChannelState cs;
        UA_SessionState ss;
        UA_StatusCode st;
        UA_Client_getState(t->client, &cs, &ss, &st);
        if(ss == UA_SESSIONSTATE_ACTIVATED)
            return UA_STATUSCODE_GOOD;
        gt_close(t);
    }
    t->client = gt_new_client(t);
    if(!t->client)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode r = t->user ? UA_Client_connectUsername(t->client, t->url, t->user, t->password)
                              : UA_Client_connect(t->client, t->url);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Client_getNamespaceIndex(t->client, UA_STRING(GDS_NS_URI), &t->ns);
    if(r != UA_STATUSCODE_GOOD) {
        gt_close(t);
        return r;
    }
    gt_bind_ns(t->ns);
    return UA_STATUSCODE_GOOD;
}

void gt_bind_ns(UA_UInt16 ns) {
    /* The GDS types are encoded with the target's namespace index */
    for(size_t i = 0; i < UA_TYPES_GDS_COUNT; i++) {
        UA_TYPES_GDS[i].typeId.namespaceIndex = ns;
        UA_TYPES_GDS[i].binaryEncodingId.namespaceIndex = ns;
    }
}

void gt_close(gds_target *t) {
    if(!t->client)
        return;
    UA_Client_disconnect(t->client);
    UA_Client_delete(t->client);
    t->client = NULL;
}

void gt_clear(gds_target *t) {
    gt_close(t);
    for(size_t i = 0; i < t->trustN; i++)
        gds_buf_free(&t->trust[i]);
    for(size_t i = 0; i < t->crlN; i++)
        gds_buf_free(&t->crls[i]);
    gds_buf_free(&t->cert);
    gds_buf_free_secret(&t->key);
    OPENSSL_cleanse(t->password, sizeof(t->password));
}

void gt_free_out(UA_Variant *out, size_t outN) {
    if(out)
        UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
}

UA_StatusCode gt_call(gds_target *t, UA_UInt32 methodId, size_t inN, const UA_Variant *in,
                      size_t minOut, size_t *outN, UA_Variant **out) {
    *outN = 0;
    *out = NULL;
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    r = UA_Client_call(t->client, gt_node(t, UA_GDSID_DIRECTORY), gt_node(t, methodId), inN, in,
                       outN, out);
    if(r == UA_STATUSCODE_GOOD && *outN < minOut)
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    if(r != UA_STATUSCODE_GOOD) {
        gt_free_out(*out, *outN);
        *out = NULL;
        *outN = 0;
    }
    return r;
}

void gt_unique_uri(gds_target *t, char *out, size_t outLen) {
    if(gds_path(out, outLen, "urn:opengds:auditor:%s:%u", t->runTag, ++t->seq) != GDS_OK)
        out[0] = '\0';
}

void gt_record(UA_ApplicationRecordDataType *rec, const char *uri, UA_ApplicationType type,
               UA_LocalizedText *nameStorage, UA_String *discoveryUrlStorage) {
    UA_ApplicationRecordDataType_init(rec);
    rec->applicationUri = UA_STRING((char *)(uintptr_t)uri);
    rec->applicationType = type;
    *nameStorage = UA_LOCALIZEDTEXT("en", "OpenGDS Auditor test application");
    rec->applicationNames = nameStorage;
    rec->applicationNamesSize = 1;
    rec->productUri = UA_STRING("urn:opengds:auditor:product");
    if(type != UA_APPLICATIONTYPE_CLIENT) {
        *discoveryUrlStorage = UA_STRING("opc.tcp://auditor-test.invalid:4840");
        rec->discoveryUrls = discoveryUrlStorage;
        rec->discoveryUrlsSize = 1;
    }
}

UA_StatusCode gt_register_record(gds_target *t, const UA_ApplicationRecordDataType *rec,
                                 UA_NodeId *appId) {
    UA_NodeId_init(appId);
    UA_StatusCode r = gt_session(t); /* binds the GDS type namespace before encoding */
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_Variant in;
    UA_Variant_setScalar(&in, (void *)(uintptr_t)rec, gt_record_type());
    size_t outN = 0;
    UA_Variant *out = NULL;
    r = gt_call(t, UA_GDSID_DIRECTORY_REGISTERAPPLICATION, 1, &in, 1, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_NodeId *id = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_NODEID]);
    if(!id || UA_NodeId_isNull(id))
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    else
        r = UA_NodeId_copy(id, appId);
    gt_free_out(out, outN);
    return r;
}

UA_StatusCode gt_register(gds_target *t, UA_ApplicationType type, char *uriOut, size_t uriLen,
                          UA_NodeId *appId) {
    UA_NodeId_init(appId);
    gt_unique_uri(t, uriOut, uriLen);
    UA_ApplicationRecordDataType rec;
    UA_LocalizedText name;
    UA_String url;
    gt_record(&rec, uriOut, type, &name, &url);
    return gt_register_record(t, &rec, appId);
}

UA_StatusCode gt_call_obj(gds_target *t, UA_NodeId obj, UA_NodeId method, size_t inN,
                          const UA_Variant *in, size_t minOut, size_t *outN, UA_Variant **out) {
    *outN = 0;
    *out = NULL;
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    r = UA_Client_call(t->client, obj, method, inN, in, outN, out);
    if(r == UA_STATUSCODE_GOOD && *outN < minOut)
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    if(r != UA_STATUSCODE_GOOD) {
        gt_free_out(*out, *outN);
        *out = NULL;
        *outN = 0;
    }
    return r;
}

UA_StatusCode gt_find(UA_Client *c, UA_NodeId parent, UA_UInt16 ns, const char *name,
                      UA_NodeId *out) {
    UA_NodeId_init(out);
    UA_RelativePathElement el;
    UA_RelativePathElement_init(&el);
    el.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HIERARCHICALREFERENCES);
    el.includeSubtypes = true;
    el.targetName = UA_QUALIFIEDNAME(ns, (char *)(uintptr_t)name);
    UA_BrowsePath bp;
    UA_BrowsePath_init(&bp);
    bp.startingNode = parent;
    bp.relativePath.elements = &el;
    bp.relativePath.elementsSize = 1;
    UA_TranslateBrowsePathsToNodeIdsRequest req;
    UA_TranslateBrowsePathsToNodeIdsRequest_init(&req);
    req.browsePaths = &bp;
    req.browsePathsSize = 1;
    UA_TranslateBrowsePathsToNodeIdsResponse resp =
        UA_Client_Service_translateBrowsePathsToNodeIds(c, req);
    UA_StatusCode r = resp.responseHeader.serviceResult;
    if(r == UA_STATUSCODE_GOOD) {
        if(resp.resultsSize != 1 || resp.results[0].statusCode != UA_STATUSCODE_GOOD ||
           resp.results[0].targetsSize < 1)
            r = UA_STATUSCODE_BADNOTFOUND;
        else
            r = UA_NodeId_copy(&resp.results[0].targets[0].targetId.nodeId, out);
    }
    UA_TranslateBrowsePathsToNodeIdsResponse_clear(&resp);
    return r;
}

UA_Client *gt_anon_session(gds_target *t, UA_StatusCode *r) {
    UA_Client *c = gt_new_client(t);
    if(!c) {
        *r = UA_STATUSCODE_BADOUTOFMEMORY;
        return NULL;
    }
    *r = UA_Client_connect(c, t->url);
    if(*r != UA_STATUSCODE_GOOD) {
        UA_Client_delete(c);
        return NULL;
    }
    return c;
}

UA_Client *gt_sign_only_session(gds_target *t, UA_StatusCode *r) {
    static const char *const policies[] = {
        "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
        "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"};
    *r = UA_STATUSCODE_BADSECURITYPOLICYREJECTED;
    for(size_t i = 0; i < sizeof(policies) / sizeof(policies[0]); i++) {
        UA_Client *c = uac_new_secure_mode(&t->cert, &t->key, t->trust, t->trustN, t->crls,
                                           t->crlN, t->appUri, policies[i],
                                           UA_MESSAGESECURITYMODE_SIGN);
        if(!c) {
            *r = UA_STATUSCODE_BADOUTOFMEMORY;
            continue;
        }
        UA_Client_getConfig(c)->customDataTypes = &gdsTypes;
        *r = t->user ? UA_Client_connectUsername(c, t->url, t->user, t->password)
                     : UA_Client_connect(c, t->url);
        if(*r == UA_STATUSCODE_GOOD)
            return c;
        UA_Client_delete(c);
    }
    return NULL;
}

void gt_drop(UA_Client *c) {
    if(!c)
        return;
    UA_Client_disconnect(c);
    UA_Client_delete(c);
}

UA_StatusCode gt_issue(gds_target *t, ga_ctx *ctx, char *uri, size_t uriLen, UA_NodeId *appId,
                       gds_buf *cert, gds_buf *issuer) {
    cert->data = issuer->data = NULL;
    cert->len = issuer->len = 0;
    UA_StatusCode r = gt_register(t, UA_APPLICATIONTYPE_CLIENT, uri, uriLen, appId);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    gds_buf key = {0}, csr = {0};
    size_t privLen = 0;
    if(x509_new_rsa_key(2048, &key) != GDS_OK ||
       x509_make_csr(&key, "OpenGDS Auditor test", uri, NULL, &csr) != GDS_OK)
        r = UA_STATUSCODE_BADINTERNALERROR;
    else
        r = gt_sign(t, appId, &csr, ctx, cert, issuer, &privLen);
    gds_buf_free_secret(&key);
    gds_buf_free(&csr);
    if(r != UA_STATUSCODE_GOOD)
        UA_NodeId_clear(appId);
    return r;
}

UA_StatusCode gt_sign(gds_target *t, const UA_NodeId *appId, const gds_buf *csr, ga_ctx *ctx,
                      gds_buf *certOut, gds_buf *issuerOut, size_t *privKeyLen) {
    certOut->data = issuerOut->data = NULL;
    certOut->len = issuerOut->len = 0;
    *privKeyLen = 0;
    UA_NodeId group = gt_default_group(t), type = gt_rsa_type();
    UA_ByteString csrBs = {csr->len, csr->data};
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &type, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[3], &csrBs, &UA_TYPES[UA_TYPES_BYTESTRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = gt_call(t, UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST, 4, in, 1, &outN, &out);
    if(r != UA_STATUSCODE_GOOD) {
        ga_note(ctx, "StartSigningRequest -> %s", UA_StatusCode_name(r));
        return r;
    }
    UA_NodeId reqId;
    const UA_NodeId *rid = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_NODEID]);
    r = rid ? UA_NodeId_copy(rid, &reqId) : UA_STATUSCODE_BADUNEXPECTEDERROR;
    gt_free_out(out, outN);
    if(r != UA_STATUSCODE_GOOD)
        return r;

    UA_Variant fin[2];
    UA_Variant_setScalar(&fin[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&fin[1], &reqId, &UA_TYPES[UA_TYPES_NODEID]);
    unsigned waited = 0;
    for(;;) {
        r = gt_call(t, UA_GDSID_DIRECTORY_FINISHREQUEST, 2, fin, 3, &outN, &out);
        if(r != UA_STATUSCODE_BADNOTHINGTODO || waited >= t->pollSeconds)
            break;
        waited++;
        sleep(1);
    }
    ga_note(ctx, "FinishRequest -> %s after %u pending poll(s)", UA_StatusCode_name(r), waited);
    UA_NodeId_clear(&reqId);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_ByteString *c = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
    const UA_ByteString *k = uac_out_scalar(out, outN, 1, &UA_TYPES[UA_TYPES_BYTESTRING]);
    const void *iss = NULL;
    size_t nIss = 0;
    if(!c || gds_arg_array(&out[2], &UA_TYPES[UA_TYPES_BYTESTRING], GDS_MAX_CHAIN_LEN, &iss,
                           &nIss) != UA_STATUSCODE_GOOD) {
        gt_free_out(out, outN);
        return UA_STATUSCODE_BADUNEXPECTEDERROR;
    }
    *privKeyLen = k ? k->length : 0;
    gds_status s = gds_buf_dup(c->data, c->length, certOut);
    if(s == GDS_OK && nIss > 0) {
        const UA_ByteString *i0 = iss;
        s = gds_buf_dup(i0[0].data, i0[0].length, issuerOut);
    }
    gt_free_out(out, outN);
    if(s != GDS_OK) {
        gds_buf_free(certOut);
        gds_buf_free(issuerOut);
        return gds_status_to_ua(s);
    }
    return UA_STATUSCODE_GOOD;
}

bool gt_absent(ga_ctx *ctx, UA_StatusCode r, bool optional, const char *method) {
    if(r != UA_STATUSCODE_BADMETHODINVALID && r != UA_STATUSCODE_BADNOTIMPLEMENTED &&
       r != UA_STATUSCODE_BADNODEIDUNKNOWN)
        return false;
    if(optional)
        ga_not_supported(ctx, "%s (Optional) not offered: %s", method, UA_StatusCode_name(r));
    else
        ga_fail(ctx, "%s (Mandatory) not offered: %s", method, UA_StatusCode_name(r));
    return true;
}

UA_StatusCode gt_service(gds_target *t, UA_NodeId folder, const char *method, UA_NodeId *obj) {
    UA_NodeId_init(obj);
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = folder;
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HIERARCHICALREFERENCES);
    bd.includeSubtypes = true;
    bd.nodeClassMask = UA_NODECLASS_OBJECT;
    bd.resultMask = UA_BROWSERESULTMASK_NONE;
    UA_BrowseRequest req;
    UA_BrowseRequest_init(&req);
    req.nodesToBrowse = &bd;
    req.nodesToBrowseSize = 1;
    req.requestedMaxReferencesPerNode = 64;
    UA_BrowseResponse resp = UA_Client_Service_browse(t->client, req);
    r = resp.responseHeader.serviceResult;
    if(r == UA_STATUSCODE_GOOD && (resp.resultsSize != 1 || resp.results[0].statusCode != UA_STATUSCODE_GOOD))
        r = resp.resultsSize == 1 ? resp.results[0].statusCode : UA_STATUSCODE_BADUNEXPECTEDERROR;
    bool found = false;
    for(size_t i = 0; r == UA_STATUSCODE_GOOD && !found && i < resp.results[0].referencesSize; i++) {
        const UA_ExpandedNodeId *x = &resp.results[0].references[i].nodeId;
        if(x->serverIndex != 0 || x->namespaceUri.length > 0)
            continue;
        UA_NodeId m;
        if(gt_find(t->client, x->nodeId, t->ns, method, &m) == UA_STATUSCODE_GOOD) {
            UA_NodeId_clear(&m);
            r = UA_NodeId_copy(&x->nodeId, obj);
            found = true;
        }
    }
    UA_BrowseResponse_clear(&resp);
    if(r == UA_STATUSCODE_GOOD && !found)
        r = UA_STATUSCODE_BADNOTFOUND;
    return r;
}
