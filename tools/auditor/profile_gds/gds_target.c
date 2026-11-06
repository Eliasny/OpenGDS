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

UA_StatusCode gt_register(gds_target *t, UA_ApplicationType type, char *uriOut, size_t uriLen,
                          UA_NodeId *appId) {
    UA_NodeId_init(appId);
    gt_unique_uri(t, uriOut, uriLen);
    UA_ApplicationRecordDataType rec;
    UA_LocalizedText name;
    UA_String url;
    gt_record(&rec, uriOut, type, &name, &url);
    UA_StatusCode r = gt_session(t); /* binds the GDS type namespace before encoding */
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_Variant in;
    UA_Variant_setScalar(&in, &rec, gt_record_type());
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
