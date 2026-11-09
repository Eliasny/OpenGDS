/* OpenGDS libgdsclient - GDS Directory and CertificateManager wrappers
 * (OPC 10000-12 v1.05.07 §6.5, §7.9).
 * SPDX-License-Identifier: MPL-2.0 */
#include "gdsc_gds.h"

#include <open62541/client_highlevel.h>
#include <open62541/nodeids_gds.h>

#include <string.h>
#include <time.h>

#include "gdsc_push.h"
#include "common/ua_args.h"
#include "common/banned.h"

static UA_DataTypeArray gdsTypes = {NULL, UA_TYPES_GDS_COUNT, UA_TYPES_GDS, false};

static const UA_DataType *record_type(void) {
    return &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE];
}

UA_StatusCode gdsc_gds_bind(UA_Client *c, UA_UInt16 *ns) {
    UA_StatusCode r = UA_Client_getNamespaceIndex(c, UA_STRING(GDSC_GDS_NS_URI), ns);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    /* The GDS DataTypes are encoded with the GDS's namespace index */
    for(size_t i = 0; i < UA_TYPES_GDS_COUNT; i++) {
        UA_TYPES_GDS[i].typeId.namespaceIndex = *ns;
        UA_TYPES_GDS[i].binaryEncodingId.namespaceIndex = *ns;
    }
    UA_Client_getConfig(c)->customDataTypes = &gdsTypes;
    return UA_STATUSCODE_GOOD;
}

UA_NodeId gdsc_gds_default_group(UA_UInt16 ns) {
    return UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
}

static UA_StatusCode dir_call(UA_Client *c, UA_UInt16 ns, UA_UInt32 method, size_t inN,
                              const UA_Variant *in, size_t minOut, UA_Variant **out,
                              size_t *outN) {
    *out = NULL;
    *outN = 0;
    UA_StatusCode r = UA_Client_call(c, UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY),
                                     UA_NODEID_NUMERIC(ns, method), inN, in, outN, out);
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

/* Output i as a non-null NodeId, copied */
static UA_StatusCode out_nodeid(const UA_Variant *out, size_t i, UA_NodeId *id) {
    const void *p = NULL;
    if(gds_arg_scalar(&out[i], &UA_TYPES[UA_TYPES_NODEID], &p) != UA_STATUSCODE_GOOD ||
       UA_NodeId_isNull(p))
        return UA_STATUSCODE_BADUNEXPECTEDERROR;
    return UA_NodeId_copy(p, id);
}

UA_StatusCode gdsc_find_applications(UA_Client *c, UA_UInt16 ns, const char *applicationUri,
                                     UA_ApplicationRecordDataType **recs, size_t *n) {
    *recs = NULL;
    *n = 0;
    if(!applicationUri || strlen(applicationUri) >= GDS_MAX_APPLICATION_URI)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_String uri = UA_STRING((char *)(uintptr_t)applicationUri);
    UA_Variant in, *out = NULL;
    size_t outN = 0;
    UA_Variant_setScalar(&in, &uri, &UA_TYPES[UA_TYPES_STRING]);
    UA_StatusCode r = dir_call(c, ns, UA_GDSID_DIRECTORY_FINDAPPLICATIONS, 1, &in, 1, &out, &outN);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const void *arr = NULL;
    size_t len = 0;
    r = gds_arg_array(&out[0], record_type(), GDS_MAX_QUERY_RECORDS, &arr, &len);
    if(r == UA_STATUSCODE_GOOD && len > 0)
        r = UA_Array_copy(arr, len, (void **)recs, record_type());
    if(r == UA_STATUSCODE_GOOD)
        *n = len;
    out_free(out, outN);
    return r;
}

UA_StatusCode gdsc_register_application(UA_Client *c, UA_UInt16 ns,
                                        const UA_ApplicationRecordDataType *rec,
                                        UA_NodeId *applicationId) {
    UA_NodeId_init(applicationId);
    UA_Variant in, *out = NULL;
    size_t outN = 0;
    UA_Variant_setScalar(&in, (void *)(uintptr_t)rec, record_type());
    UA_StatusCode r =
        dir_call(c, ns, UA_GDSID_DIRECTORY_REGISTERAPPLICATION, 1, &in, 1, &out, &outN);
    if(r == UA_STATUSCODE_GOOD)
        r = out_nodeid(out, 0, applicationId);
    out_free(out, outN);
    return r;
}

UA_StatusCode gdsc_unregister_application(UA_Client *c, UA_UInt16 ns,
                                          const UA_NodeId *applicationId) {
    UA_Variant in, *out = NULL;
    size_t outN = 0;
    UA_Variant_setScalar(&in, (void *)(uintptr_t)applicationId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_StatusCode r =
        dir_call(c, ns, UA_GDSID_DIRECTORY_UNREGISTERAPPLICATION, 1, &in, 0, &out, &outN);
    out_free(out, outN);
    return r;
}

UA_StatusCode gdsc_revoke_certificate(UA_Client *c, UA_UInt16 ns, const UA_NodeId *applicationId,
                                      const gds_buf *cert) {
    if(!cert || !cert->data || cert->len == 0 || cert->len > GDS_MAX_CERT_SIZE)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_ByteString bs = {cert->len, cert->data};
    UA_Variant in[2], *out = NULL;
    size_t outN = 0;
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)applicationId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &bs, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_StatusCode r =
        dir_call(c, ns, UA_GDSID_DIRECTORY_REVOKECERTIFICATE, 2, in, 0, &out, &outN);
    out_free(out, outN);
    return r;
}

UA_StatusCode gdsc_start_signing_request(UA_Client *c, UA_UInt16 ns, const UA_NodeId *appId,
                                         const UA_NodeId *group, const UA_NodeId *certType,
                                         const gds_buf *csr, UA_NodeId *reqId) {
    UA_NodeId_init(reqId);
    if(!csr || !csr->data || csr->len == 0 || csr->len > GDS_MAX_CSR_SIZE)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_ByteString csrBs = {csr->len, csr->data};
    UA_Variant in[4], *out = NULL;
    size_t outN = 0;
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], (void *)(uintptr_t)group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], (void *)(uintptr_t)certType, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[3], &csrBs, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_StatusCode r =
        dir_call(c, ns, UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST, 4, in, 1, &out, &outN);
    if(r == UA_STATUSCODE_GOOD)
        r = out_nodeid(out, 0, reqId);
    out_free(out, outN);
    return r;
}

/* FinishRequest outputs (§7.9.6): certificate, privateKey, issuerCertificates */
static UA_StatusCode take_issued(const UA_Variant *out, gds_buf *certOut, gds_buf *issuersOut,
                                 size_t *issuersN) {
    const UA_ByteString *cert = NULL, *key = NULL;
    const void *iss = NULL;
    size_t nIss = 0;
    if(gds_arg_bytes(&out[0], GDS_MAX_CERT_SIZE, &cert) != UA_STATUSCODE_GOOD ||
       cert->length == 0 || gds_arg_bytes(&out[1], GDS_MAX_KEY_SIZE, &key) != UA_STATUSCODE_GOOD ||
       gds_arg_array(&out[2], &UA_TYPES[UA_TYPES_BYTESTRING], GDS_MAX_CHAIN_LEN, &iss, &nIss) !=
           UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADUNEXPECTEDERROR;
    if(key->length > 0)
        return UA_STATUSCODE_BADUNEXPECTEDERROR; /* the device made its own key */
    const UA_ByteString *ib = iss;
    for(size_t i = 0; i < nIss; i++)
        if(ib[i].length == 0 || ib[i].length > GDS_MAX_CERT_SIZE)
            return UA_STATUSCODE_BADUNEXPECTEDERROR;
    gds_status s = gds_buf_dup(cert->data, cert->length, certOut);
    for(size_t i = 0; s == GDS_OK && i < nIss; i++) {
        s = gds_buf_dup(ib[i].data, ib[i].length, &issuersOut[i]);
        if(s == GDS_OK)
            *issuersN = i + 1;
    }
    return gds_status_to_ua(s);
}

static void issued_free(gds_buf *certOut, gds_buf *issuersOut, size_t *issuersN) {
    gds_buf_free(certOut);
    for(size_t i = 0; i < *issuersN; i++)
        gds_buf_free(&issuersOut[i]);
    *issuersN = 0;
}

UA_StatusCode gdsc_finish_request(UA_Client *c, UA_UInt16 ns, const UA_NodeId *appId,
                                  const UA_NodeId *reqId, gds_buf *certOut, gds_buf *issuersOut,
                                  size_t *issuersN) {
    memset(certOut, 0, sizeof(*certOut));
    *issuersN = 0;
    UA_Variant in[2], *out = NULL;
    size_t outN = 0;
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], (void *)(uintptr_t)reqId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_StatusCode r = dir_call(c, ns, UA_GDSID_DIRECTORY_FINISHREQUEST, 2, in, 3, &out, &outN);
    if(r == UA_STATUSCODE_GOOD)
        r = take_issued(out, certOut, issuersOut, issuersN);
    if(r != UA_STATUSCODE_GOOD)
        issued_free(certOut, issuersOut, issuersN);
    out_free(out, outN);
    return r;
}

UA_StatusCode gdsc_sign_csr(UA_Client *c, UA_UInt16 ns, const UA_NodeId *appId,
                            const UA_NodeId *group, const UA_NodeId *certType,
                            const gds_buf *csr, unsigned pollSeconds, gds_buf *certOut,
                            gds_buf *issuersOut, size_t *issuersN) {
    memset(certOut, 0, sizeof(*certOut));
    *issuersN = 0;
    UA_NodeId reqId;
    UA_StatusCode r = gdsc_start_signing_request(c, ns, appId, group, certType, csr, &reqId);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const struct timespec step = {1, 0};
    for(unsigned waited = 0;; waited++) {
        r = gdsc_finish_request(c, ns, appId, &reqId, certOut, issuersOut, issuersN);
        if(r != UA_STATUSCODE_BADNOTHINGTODO || waited >= pollSeconds)
            break;
        nanosleep(&step, NULL); /* §7.9.6: Bad_NothingToDo while not yet signed */
    }
    UA_NodeId_clear(&reqId);
    return r;
}

UA_StatusCode gdsc_get_certificate_groups(UA_Client *c, UA_UInt16 ns, const UA_NodeId *appId,
                                          UA_NodeId **groups, size_t *n) {
    *groups = NULL;
    *n = 0;
    UA_Variant in, *out = NULL;
    size_t outN = 0;
    UA_Variant_setScalar(&in, (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_StatusCode r =
        dir_call(c, ns, UA_GDSID_DIRECTORY_GETCERTIFICATEGROUPS, 1, &in, 1, &out, &outN);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const void *arr = NULL;
    size_t len = 0;
    r = gds_arg_array(&out[0], &UA_TYPES[UA_TYPES_NODEID], GDSC_MAX_GROUPS, &arr, &len);
    if(r == UA_STATUSCODE_GOOD && len > 0)
        r = UA_Array_copy(arr, len, (void **)groups, &UA_TYPES[UA_TYPES_NODEID]);
    if(r == UA_STATUSCODE_GOOD)
        *n = len;
    out_free(out, outN);
    return r;
}

UA_StatusCode gdsc_get_certificate_status(UA_Client *c, UA_UInt16 ns, const UA_NodeId *appId,
                                          const UA_NodeId *group, const UA_NodeId *certType,
                                          bool *updateRequired) {
    UA_Variant in[3], *out = NULL;
    size_t outN = 0;
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], (void *)(uintptr_t)group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], (void *)(uintptr_t)certType, &UA_TYPES[UA_TYPES_NODEID]);
    UA_StatusCode r =
        dir_call(c, ns, UA_GDSID_DIRECTORY_GETCERTIFICATESTATUS, 3, in, 1, &out, &outN);
    const void *p = NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_scalar(&out[0], &UA_TYPES[UA_TYPES_BOOLEAN], &p);
    if(r == UA_STATUSCODE_GOOD)
        *updateRequired = *(const UA_Boolean *)p;
    out_free(out, outN);
    return r;
}

UA_StatusCode gdsc_get_trust_list_id(UA_Client *c, UA_UInt16 ns, const UA_NodeId *appId,
                                     const UA_NodeId *group, UA_NodeId *tl) {
    UA_NodeId_init(tl);
    UA_Variant in[2], *res = NULL;
    size_t resN = 0;
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], (void *)(uintptr_t)group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_StatusCode r = dir_call(c, ns, UA_GDSID_DIRECTORY_GETTRUSTLIST, 2, in, 1, &res, &resN);
    if(r == UA_STATUSCODE_GOOD)
        r = out_nodeid(res, 0, tl);
    out_free(res, resN);
    return r;
}

UA_StatusCode gdsc_get_trust_list(UA_Client *c, UA_UInt16 ns, const UA_NodeId *appId,
                                  const UA_NodeId *group, UA_TrustListDataType *out) {
    UA_TrustListDataType_init(out);
    UA_NodeId tl;
    UA_StatusCode r = gdsc_get_trust_list_id(c, ns, appId, group, &tl);
    if(r == UA_STATUSCODE_GOOD)
        r = gdsc_trustlist_read(c, &tl, out);
    UA_NodeId_clear(&tl);
    return r;
}
