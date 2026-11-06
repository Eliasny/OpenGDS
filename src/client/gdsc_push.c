/* OpenGDS libgdsclient - push wrappers (OPC 10000-12 v1.05.07 §7.7, §7.8.2,
 * §7.10).
 * SPDX-License-Identifier: MPL-2.0 */
#include "gdsc_push.h"

#include <open62541/client_highlevel.h>

#include <stdint.h>
#include <string.h>

#include "common/limits.h"
#include "common/ua_args.h"
#include "common/banned.h"

/* FileType open modes (OPC 10000-5 §C.2.1); 12 §7.8.2.2 allows only these two */
#define TL_MODE_READ ((UA_Byte)0x01)
#define TL_MODE_WRITE_ERASE ((UA_Byte)0x06)

#define TL_READ_BLOCK ((UA_Int32)16384)

static UA_NodeId ns0(UA_UInt32 id) {
    return UA_NODEID_NUMERIC(0, id);
}

static void out_free(UA_Variant **out, size_t *outN) {
    if(*out)
        UA_Array_delete(*out, *outN, &UA_TYPES[UA_TYPES_VARIANT]);
    *out = NULL;
    *outN = 0;
}

/* Call a method; on Good the result has at least minOut outputs, else
 * Bad_UnexpectedError and nothing is returned. */
static UA_StatusCode call(UA_Client *c, const UA_NodeId *obj, const UA_NodeId *method,
                          size_t inN, const UA_Variant *in, size_t minOut, UA_Variant **out,
                          size_t *outN) {
    *out = NULL;
    *outN = 0;
    UA_StatusCode r = UA_Client_call(c, *obj, *method, inN, in, outN, out);
    if(r == UA_STATUSCODE_GOOD && *outN < minOut)
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    if(r != UA_STATUSCODE_GOOD)
        out_free(out, outN);
    return r;
}

/* Output i as a Boolean scalar; a missing or mistyped value is an error */
static UA_StatusCode out_bool(const UA_Variant *out, size_t outN, size_t i, bool *v) {
    const void *p = NULL;
    if(i >= outN || gds_arg_scalar(&out[i], &UA_TYPES[UA_TYPES_BOOLEAN], &p) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADUNEXPECTEDERROR;
    *v = *(const UA_Boolean *)p;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode gdsc_find_child(UA_Client *c, const UA_NodeId *parent, const char *browseName,
                              UA_NodeId *out) {
    UA_NodeId_init(out);
    UA_RelativePathElement el;
    UA_RelativePathElement_init(&el);
    el.referenceTypeId = ns0(UA_NS0ID_HIERARCHICALREFERENCES);
    el.includeSubtypes = true;
    el.targetName = UA_QUALIFIEDNAME(0, (char *)(uintptr_t)browseName);
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
    if(r == UA_STATUSCODE_GOOD) {
        if(resp.resultsSize != 1)
            r = UA_STATUSCODE_BADUNEXPECTEDERROR;
        else if(resp.results[0].statusCode != UA_STATUSCODE_GOOD)
            r = resp.results[0].statusCode;
        else if(resp.results[0].targetsSize < 1)
            r = UA_STATUSCODE_BADNOMATCH;
        else
            r = UA_NodeId_copy(&resp.results[0].targets[0].targetId.nodeId, out);
    }
    UA_TranslateBrowsePathsToNodeIdsResponse_clear(&resp);
    return r;
}

static UA_StatusCode read_uint32(UA_Client *c, const UA_NodeId *node, UA_UInt32 *out) {
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode r = UA_Client_readValueAttribute(c, *node, &v);
    const void *p = NULL;
    if(r == UA_STATUSCODE_GOOD && gds_arg_scalar(&v, &UA_TYPES[UA_TYPES_UINT32], &p) != UA_STATUSCODE_GOOD)
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    if(r == UA_STATUSCODE_GOOD)
        *out = *(const UA_UInt32 *)p;
    UA_Variant_clear(&v);
    return r;
}

UA_StatusCode gdsc_read_max_trustlist_size(UA_Client *c, UA_UInt32 *out) {
    *out = 0;
    const UA_NodeId n = ns0(UA_NS0ID_SERVERCONFIGURATION_MAXTRUSTLISTSIZE);
    return read_uint32(c, &n, out);
}

/* The TrustList's FileType methods (12 §7.8.2), resolved by browse name so
 * that every CertificateGroup works, not only the well-known default. */
typedef struct {
    UA_NodeId open, write, read, close, closeAndUpdate;
} tl_methods;

static void tl_methods_clear(tl_methods *m) {
    UA_NodeId_clear(&m->open);
    UA_NodeId_clear(&m->write);
    UA_NodeId_clear(&m->read);
    UA_NodeId_clear(&m->close);
    UA_NodeId_clear(&m->closeAndUpdate);
}

static UA_StatusCode tl_methods_find(UA_Client *c, const UA_NodeId *tl, bool forWrite,
                                     tl_methods *m) {
    memset(m, 0, sizeof(*m));
    UA_StatusCode r = gdsc_find_child(c, tl, "Open", &m->open);
    if(r == UA_STATUSCODE_GOOD)
        r = gdsc_find_child(c, tl, "Close", &m->close);
    if(r == UA_STATUSCODE_GOOD && forWrite)
        r = gdsc_find_child(c, tl, "Write", &m->write);
    if(r == UA_STATUSCODE_GOOD && forWrite)
        r = gdsc_find_child(c, tl, "CloseAndUpdate", &m->closeAndUpdate);
    if(r == UA_STATUSCODE_GOOD && !forWrite)
        r = gdsc_find_child(c, tl, "Read", &m->read);
    if(r != UA_STATUSCODE_GOOD)
        tl_methods_clear(m);
    return r;
}

static UA_StatusCode tl_open(UA_Client *c, const UA_NodeId *tl, const tl_methods *m,
                             UA_Byte mode, UA_UInt32 *handle) {
    UA_Variant in, *out = NULL;
    size_t outN = 0;
    UA_Variant_setScalar(&in, &mode, &UA_TYPES[UA_TYPES_BYTE]);
    UA_StatusCode r = call(c, tl, &m->open, 1, &in, 1, &out, &outN);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const void *p = NULL;
    if(gds_arg_scalar(&out[0], &UA_TYPES[UA_TYPES_UINT32], &p) != UA_STATUSCODE_GOOD)
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    else
        *handle = *(const UA_UInt32 *)p;
    out_free(&out, &outN);
    return r;
}

static void tl_close(UA_Client *c, const UA_NodeId *tl, const tl_methods *m, UA_UInt32 handle) {
    UA_Variant in, *out = NULL;
    size_t outN = 0;
    UA_Variant_setScalar(&in, &handle, &UA_TYPES[UA_TYPES_UINT32]);
    /* Best effort: the Server also drops the handle with the Session */
    UA_StatusCode r = call(c, tl, &m->close, 1, &in, 0, &out, &outN);
    (void)r;
    out_free(&out, &outN);
}

/* Block size for Write: GDSC_TL_BLOCK, or the TrustList's
 * MaxByteStringLength (OPC 10000-5 FileType, 12 §7.7.3) when lower. */
static size_t tl_block_size(UA_Client *c, const UA_NodeId *tl) {
    UA_NodeId prop;
    UA_UInt32 max = 0;
    size_t block = GDSC_TL_BLOCK;
    if(gdsc_find_child(c, tl, "MaxByteStringLength", &prop) == UA_STATUSCODE_GOOD &&
       read_uint32(c, &prop, &max) == UA_STATUSCODE_GOOD && max > 0 && max < block)
        block = max;
    UA_NodeId_clear(&prop);
    return block;
}

static UA_StatusCode tl_write_blocks(UA_Client *c, const UA_NodeId *tl, const tl_methods *m,
                                     UA_UInt32 handle, const UA_ByteString *file) {
    const size_t block = tl_block_size(c, tl);
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    for(size_t off = 0; off < file->length && r == UA_STATUSCODE_GOOD; off += block) {
        size_t n = file->length - off < block ? file->length - off : block;
        UA_ByteString chunk = {n, file->data + off};
        UA_Variant in[2], *out = NULL;
        size_t outN = 0;
        UA_Variant_setScalar(&in[0], &handle, &UA_TYPES[UA_TYPES_UINT32]);
        UA_Variant_setScalar(&in[1], &chunk, &UA_TYPES[UA_TYPES_BYTESTRING]);
        r = call(c, tl, &m->write, 2, in, 0, &out, &outN);
        out_free(&out, &outN);
    }
    return r;
}

static UA_StatusCode tl_close_and_update(UA_Client *c, const UA_NodeId *tl, const tl_methods *m,
                                         UA_UInt32 handle, bool *acr) {
    UA_Variant in, *out = NULL;
    size_t outN = 0;
    UA_Variant_setScalar(&in, &handle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_StatusCode r = call(c, tl, &m->closeAndUpdate, 1, &in, 1, &out, &outN);
    if(r == UA_STATUSCODE_GOOD)
        r = out_bool(out, outN, 0, acr);
    out_free(&out, &outN);
    return r;
}

UA_StatusCode gdsc_trustlist_write(UA_Client *c, const UA_NodeId *trustList,
                                   const UA_TrustListDataType *tl, UA_UInt32 maxSize,
                                   bool *applyChangesRequired) {
    *applyChangesRequired = false;
    UA_ByteString file = UA_BYTESTRING_NULL;
    UA_StatusCode r = UA_encodeBinary(tl, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], &file, NULL);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if(file.length > GDS_MAX_TRUSTLIST_SIZE || (maxSize > 0 && file.length > maxSize)) {
        UA_ByteString_clear(&file);
        return UA_STATUSCODE_BADREQUESTTOOLARGE; /* 12 §7.8.2.5 */
    }
    tl_methods m;
    r = tl_methods_find(c, trustList, true, &m);
    UA_UInt32 handle = 0;
    if(r == UA_STATUSCODE_GOOD)
        r = tl_open(c, trustList, &m, TL_MODE_WRITE_ERASE, &handle);
    if(r == UA_STATUSCODE_GOOD) {
        r = tl_write_blocks(c, trustList, &m, handle, &file);
        if(r == UA_STATUSCODE_GOOD)
            r = tl_close_and_update(c, trustList, &m, handle, applyChangesRequired);
        else
            tl_close(c, trustList, &m, handle); /* discards what was written */
    }
    tl_methods_clear(&m);
    UA_ByteString_clear(&file);
    return r;
}

/* Read blocks until a short one; the file is bounded by GDS_MAX_TRUSTLIST_SIZE */
static UA_StatusCode tl_read_all(UA_Client *c, const UA_NodeId *tl, const tl_methods *m,
                                 UA_UInt32 handle, gds_buf *acc) {
    for(;;) {
        UA_Int32 len = TL_READ_BLOCK;
        UA_Variant in[2], *out = NULL;
        size_t outN = 0;
        UA_Variant_setScalar(&in[0], &handle, &UA_TYPES[UA_TYPES_UINT32]);
        UA_Variant_setScalar(&in[1], &len, &UA_TYPES[UA_TYPES_INT32]);
        UA_StatusCode r = call(c, tl, &m->read, 2, in, 1, &out, &outN);
        if(r != UA_STATUSCODE_GOOD)
            return r;
        const UA_ByteString *chunk = NULL;
        r = gds_arg_bytes(&out[0], (size_t)TL_READ_BLOCK, &chunk);
        if(r != UA_STATUSCODE_GOOD) {
            out_free(&out, &outN);
            return UA_STATUSCODE_BADUNEXPECTEDERROR;
        }
        size_t got = chunk->length;
        gds_status s = gds_buf_append(acc, chunk->data, got, GDS_MAX_TRUSTLIST_SIZE);
        out_free(&out, &outN);
        if(s != GDS_OK)
            return gds_status_to_ua(s);
        if(got < (size_t)TL_READ_BLOCK)
            return UA_STATUSCODE_GOOD;
    }
}

static bool tl_within_limits(const UA_TrustListDataType *t) {
    return t->trustedCertificatesSize <= GDS_MAX_TRUSTLIST_ENTRIES &&
           t->trustedCrlsSize <= GDS_MAX_TRUSTLIST_ENTRIES &&
           t->issuerCertificatesSize <= GDS_MAX_TRUSTLIST_ENTRIES &&
           t->issuerCrlsSize <= GDS_MAX_TRUSTLIST_ENTRIES;
}

UA_StatusCode gdsc_trustlist_read(UA_Client *c, const UA_NodeId *trustList,
                                  UA_TrustListDataType *out) {
    UA_TrustListDataType_init(out);
    tl_methods m;
    UA_StatusCode r = tl_methods_find(c, trustList, false, &m);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_UInt32 handle = 0;
    gds_buf acc = {0};
    r = tl_open(c, trustList, &m, TL_MODE_READ, &handle);
    if(r == UA_STATUSCODE_GOOD) {
        r = tl_read_all(c, trustList, &m, handle, &acc);
        tl_close(c, trustList, &m, handle);
    }
    if(r == UA_STATUSCODE_GOOD) {
        UA_ByteString file = {acc.len, acc.data};
        r = UA_decodeBinary(&file, out, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL);
        if(r == UA_STATUSCODE_GOOD && !tl_within_limits(out))
            r = UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
        if(r != UA_STATUSCODE_GOOD)
            UA_TrustListDataType_clear(out);
    }
    gds_buf_free(&acc);
    tl_methods_clear(&m);
    return r;
}

UA_StatusCode gdsc_create_signing_request(UA_Client *c, const UA_NodeId *group,
                                          const UA_NodeId *certType, gds_buf *csrOut) {
    memset(csrOut, 0, sizeof(*csrOut));
    UA_NodeId g = *group, t = *certType;
    UA_String subject = UA_STRING_NULL;
    UA_Boolean regen = false;
    UA_ByteString nonce = UA_BYTESTRING_NULL;
    UA_Variant in[5], *out = NULL;
    size_t outN = 0;
    UA_Variant_setScalar(&in[0], &g, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &t, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &subject, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[3], &regen, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Variant_setScalar(&in[4], &nonce, &UA_TYPES[UA_TYPES_BYTESTRING]);
    const UA_NodeId obj = ns0(UA_NS0ID_SERVERCONFIGURATION);
    const UA_NodeId method = ns0(UA_NS0ID_SERVERCONFIGURATION_CREATESIGNINGREQUEST);
    UA_StatusCode r = call(c, &obj, &method, 5, in, 1, &out, &outN);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_ByteString *csr = NULL;
    if(gds_arg_bytes(&out[0], GDS_MAX_CSR_SIZE, &csr) != UA_STATUSCODE_GOOD || csr->length == 0)
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    else if(gds_buf_dup(csr->data, csr->length, csrOut) != GDS_OK)
        r = UA_STATUSCODE_BADOUTOFMEMORY;
    out_free(&out, &outN);
    return r;
}

UA_StatusCode gdsc_update_certificate(UA_Client *c, const UA_NodeId *group,
                                      const UA_NodeId *certType, const gds_buf *cert,
                                      const gds_buf *issuers, size_t issuersN,
                                      bool *applyChangesRequired) {
    *applyChangesRequired = false;
    if(!cert->data || cert->len == 0 || cert->len > GDS_MAX_CERT_SIZE ||
       issuersN > GDS_MAX_CHAIN_LEN)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_ByteString iss[GDS_MAX_CHAIN_LEN];
    for(size_t i = 0; i < issuersN; i++) {
        iss[i].data = issuers[i].data;
        iss[i].length = issuers[i].len;
    }
    UA_NodeId g = *group, t = *certType;
    UA_ByteString cb = {cert->len, cert->data};
    UA_String keyFormat = UA_STRING_NULL;
    UA_ByteString key = UA_BYTESTRING_NULL;
    UA_Variant in[6], *out = NULL;
    size_t outN = 0;
    UA_Variant_setScalar(&in[0], &g, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &t, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &cb, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setArray(&in[3], issuersN ? iss : UA_EMPTY_ARRAY_SENTINEL, issuersN,
                        &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&in[4], &keyFormat, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[5], &key, &UA_TYPES[UA_TYPES_BYTESTRING]);
    const UA_NodeId obj = ns0(UA_NS0ID_SERVERCONFIGURATION);
    const UA_NodeId method = ns0(UA_NS0ID_SERVERCONFIGURATION_UPDATECERTIFICATE);
    UA_StatusCode r = call(c, &obj, &method, 6, in, 1, &out, &outN);
    if(r == UA_STATUSCODE_GOOD)
        r = out_bool(out, outN, 0, applyChangesRequired);
    out_free(&out, &outN);
    return r;
}

static UA_StatusCode call_no_args(UA_Client *c, UA_UInt32 methodId) {
    const UA_NodeId obj = ns0(UA_NS0ID_SERVERCONFIGURATION);
    const UA_NodeId method = ns0(methodId);
    UA_Variant *out = NULL;
    size_t outN = 0;
    UA_StatusCode r = call(c, &obj, &method, 0, NULL, 0, &out, &outN);
    out_free(&out, &outN);
    return r;
}

UA_StatusCode gdsc_apply_changes(UA_Client *c) {
    return call_no_args(c, UA_NS0ID_SERVERCONFIGURATION_APPLYCHANGES);
}

UA_StatusCode gdsc_cancel_changes(UA_Client *c) {
    return call_no_args(c, UA_NS0ID_SERVERCONFIGURATION_CANCELCHANGES);
}
