/* OpenGDS Auditor - OPC UA client helpers (open62541).
 * SPDX-License-Identifier: MPL-2.0 */
#include "uaclient.h"

#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/log_stdout.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/limits.h"
#include "common/banned.h"

/* Single-threaded tools: one step counter per process is enough. */
static unsigned stepNo = 0;
static bool quiet = false;

void uac_set_quiet(bool q) {
    quiet = q;
}

UA_LogLevel uac_log_level(void) {
    return quiet ? UA_LOGLEVEL_FATAL : UA_LOGLEVEL_WARNING;
}

void uac_step(const char *fmt, ...) {
    if(quiet)
        return;
    va_list ap;
    va_start(ap, fmt);
    printf("\n[%u] ", ++stepNo);
    vprintf(fmt, ap); /* NOLINT(clang-analyzer-valist.Uninitialized): va_start above */
    printf("\n");
    va_end(ap);
    fflush(stdout);
}

void uac_info(const char *fmt, ...) {
    if(quiet)
        return;
    va_list ap;
    va_start(ap, fmt);
    printf("    ");
    vprintf(fmt, ap); /* NOLINT(clang-analyzer-valist.Uninitialized): va_start above */
    printf("\n");
    va_end(ap);
    fflush(stdout);
}

static UA_ByteString *borrow_list(const gds_buf *items, size_t n) {
    UA_ByteString *l = calloc(n ? n : 1, sizeof(UA_ByteString));
    if(!l)
        return NULL;
    for(size_t i = 0; i < n; i++) {
        l[i].data = items[i].data;
        l[i].length = items[i].len;
    }
    return l;
}

UA_Client *uac_new_secure(const gds_buf *cert, const gds_buf *key, const gds_buf *trust,
                          size_t trustN, const gds_buf *crls, size_t crlN,
                          const char *applicationUri) {
    UA_ClientConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.logging = UA_Log_Stdout_new(uac_log_level());
    if(!cfg.logging || UA_ClientConfig_setDefault(&cfg) != UA_STATUSCODE_GOOD) {
        UA_ClientConfig_clear(&cfg);
        return NULL;
    }
    UA_ByteString *tl = borrow_list(trust, trustN);
    UA_ByteString *rl = borrow_list(crls, crlN);
    UA_StatusCode r = UA_STATUSCODE_BADOUTOFMEMORY;
    if(tl && rl) {
        UA_ByteString uc = {cert->len, cert->data}, uk = {key->len, key->data};
        r = UA_ClientConfig_setDefaultEncryption(&cfg, uc, uk, tl, trustN, rl, crlN);
    }
    free(tl);
    free(rl);
    if(r == UA_STATUSCODE_GOOD) {
        cfg.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
        UA_String_clear(&cfg.securityPolicyUri);
        cfg.securityPolicyUri = UA_STRING_ALLOC(POLICY_RSAPSS);
        UA_String_clear(&cfg.clientDescription.applicationUri);
        cfg.clientDescription.applicationUri = UA_STRING_ALLOC(applicationUri);
        if(!cfg.securityPolicyUri.data || !cfg.clientDescription.applicationUri.data)
            r = UA_STATUSCODE_BADOUTOFMEMORY;
    }
    if(r != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "client encryption config failed: %s\n", UA_StatusCode_name(r));
        UA_ClientConfig_clear(&cfg);
        return NULL;
    }
    UA_Client *c = UA_Client_newWithConfig(&cfg);
    if(!c)
        UA_ClientConfig_clear(&cfg);
    return c;
}

UA_StatusCode uac_fetch_server_cert(const char *url, UA_ByteString *out) {
    UA_ByteString_init(out);
    UA_ClientConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.logging = UA_Log_Stdout_new(uac_log_level());
    if(!cfg.logging || UA_ClientConfig_setDefault(&cfg) != UA_STATUSCODE_GOOD) {
        UA_ClientConfig_clear(&cfg);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    UA_Client *c = UA_Client_newWithConfig(&cfg);
    if(!c) {
        UA_ClientConfig_clear(&cfg);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    size_t n = 0;
    UA_EndpointDescription *eps = NULL;
    UA_StatusCode r = UA_Client_getEndpoints(c, url, &n, &eps);
    if(r == UA_STATUSCODE_GOOD) {
        r = UA_STATUSCODE_BADNOTFOUND;
        for(size_t i = 0; i < n; i++) {
            if(eps[i].securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT &&
               eps[i].serverCertificate.length > 0 &&
               eps[i].serverCertificate.length <= GDS_MAX_CERT_SIZE) {
                r = UA_ByteString_copy(&eps[i].serverCertificate, out);
                break;
            }
        }
        UA_Array_delete(eps, n, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    }
    UA_Client_delete(c);
    return r;
}

UA_StatusCode uac_find_child(UA_Client *c, const UA_NodeId parent, const char *name,
                             UA_NodeId *out) {
    UA_NodeId_init(out);
    UA_RelativePathElement el;
    UA_RelativePathElement_init(&el);
    el.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HIERARCHICALREFERENCES);
    el.includeSubtypes = true;
    el.targetName = UA_QUALIFIEDNAME(0, (char *)(uintptr_t)name);
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

UA_StatusCode uac_call(UA_Client *c, const char *label, UA_NodeId obj, UA_NodeId method,
                       size_t inSize, const UA_Variant *in, size_t minOutputs,
                       size_t *outSize, UA_Variant **out) {
    *outSize = 0;
    *out = NULL;
    UA_StatusCode r = UA_Client_call(c, obj, method, inSize, in, outSize, out);
    if(r == UA_STATUSCODE_GOOD && *outSize < minOutputs) {
        UA_Array_delete(*out, *outSize, &UA_TYPES[UA_TYPES_VARIANT]);
        *out = NULL;
        *outSize = 0;
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    } else if(r != UA_STATUSCODE_GOOD && *out) {
        UA_Array_delete(*out, *outSize, &UA_TYPES[UA_TYPES_VARIANT]);
        *out = NULL;
        *outSize = 0;
    }
    uac_info("%-26s -> %s", label, UA_StatusCode_name(r));
    return r;
}

const void *uac_out_scalar(const UA_Variant *out, size_t outSize, size_t i,
                           const UA_DataType *type) {
    if(!out || i >= outSize)
        return NULL;
    const void *p = NULL;
    if(gds_arg_scalar(&out[i], type, &p) != UA_STATUSCODE_GOOD)
        return NULL;
    return p;
}

/* 4 MiB in chunks of at least 1 KiB */
#define UAC_MAX_TL_READS ((size_t)4096)

UA_StatusCode uac_read_trustlist(UA_Client *c, const UA_NodeId tl, UA_TrustListDataType *out) {
    UA_TrustListDataType_init(out);
    UA_NodeId mOpen, mRead, mClose;
    UA_NodeId_init(&mOpen);
    UA_NodeId_init(&mRead);
    UA_NodeId_init(&mClose);
    UA_ByteString all = UA_BYTESTRING_NULL;
    gds_buf acc = {0};
    size_t outN = 0;
    UA_Variant *outV = NULL;
    UA_StatusCode r = uac_find_child(c, tl, "Open", &mOpen);
    if(r == UA_STATUSCODE_GOOD)
        r = uac_find_child(c, tl, "Read", &mRead);
    if(r == UA_STATUSCODE_GOOD)
        r = uac_find_child(c, tl, "Close", &mClose);
    if(r != UA_STATUSCODE_GOOD)
        goto cleanup;

    UA_Byte mode = 0x01; /* Read */
    UA_Variant in;
    UA_Variant_setScalar(&in, &mode, &UA_TYPES[UA_TYPES_BYTE]);
    r = uac_call(c, "TrustList.Open(Read)", tl, mOpen, 1, &in, 1, &outN, &outV);
    if(r != UA_STATUSCODE_GOOD)
        goto cleanup;
    const UA_UInt32 *hp = uac_out_scalar(outV, outN, 0, &UA_TYPES[UA_TYPES_UINT32]);
    if(!hp) {
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
        goto cleanup;
    }
    UA_UInt32 handle = *hp;
    UA_Array_delete(outV, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    outV = NULL;

    /* OPC 10000-20 §4.2.4: a Server may return less than Length; only an
     * empty ByteString means end of file. Bounded by size and Read count. */
    for(size_t reads = 0;; reads++) {
        if(reads == UAC_MAX_TL_READS) {
            r = UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
            break;
        }
        UA_Int32 len = 16384;
        UA_Variant rin[2];
        UA_Variant_setScalar(&rin[0], &handle, &UA_TYPES[UA_TYPES_UINT32]);
        UA_Variant_setScalar(&rin[1], &len, &UA_TYPES[UA_TYPES_INT32]);
        r = UA_Client_call(c, tl, mRead, 2, rin, &outN, &outV);
        if(r != UA_STATUSCODE_GOOD)
            break;
        const UA_ByteString *chunk =
            uac_out_scalar(outV, outN, 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
        if(!chunk || chunk->length > (size_t)len) {
            r = UA_STATUSCODE_BADUNEXPECTEDERROR;
            break;
        }
        size_t got = chunk->length;
        gds_status s = gds_buf_append(&acc, chunk->data, got, GDS_MAX_TRUSTLIST_SIZE);
        UA_Array_delete(outV, outN, &UA_TYPES[UA_TYPES_VARIANT]);
        outV = NULL;
        if(s != GDS_OK) {
            r = gds_status_to_ua(s);
            break;
        }
        if(got == 0)
            break;
    }
    uac_info("TrustList.Read             -> %zu bytes", acc.len);
    UA_Variant cin;
    UA_Variant_setScalar(&cin, &handle, &UA_TYPES[UA_TYPES_UINT32]);
    size_t cN = 0;
    UA_Variant *cV = NULL;
    UA_StatusCode rc = uac_call(c, "TrustList.Close", tl, mClose, 1, &cin, 0, &cN, &cV);
    UA_Array_delete(cV, cN, &UA_TYPES[UA_TYPES_VARIANT]);
    if(r == UA_STATUSCODE_GOOD)
        r = rc;
    if(r == UA_STATUSCODE_GOOD) {
        all.data = acc.data;
        all.length = acc.len;
        r = UA_decodeBinary(&all, out, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL);
        if(r == UA_STATUSCODE_GOOD &&
           (out->trustedCertificatesSize > GDS_MAX_TRUSTLIST_ENTRIES ||
            out->trustedCrlsSize > GDS_MAX_TRUSTLIST_ENTRIES ||
            out->issuerCertificatesSize > GDS_MAX_TRUSTLIST_ENTRIES ||
            out->issuerCrlsSize > GDS_MAX_TRUSTLIST_ENTRIES)) {
            UA_TrustListDataType_clear(out);
            r = UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
        }
    }
cleanup:
    if(outV)
        UA_Array_delete(outV, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    gds_buf_free(&acc);
    UA_NodeId_clear(&mOpen);
    UA_NodeId_clear(&mRead);
    UA_NodeId_clear(&mClose);
    return r;
}
