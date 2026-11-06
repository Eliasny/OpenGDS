/* OpenGDS Auditor GDS profile - trust list helpers (see gds_tl.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include "gds_tl.h"

#include <open62541/client_highlevel.h>
#include <open62541/nodeids_gds.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <string.h>

#include "common/limits.h"
#include "test_ca.h"
#include "common/banned.h"

#define GTL_MAX_READS 4096

UA_NodeId gtl_default(const gds_target *t) {
    return gt_node(t, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST);
}

UA_StatusCode gtl_method(UA_Client *c, UA_NodeId tl, const char *name, UA_NodeId *out) {
    return uac_find_child(c, tl, name, out);
}

static UA_StatusCode callm(UA_Client *c, UA_NodeId tl, const char *name, size_t inN,
                           const UA_Variant *in, size_t minOut, size_t *outN, UA_Variant **out) {
    *outN = 0;
    *out = NULL;
    if(!c)
        return UA_STATUSCODE_BADSESSIONCLOSED;
    UA_NodeId m;
    UA_StatusCode r = gtl_method(c, tl, name, &m);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    r = UA_Client_call(c, tl, m, inN, in, outN, out);
    UA_NodeId_clear(&m);
    if(r == UA_STATUSCODE_GOOD && *outN < minOut)
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    if(r != UA_STATUSCODE_GOOD) {
        gt_free_out(*out, *outN);
        *out = NULL;
        *outN = 0;
    }
    return r;
}

UA_StatusCode gtl_open(UA_Client *c, UA_NodeId tl, UA_Byte mode, bool withMasks, UA_UInt32 masks,
                       UA_UInt32 *handle) {
    *handle = 0;
    UA_Variant in;
    if(withMasks)
        UA_Variant_setScalar(&in, &masks, &UA_TYPES[UA_TYPES_UINT32]);
    else
        UA_Variant_setScalar(&in, &mode, &UA_TYPES[UA_TYPES_BYTE]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r =
        callm(c, tl, withMasks ? "OpenWithMasks" : "Open", 1, &in, 1, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_UInt32 *h = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_UINT32]);
    if(h)
        *handle = *h;
    else
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    gt_free_out(out, outN);
    return r;
}

void gtl_close(UA_Client *c, UA_NodeId tl, UA_UInt32 handle) {
    UA_Variant in;
    UA_Variant_setScalar(&in, &handle, &UA_TYPES[UA_TYPES_UINT32]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    if(callm(c, tl, "Close", 1, &in, 0, &outN, &out) == UA_STATUSCODE_GOOD)
        gt_free_out(out, outN);
}

UA_StatusCode gtl_read_all(UA_Client *c, UA_NodeId tl, UA_UInt32 handle, UA_Int32 chunk,
                           UA_ByteString *file) {
    UA_ByteString_init(file);
    UA_NodeId m;
    UA_StatusCode r = gtl_method(c, tl, "Read", &m);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    gds_buf acc = {0};
    for(size_t reads = 0;; reads++) {
        if(reads == GTL_MAX_READS) {
            r = UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
            break;
        }
        UA_Variant in[2];
        UA_Variant_setScalar(&in[0], &handle, &UA_TYPES[UA_TYPES_UINT32]);
        UA_Variant_setScalar(&in[1], &chunk, &UA_TYPES[UA_TYPES_INT32]);
        size_t outN = 0;
        UA_Variant *out = NULL;
        r = UA_Client_call(c, tl, m, 2, in, &outN, &out);
        if(r != UA_STATUSCODE_GOOD)
            break;
        const UA_ByteString *part = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
        if(!part || part->length > (size_t)chunk) {
            gt_free_out(out, outN);
            r = UA_STATUSCODE_BADUNEXPECTEDERROR;
            break;
        }
        size_t got = part->length;
        gds_status s = got ? gds_buf_append(&acc, part->data, got, GDS_MAX_TRUSTLIST_SIZE) : GDS_OK;
        gt_free_out(out, outN);
        if(s != GDS_OK) {
            r = gds_status_to_ua(s);
            break;
        }
        if(got == 0) /* only an empty ByteString ends the file (OPC 10000-20 §4.2.4) */
            break;
    }
    UA_NodeId_clear(&m);
    if(r == UA_STATUSCODE_GOOD && acc.len > 0) {
        file->data = UA_malloc(acc.len);
        if(!file->data) {
            r = UA_STATUSCODE_BADOUTOFMEMORY;
        } else {
            memcpy(file->data, acc.data, acc.len);
            file->length = acc.len;
        }
    }
    gds_buf_free(&acc);
    return r;
}

UA_StatusCode gtl_decode(const UA_ByteString *file, UA_TrustListDataType *out) {
    UA_TrustListDataType_init(out);
    return UA_decodeBinary(file, out, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL);
}

UA_StatusCode gtl_write(UA_Client *c, UA_NodeId tl, const UA_TrustListDataType *d, bool update,
                        bool *applyRequired) {
    *applyRequired = false;
    UA_ByteString file = UA_BYTESTRING_NULL;
    UA_StatusCode r = UA_encodeBinary(d, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], &file, NULL);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_UInt32 h = 0;
    r = gtl_open(c, tl, GTL_WRITE_ERASE, false, 0, &h);
    if(r != UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(&file);
        return r;
    }
    size_t outN = 0;
    UA_Variant *out = NULL;
    for(size_t pos = 0; pos < file.length && r == UA_STATUSCODE_GOOD; pos += 512) {
        UA_ByteString part = {file.length - pos < 512 ? file.length - pos : 512, file.data + pos};
        UA_Variant in[2];
        UA_Variant_setScalar(&in[0], &h, &UA_TYPES[UA_TYPES_UINT32]);
        UA_Variant_setScalar(&in[1], &part, &UA_TYPES[UA_TYPES_BYTESTRING]);
        r = callm(c, tl, "Write", 2, in, 0, &outN, &out);
        gt_free_out(out, outN);
    }
    UA_ByteString_clear(&file);
    if(r != UA_STATUSCODE_GOOD || !update) {
        gtl_close(c, tl, h);
        return r;
    }
    UA_Variant in;
    UA_Variant_setScalar(&in, &h, &UA_TYPES[UA_TYPES_UINT32]);
    r = callm(c, tl, "CloseAndUpdate", 1, &in, 1, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_Boolean *acr = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(acr)
        *applyRequired = *acr;
    else
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    gt_free_out(out, outN);
    return r;
}

UA_StatusCode gtl_add(UA_Client *c, UA_NodeId tl, const gds_buf *cert, bool trusted) {
    UA_ByteString b = {cert->len, cert->data};
    UA_Boolean tr = trusted;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &b, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&in[1], &tr, &UA_TYPES[UA_TYPES_BOOLEAN]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = callm(c, tl, "AddCertificate", 2, in, 0, &outN, &out);
    gt_free_out(out, outN);
    return r;
}

UA_StatusCode gtl_remove_thumb(UA_Client *c, UA_NodeId tl, const char *thumb, bool trusted) {
    UA_String s = UA_STRING((char *)(uintptr_t)thumb);
    UA_Boolean tr = trusted;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &s, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &tr, &UA_TYPES[UA_TYPES_BOOLEAN]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = callm(c, tl, "RemoveCertificate", 2, in, 0, &outN, &out);
    gt_free_out(out, outN);
    return r;
}

UA_StatusCode gtl_last_update(UA_Client *c, UA_NodeId tl, UA_DateTime *out) {
    *out = 0;
    UA_NodeId v;
    UA_StatusCode r = uac_find_child(c, tl, "LastUpdateTime", &v);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_Variant val;
    UA_Variant_init(&val);
    r = UA_Client_readValueAttribute(c, v, &val);
    if(r == UA_STATUSCODE_GOOD && UA_Variant_hasScalarType(&val, &UA_TYPES[UA_TYPES_DATETIME]))
        *out = *(UA_DateTime *)val.data;
    else if(r == UA_STATUSCODE_GOOD)
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    UA_Variant_clear(&val);
    UA_NodeId_clear(&v);
    return r;
}

bool gtl_has(const UA_ByteString *list, size_t n, const gds_buf *x) {
    UA_ByteString b = {x->len, x->data};
    for(size_t i = 0; i < n; i++)
        if(UA_ByteString_equal(&list[i], &b))
            return true;
    return false;
}

static int add_ext(X509 *cert, X509 *issuer, int nid, const char *value) {
    X509V3_CTX v3;
    X509V3_set_ctx_nodb(&v3);
    X509V3_set_ctx(&v3, issuer, cert, NULL, NULL, 0);
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, &v3, nid, value);
    if(!ex)
        return 0;
    int ok = X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return ok;
}

gds_status gtl_make_cert(X509 *issuer, EVP_PKEY *issuerKey, EVP_PKEY *key, const char *cn,
                         const char *uri, bool isCa, int days, gds_buf *out) {
    memset(out, 0, sizeof(*out));
    X509 *x = X509_new();
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    BIGNUM *bn = BN_new();
    gds_status ret = GDS_ECRYPTO;
    char san[GDS_MAX_APPLICATION_URI + 8];
    if(!x || !serial || !bn || BN_rand(bn, 64, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) != 1 ||
       !BN_to_ASN1_INTEGER(bn, serial) || X509_set_serialNumber(x, serial) != 1 ||
       X509_set_version(x, 2) != 1 || X509_set_pubkey(x, key) != 1 ||
       !X509_gmtime_adj(X509_getm_notBefore(x), -3600) ||
       !X509_gmtime_adj(X509_getm_notAfter(x), (long)days * 86400L))
        goto done;
    X509_NAME *n = X509_get_subject_name(x);
    if(X509_NAME_add_entry_by_txt(n, "O", MBSTRING_UTF8, (const unsigned char *)TESTCA_ORG, -1,
                                  -1, 0) != 1 ||
       X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_UTF8, (const unsigned char *)cn, -1, -1,
                                  0) != 1)
        goto done;
    X509 *iss = issuer ? issuer : x;
    if(X509_set_issuer_name(x, X509_get_subject_name(iss)) != 1)
        goto done;
    if(!add_ext(x, iss, NID_basic_constraints, isCa ? "critical,CA:TRUE" : "critical,CA:FALSE") ||
       !add_ext(x, iss, NID_key_usage,
                isCa ? "critical,keyCertSign,cRLSign,digitalSignature"
                     : "critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment") ||
       !add_ext(x, iss, NID_subject_key_identifier, "hash") ||
       !add_ext(x, iss, NID_authority_key_identifier, "keyid:always"))
        goto done;
    if(!isCa && !add_ext(x, iss, NID_ext_key_usage, "serverAuth,clientAuth"))
        goto done;
    if(uri) {
        if(gds_path(san, sizeof(san), "URI:%s", uri) != GDS_OK ||
           !add_ext(x, iss, NID_subject_alt_name, san))
            goto done;
    }
    if(X509_sign(x, issuerKey ? issuerKey : key, EVP_sha256()) <= 0)
        goto done;
    ret = x509_cert_to_der(x, out);
done:
    if(ret != GDS_OK)
        x509_drain_errors("gtl_make_cert");
    BN_free(bn);
    ASN1_INTEGER_free(serial);
    X509_free(x);
    return ret;
}
