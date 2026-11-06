/* OpenGDS Auditor server profile - the push-managed Server under test.
 * SPDX-License-Identifier: MPL-2.0 */
#include "srv_target.h"

#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/log_stdout.h>
#include <openssl/crypto.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/ua_args.h"
#include "common/banned.h"

#define SP "http://opcfoundation.org/UA/SecurityPolicy#"

static UA_NodeId ns0(UA_UInt32 id) {
    return UA_NODEID_NUMERIC(0, id);
}

static UA_NodeId tl_node(void) {
    return ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST);
}

static void free_out(UA_Variant *out, size_t outN) {
    if(out)
        UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
}

UA_Client *st_new_client(const srv_target *t, bool withPinned, const char *policyUri,
                         UA_MessageSecurityMode mode) {
    gds_buf trust[3];
    size_t n = 0;
    trust[n++] = t->caDer;
    if(withPinned && t->pinned.len)
        trust[n++] = t->pinned;
    return uac_new_secure_mode(&t->cert, &t->key, trust, n, &t->caCrl, 1, t->appUri,
                               policyUri ? policyUri : POLICY_RSAPSS, mode);
}

static UA_StatusCode connect_admin(const srv_target *t, UA_Client *c) {
    return t->user ? UA_Client_connectUsername(c, t->url, t->user, t->password)
                   : UA_Client_connect(c, t->url);
}

void st_client_free(UA_Client *c) {
    if(!c)
        return;
    UA_Client_disconnect(c);
    UA_Client_delete(c);
}

UA_StatusCode st_admin(srv_target *t) {
    if(t->client) {
        UA_SecureChannelState cs;
        UA_SessionState ss;
        UA_StatusCode st;
        UA_Client_getState(t->client, &cs, &ss, &st);
        if(ss == UA_SESSIONSTATE_ACTIVATED)
            return UA_STATUSCODE_GOOD;
        st_close(t);
    }
    t->client = st_new_client(t, true, NULL, UA_MESSAGESECURITYMODE_SIGNANDENCRYPT);
    if(!t->client)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode r = connect_admin(t, t->client);
    if(r != UA_STATUSCODE_GOOD)
        st_close(t);
    return r;
}

UA_StatusCode st_admin_fresh(const srv_target *t, bool withPinned, UA_Client **out) {
    *out = st_new_client(t, withPinned, NULL, UA_MESSAGESECURITYMODE_SIGNANDENCRYPT);
    if(!*out)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode r = connect_admin(t, *out);
    if(r != UA_STATUSCODE_GOOD) {
        st_client_free(*out);
        *out = NULL;
    }
    return r;
}

void st_close(srv_target *t) {
    st_client_free(t->client);
    t->client = NULL;
}

void st_clear(srv_target *t) {
    st_close(t);
    gds_buf_free(&t->cert);
    gds_buf_free_secret(&t->key);
    gds_buf_free(&t->pinned);
    gds_buf_free(&t->caDer);
    gds_buf_free(&t->caCrl);
    gds_buf_free(&t->peerCert);
    gds_buf_free_secret(&t->peerKey);
    gds_buf_free(&t->snapCert);
    gds_buf_free(&t->tGood);
    UA_TrustListDataType_clear(&t->snap);
    UA_TrustListDataType_clear(&t->pushed);
    UA_TrustListDataType_clear(&t->queued);
    UA_NodeId_clear(&t->certType);
    testca_free(&t->ca);
    OPENSSL_cleanse(t->password, sizeof(t->password));
}

UA_StatusCode st_endpoints(const srv_target *t, UA_EndpointDescription **eps, size_t *n) {
    *eps = NULL;
    *n = 0;
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
    UA_StatusCode r = UA_Client_getEndpoints(c, t->url, n, eps);
    UA_Client_delete(c);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    /* hostile input: bound what the tests look at */
    if(*n > 64)
        r = UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
    for(size_t i = 0; r == UA_STATUSCODE_GOOD && i < *n; i++)
        if((*eps)[i].serverCertificate.length > GDS_MAX_CERT_SIZE)
            r = UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
    if(r != UA_STATUSCODE_GOOD) {
        UA_Array_delete(*eps, *n, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
        *eps = NULL;
        *n = 0;
    }
    return r;
}

UA_StatusCode st_presented(const srv_target *t, gds_buf *out) {
    out->data = NULL;
    out->len = 0;
    UA_EndpointDescription *eps = NULL;
    size_t n = 0;
    UA_StatusCode r = st_endpoints(t, &eps, &n);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    /* The endpoint the Auditor's own sessions use, else the first secure one */
    const UA_String pss = UA_STRING(POLICY_RSAPSS);
    const UA_EndpointDescription *pick = NULL;
    for(size_t i = 0; i < n; i++) {
        if(eps[i].securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT ||
           eps[i].serverCertificate.length == 0)
            continue;
        if(!pick || UA_String_equal(&eps[i].securityPolicyUri, &pss))
            pick = &eps[i];
        if(UA_String_equal(&eps[i].securityPolicyUri, &pss))
            break;
    }
    if(!pick)
        r = UA_STATUSCODE_BADNOTFOUND;
    else
        r = gds_status_to_ua(
            gds_buf_dup(pick->serverCertificate.data, pick->serverCertificate.length, out));
    UA_Array_delete(eps, n, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    return r;
}

static UA_StatusCode call(UA_Client *c, UA_NodeId obj, UA_UInt32 method, size_t inN,
                          const UA_Variant *in, size_t minOut, size_t *outN, UA_Variant **out) {
    *outN = 0;
    *out = NULL;
    UA_StatusCode r = UA_Client_call(c, obj, ns0(method), inN, in, outN, out);
    if(r == UA_STATUSCODE_GOOD && *outN < minOut)
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    if(r != UA_STATUSCODE_GOOD) {
        free_out(*out, *outN);
        *out = NULL;
        *outN = 0;
    }
    return r;
}

/* Close a handle on the error path; the status is not the test's result. */
static void close_handle(UA_Client *c, UA_UInt32 h) {
    UA_Variant in;
    UA_Variant_setScalar(&in, &h, &UA_TYPES[UA_TYPES_UINT32]);
    size_t n = 0;
    UA_Variant *o = NULL;
    if(call(c, tl_node(), UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_CLOSE,
            1, &in, 0, &n, &o) == UA_STATUSCODE_GOOD)
        free_out(o, n);
}

UA_StatusCode st_write_trustlist(UA_Client *c, const UA_TrustListDataType *tl, size_t chunk,
                                 bool *applyRequired, ga_ctx *ctx) {
    *applyRequired = false;
    UA_ByteString file = UA_BYTESTRING_NULL;
    UA_StatusCode r = UA_encodeBinary(tl, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], &file, NULL);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_Byte mode = ST_OPEN_WRITE_ERASE;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &mode, &UA_TYPES[UA_TYPES_BYTE]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    r = call(c, tl_node(), UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_OPEN,
             1, in, 1, &outN, &out);
    ga_note(ctx, "Open(Write|EraseExisting) -> %s", UA_StatusCode_name(r));
    if(r != UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(&file);
        return r;
    }
    const UA_UInt32 *hp = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_UINT32]);
    UA_UInt32 h = hp ? *hp : 0;
    free_out(out, outN);
    if(!hp) {
        UA_ByteString_clear(&file);
        return UA_STATUSCODE_BADUNEXPECTEDERROR;
    }
    size_t chunks = 0;
    for(size_t pos = 0; pos < file.length; pos += chunk) {
        UA_ByteString part = {file.length - pos < chunk ? file.length - pos : chunk,
                              file.data + pos};
        UA_Variant_setScalar(&in[0], &h, &UA_TYPES[UA_TYPES_UINT32]);
        UA_Variant_setScalar(&in[1], &part, &UA_TYPES[UA_TYPES_BYTESTRING]);
        r = call(c, tl_node(), UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_WRITE,
                 2, in, 0, &outN, &out);
        if(r != UA_STATUSCODE_GOOD)
            break;
        free_out(out, outN);
        chunks++;
    }
    size_t total = file.length;
    UA_ByteString_clear(&file);
    if(r != UA_STATUSCODE_GOOD) {
        ga_note(ctx, "Write chunk %zu -> %s", chunks + 1, UA_StatusCode_name(r));
        close_handle(c, h);
        return r;
    }
    UA_Variant_setScalar(&in[0], &h, &UA_TYPES[UA_TYPES_UINT32]);
    r = call(c, tl_node(),
             UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_CLOSEANDUPDATE,
             1, in, 1, &outN, &out);
    ga_note(ctx, "Write %zu bytes in %zu chunk(s); CloseAndUpdate -> %s", total, chunks,
            UA_StatusCode_name(r));
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_Boolean *acr = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(acr)
        *applyRequired = *acr;
    else
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    free_out(out, outN);
    return r;
}

static bool lists_in_bounds(const UA_TrustListDataType *l) {
    return l->trustedCertificatesSize <= GDS_MAX_TRUSTLIST_ENTRIES &&
           l->trustedCrlsSize <= GDS_MAX_TRUSTLIST_ENTRIES &&
           l->issuerCertificatesSize <= GDS_MAX_TRUSTLIST_ENTRIES &&
           l->issuerCrlsSize <= GDS_MAX_TRUSTLIST_ENTRIES;
}

UA_StatusCode st_read_trustlist(UA_Client *c, UA_UInt32 masks, UA_TrustListDataType *out) {
    UA_TrustListDataType_init(out);
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &masks, &UA_TYPES[UA_TYPES_UINT32]);
    size_t outN = 0;
    UA_Variant *o = NULL;
    UA_StatusCode r = call(
        c, tl_node(), UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_OPENWITHMASKS,
        1, in, 1, &outN, &o);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_UInt32 *hp = uac_out_scalar(o, outN, 0, &UA_TYPES[UA_TYPES_UINT32]);
    UA_UInt32 h = hp ? *hp : 0;
    free_out(o, outN);
    if(!hp)
        return UA_STATUSCODE_BADUNEXPECTEDERROR;
    gds_buf acc = {0};
    for(;;) {
        UA_Int32 len = 16384;
        UA_Variant_setScalar(&in[0], &h, &UA_TYPES[UA_TYPES_UINT32]);
        UA_Variant_setScalar(&in[1], &len, &UA_TYPES[UA_TYPES_INT32]);
        r = call(c, tl_node(), UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_READ,
                 2, in, 1, &outN, &o);
        if(r != UA_STATUSCODE_GOOD)
            break;
        const UA_ByteString *chunk = uac_out_scalar(o, outN, 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
        if(!chunk || chunk->length > (size_t)len) {
            free_out(o, outN);
            r = UA_STATUSCODE_BADUNEXPECTEDERROR;
            break;
        }
        size_t got = chunk->length;
        gds_status s = got ? gds_buf_append(&acc, chunk->data, got, GDS_MAX_TRUSTLIST_SIZE) : GDS_OK;
        free_out(o, outN);
        if(s != GDS_OK) {
            r = gds_status_to_ua(s);
            break;
        }
        if(got == 0) /* §7.8.2.1: read until a Read returns no bytes */
            break;
    }
    UA_Variant_setScalar(&in[0], &h, &UA_TYPES[UA_TYPES_UINT32]);
    UA_StatusCode rc = call(c, tl_node(),
                            UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_CLOSE,
                            1, in, 0, &outN, &o);
    if(rc == UA_STATUSCODE_GOOD)
        free_out(o, outN);
    if(r == UA_STATUSCODE_GOOD)
        r = rc;
    if(r == UA_STATUSCODE_GOOD) {
        UA_ByteString all = {acc.len, acc.data};
        r = UA_decodeBinary(&all, out, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL);
        if(r == UA_STATUSCODE_GOOD && !lists_in_bounds(out)) {
            UA_TrustListDataType_clear(out);
            r = UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
        }
    }
    gds_buf_free(&acc);
    return r;
}

UA_StatusCode st_apply(UA_Client *c) {
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = call(c, ns0(UA_NS0ID_SERVERCONFIGURATION),
                           UA_NS0ID_SERVERCONFIGURATION_APPLYCHANGES, 0, NULL, 0, &outN, &out);
    if(r == UA_STATUSCODE_GOOD)
        free_out(out, outN);
    return r;
}

UA_StatusCode st_csr(const srv_target *t, UA_Client *c, bool regen, const UA_ByteString *nonce,
                     gds_buf *csr) {
    csr->data = NULL;
    csr->len = 0;
    UA_NodeId group = ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_NodeId type = t->certType;
    UA_String subject = UA_STRING_NULL;
    UA_Boolean rg = regen;
    UA_ByteString n = nonce ? *nonce : UA_BYTESTRING_NULL;
    UA_Variant in[5];
    UA_Variant_setScalar(&in[0], &group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &type, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &subject, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[3], &rg, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Variant_setScalar(&in[4], &n, &UA_TYPES[UA_TYPES_BYTESTRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = call(c, ns0(UA_NS0ID_SERVERCONFIGURATION),
                           UA_NS0ID_SERVERCONFIGURATION_CREATESIGNINGREQUEST, 5, in, 1, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_ByteString *b = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(!b || b->length == 0 || b->length > GDS_MAX_CSR_SIZE)
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    else
        r = gds_status_to_ua(gds_buf_dup(b->data, b->length, csr));
    free_out(out, outN);
    return r;
}

UA_StatusCode st_update_cert(const srv_target *t, UA_Client *c, const gds_buf *cert,
                             const gds_buf *issuers, size_t issuersN, bool *applyRequired) {
    *applyRequired = false;
    UA_ByteString iss[GDS_MAX_CHAIN_LEN];
    if(issuersN > GDS_MAX_CHAIN_LEN)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    for(size_t i = 0; i < issuersN; i++) {
        iss[i].data = issuers[i].data;
        iss[i].length = issuers[i].len;
    }
    UA_NodeId group = ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_NodeId type = t->certType;
    UA_ByteString cb = {cert->len, cert->data};
    UA_String fmt = UA_STRING_NULL;
    UA_ByteString pk = UA_BYTESTRING_NULL;
    UA_Variant in[6];
    UA_Variant_setScalar(&in[0], &group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &type, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &cb, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setArray(&in[3], issuersN ? iss : NULL, issuersN, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(issuersN == 0)
        in[3].data = UA_EMPTY_ARRAY_SENTINEL;
    UA_Variant_setScalar(&in[4], &fmt, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[5], &pk, &UA_TYPES[UA_TYPES_BYTESTRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = call(c, ns0(UA_NS0ID_SERVERCONFIGURATION),
                           UA_NS0ID_SERVERCONFIGURATION_UPDATECERTIFICATE, 6, in, 1, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_Boolean *acr = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(acr)
        *applyRequired = *acr;
    else
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    free_out(out, outN);
    return r;
}

void st_supports_transactions(UA_Client *c, bool *present, bool *value) {
    *present = *value = false;
    UA_Variant v;
    UA_Variant_init(&v);
    if(UA_Client_readValueAttribute(c, ns0(UA_NS0ID_SERVERCONFIGURATION_SUPPORTSTRANSACTIONS),
                                    &v) == UA_STATUSCODE_GOOD &&
       UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_BOOLEAN])) {
        *present = true;
        *value = *(UA_Boolean *)v.data;
    }
    UA_Variant_clear(&v);
}

/* Every entry of a is in b (byte equality) and the sizes match. */
static bool set_equal(const UA_ByteString *a, size_t na, const UA_ByteString *b, size_t nb) {
    if(na != nb)
        return false;
    for(size_t i = 0; i < na; i++) {
        bool found = false;
        for(size_t j = 0; j < nb && !found; j++)
            found = UA_ByteString_equal(&a[i], &b[j]);
        if(!found)
            return false;
    }
    return true;
}

bool st_lists_equal(const UA_TrustListDataType *a, const UA_TrustListDataType *b, char *why,
                    size_t whyLen) {
    const char *diff = NULL;
    if(!set_equal(a->trustedCertificates, a->trustedCertificatesSize, b->trustedCertificates,
                  b->trustedCertificatesSize))
        diff = "TrustedCertificates";
    else if(!set_equal(a->trustedCrls, a->trustedCrlsSize, b->trustedCrls, b->trustedCrlsSize))
        diff = "TrustedCrls";
    else if(!set_equal(a->issuerCertificates, a->issuerCertificatesSize, b->issuerCertificates,
                       b->issuerCertificatesSize))
        diff = "IssuerCertificates";
    else if(!set_equal(a->issuerCrls, a->issuerCrlsSize, b->issuerCrls, b->issuerCrlsSize))
        diff = "IssuerCrls";
    if(!diff)
        return true;
    if(gds_path(why, whyLen, "%s differ (%zu/%zu/%zu/%zu vs %zu/%zu/%zu/%zu entries)", diff,
                a->trustedCertificatesSize, a->trustedCrlsSize, a->issuerCertificatesSize,
                a->issuerCrlsSize, b->trustedCertificatesSize, b->trustedCrlsSize,
                b->issuerCertificatesSize, b->issuerCrlsSize) != GDS_OK)
        why[0] = '\0';
    return false;
}

static bool contains(const UA_ByteString *l, size_t n, const gds_buf *x) {
    UA_ByteString b = {x->len, x->data};
    for(size_t i = 0; i < n; i++)
        if(UA_ByteString_equal(&l[i], &b))
            return true;
    return false;
}

static UA_StatusCode append(UA_ByteString **l, size_t *n, const gds_buf *x) {
    if(!x || !x->len || contains(*l, *n, x))
        return UA_STATUSCODE_GOOD;
    UA_ByteString b = {x->len, x->data};
    return UA_Array_appendCopy((void **)l, n, &b, &UA_TYPES[UA_TYPES_BYTESTRING]);
}

UA_StatusCode st_list_copy_add(const UA_TrustListDataType *src, const gds_buf *trustedCert,
                               const gds_buf *trustedCrl, UA_TrustListDataType *dst) {
    UA_StatusCode r = UA_TrustListDataType_copy(src, dst);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    dst->specifiedLists = ST_MASK_ALL;
    r = append(&dst->trustedCertificates, &dst->trustedCertificatesSize, trustedCert);
    if(r == UA_STATUSCODE_GOOD)
        r = append(&dst->trustedCrls, &dst->trustedCrlsSize, trustedCrl);
    if(r != UA_STATUSCODE_GOOD)
        UA_TrustListDataType_clear(dst);
    return r;
}

UA_StatusCode st_snapshot(srv_target *t, ga_ctx *ctx) {
    if(t->snapTaken)
        return UA_STATUSCODE_GOOD;
    UA_StatusCode r = st_admin(t);
    if(r == UA_STATUSCODE_GOOD)
        r = st_read_trustlist(t->client, ST_MASK_ALL, &t->snap);
    if(r == UA_STATUSCODE_GOOD)
        r = st_presented(t, &t->snapCert);
    if(r != UA_STATUSCODE_GOOD) {
        UA_TrustListDataType_clear(&t->snap);
        ga_note(ctx, "snapshot failed: %s", UA_StatusCode_name(r));
        return r;
    }
    t->snapTaken = true;
    ga_note(ctx, "snapshot: %zu trusted, %zu CRL, %zu issuer, %zu issuer CRL",
            t->snap.trustedCertificatesSize, t->snap.trustedCrlsSize,
            t->snap.issuerCertificatesSize, t->snap.issuerCrlsSize);
    return UA_STATUSCODE_GOOD;
}

static const struct {
    const char *policy;
    UA_UInt32 type;
} policyTypes[] = {
    /* 12 §7.8.4.8 */
    {SP "Basic128Rsa15", UA_NS0ID_RSAMINAPPLICATIONCERTIFICATETYPE},
    {SP "Basic256", UA_NS0ID_RSAMINAPPLICATIONCERTIFICATETYPE},
    /* 12 §7.8.4.9, and the RSA policies of OPC 10000-7 built on it */
    {SP "Basic256Sha256", UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE},
    {SP "Aes128_Sha256_RsaOaep", UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE},
    {SP "Aes256_Sha256_RsaPss", UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE},
    /* 12 §7.8.4.11 - §7.8.4.16 */
    {SP "ECC_nistP256", UA_NS0ID_ECCNISTP256APPLICATIONCERTIFICATETYPE},
    {SP "ECC_nistP384", UA_NS0ID_ECCNISTP384APPLICATIONCERTIFICATETYPE},
    {SP "ECC_brainpoolP256r1", UA_NS0ID_ECCBRAINPOOLP256R1APPLICATIONCERTIFICATETYPE},
    {SP "ECC_brainpoolP384r1", UA_NS0ID_ECCBRAINPOOLP384R1APPLICATIONCERTIFICATETYPE},
    {SP "ECC_curve25519", UA_NS0ID_ECCCURVE25519APPLICATIONCERTIFICATETYPE},
    {SP "ECC_curve448", UA_NS0ID_ECCCURVE448APPLICATIONCERTIFICATETYPE},
};

UA_NodeId st_policy_cert_type(const UA_String *policyUri) {
    for(size_t i = 0; i < GDS_ARRAY_SIZE(policyTypes); i++) {
        UA_String p = UA_STRING((char *)(uintptr_t)policyTypes[i].policy);
        if(UA_String_equal(&p, policyUri))
            return ns0(policyTypes[i].type);
    }
    return UA_NODEID_NULL;
}

const char *st_short_policy(const UA_String *policyUri) {
    static char buf[96];
    size_t pre = strlen(SP);
    const UA_String *u = policyUri;
    size_t off = (u->length > pre && memcmp(u->data, SP, pre) == 0) ? pre : 0;
    size_t n = u->length - off;
    if(n >= sizeof(buf))
        n = sizeof(buf) - 1;
    memcpy(buf, u->data + off, n);
    buf[n] = '\0';
    return buf;
}

UA_StatusCode st_learn(srv_target *t, ga_ctx *ctx) {
    if(t->targetUri[0] && !UA_NodeId_isNull(&t->certType))
        return UA_STATUSCODE_GOOD;
    UA_EndpointDescription *eps = NULL;
    size_t n = 0;
    UA_StatusCode r = st_endpoints(t, &eps, &n);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_String *uri = n ? &eps[0].server.applicationUri : NULL;
    if(!uri || uri->length == 0 || uri->length > GDS_MAX_APPLICATION_URI)
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    else {
        memcpy(t->targetUri, uri->data, uri->length);
        t->targetUri[uri->length] = '\0';
    }
    UA_Array_delete(eps, n, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    if((r = st_admin(t)) != UA_STATUSCODE_GOOD)
        return r;
    UA_Variant v;
    UA_Variant_init(&v);
    r = UA_Client_readValueAttribute(
        t->client, ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_CERTIFICATETYPES),
        &v);
    const void *arr = NULL;
    size_t an = 0;
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_array(&v, &UA_TYPES[UA_TYPES_NODEID], GDS_MAX_ARRAY_FIELD, &arr, &an);
    if(r == UA_STATUSCODE_GOOD && an == 0)
        r = UA_STATUSCODE_BADNOTFOUND;
    if(r == UA_STATUSCODE_GOOD) {
        const UA_NodeId *types = arr;
        const UA_NodeId rsa = ns0(UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);
        const UA_NodeId *pick = &types[0];
        for(size_t i = 0; i < an; i++)
            if(UA_NodeId_equal(&types[i], &rsa))
                pick = &types[i];
        r = UA_NodeId_copy(pick, &t->certType);
    }
    UA_Variant_clear(&v);
    if(r == UA_STATUSCODE_GOOD)
        ga_note(ctx, "target %s, certificate type ns=%u;i=%u", t->targetUri,
                (unsigned)t->certType.namespaceIndex,
                t->certType.identifierType == UA_NODEIDTYPE_NUMERIC
                    ? (unsigned)t->certType.identifier.numeric : 0u);
    return r;
}

GDS_FORMAT(3, 4)
static void say(char *out, size_t outLen, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    /* truncation ok: evidence text. NOLINTNEXTLINE(clang-analyzer-valist.Uninitialized) */
    vsnprintf(out, outLen, fmt, ap);
    va_end(ap);
}

UA_StatusCode st_restore(srv_target *t, char *why, size_t whyLen) {
    why[0] = '\0';
    /* A new session: any transaction left open by a test is discarded with
     * the old one (12 §7.10.2) */
    st_close(t);
    UA_StatusCode r = st_admin(t);
    if(r != UA_STATUSCODE_GOOD) {
        say(why, whyLen, "cannot connect as SecurityAdmin: %s", UA_StatusCode_name(r));
        return r;
    }
    gds_buf now = {0};
    UA_StatusCode rc = UA_STATUSCODE_GOOD;
    bool certChanged = st_presented(t, &now) == UA_STATUSCODE_GOOD &&
                       (now.len != t->snapCert.len || memcmp(now.data, t->snapCert.data, now.len) != 0);
    gds_buf_free(&now);
    bool acr = false;
    if(certChanged && !UA_NodeId_isNull(&t->certType))
        rc = st_update_cert(t, t->client, &t->snapCert, NULL, 0, &acr);
    UA_TrustListDataType l;
    UA_TrustListDataType_init(&l);
    r = UA_TrustListDataType_copy(&t->snap, &l);
    l.specifiedLists = ST_MASK_ALL;
    bool acr2 = false;
    if(r == UA_STATUSCODE_GOOD)
        r = st_write_trustlist(t->client, &l, 16384, &acr2, NULL);
    UA_TrustListDataType_clear(&l);
    if(r == UA_STATUSCODE_GOOD && (acr || acr2 || certChanged))
        r = st_apply(t->client);
    st_close(t);
    if(r != UA_STATUSCODE_GOOD) {
        say(why, whyLen, "trust list not restored: %s", UA_StatusCode_name(r));
        return r;
    }
    if(rc != UA_STATUSCODE_GOOD) {
        char tp[X509_THUMBPRINT_LEN] = "?";
        say(why, whyLen,
                       "trust list restored, but UpdateCertificate with the original certificate -> %s: "
                       "the target keeps a TEST certificate; reinstall its own (thumbprint %s)",
                       UA_StatusCode_name(rc),
                       x509_thumbprint(&t->snapCert, tp) == GDS_OK ? tp : "?");
        return rc;
    }
    t->restored = true;
    return UA_STATUSCODE_GOOD;
}
