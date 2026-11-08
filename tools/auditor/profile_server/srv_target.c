/* OpenGDS Auditor server profile - the push-managed Server under test.
 * SPDX-License-Identifier: MPL-2.0 */
#include "srv_target.h"

#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/log_stdout.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <stdarg.h>
#include <stdint.h>
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

UA_Client *st_new_client(const srv_target *t, st_role role, bool withPinned,
                         const char *policyUri, UA_MessageSecurityMode mode) {
    gds_buf trust[2 + ST_MAX_TARGET_TRUST], crls[1 + ST_MAX_TARGET_TRUST];
    size_t n = 0, nc = 0;
    trust[n++] = t->caDer;
    crls[nc++] = t->caCrl;
    if(withPinned) { /* the target's own chain (a CA-issued target certificate) */
        if(t->pinned.len)
            trust[n++] = t->pinned;
        for(size_t i = 0; i < t->targetTrustN; i++)
            trust[n++] = t->targetTrust[i];
        for(size_t i = 0; i < t->targetCrlN; i++)
            crls[nc++] = t->targetCrl[i];
    }
    bool adminApp = role == ST_ADMIN && !t->adminUser && t->adminCert.len;
    const gds_buf *c = adminApp ? &t->adminCert : &t->cert;
    const gds_buf *k = adminApp ? &t->adminKey : &t->key;
    return uac_new_secure_mode(c, k, trust, n, crls, nc, t->appUri,
                               policyUri ? policyUri : POLICY_RSAPSS, mode);
}

UA_StatusCode st_connect(const srv_target *t, st_role role, UA_Client *c) {
    if(role == ST_ADMIN && t->adminUser)
        return UA_Client_connectUsername(c, t->url, t->adminUser, t->adminPassword);
    if(role == ST_USER) {
        if(!t->userName)
            return UA_STATUSCODE_BADIDENTITYTOKENINVALID;
        return UA_Client_connectUsername(c, t->url, t->userName, t->userPassword);
    }
    return UA_Client_connect(c, t->url); /* anonymous token */
}

UA_StatusCode st_open(const srv_target *t, st_role role, const char *policyUri,
                      UA_MessageSecurityMode mode, UA_Client **out) {
    *out = st_new_client(t, role, true, policyUri, mode);
    if(!*out)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode r = st_connect(t, role, *out);
    if(r != UA_STATUSCODE_GOOD) {
        st_client_free(*out);
        *out = NULL;
    }
    return r;
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
    t->client = st_new_client(t, ST_ADMIN, true, NULL, UA_MESSAGESECURITYMODE_SIGNANDENCRYPT);
    if(!t->client)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode r = st_connect(t, ST_ADMIN, t->client);
    if(r != UA_STATUSCODE_GOOD)
        st_close(t);
    return r;
}

UA_StatusCode st_admin_fresh(const srv_target *t, bool withPinned, UA_Client **out) {
    *out = st_new_client(t, ST_ADMIN, withPinned, NULL, UA_MESSAGESECURITYMODE_SIGNANDENCRYPT);
    if(!*out)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode r = st_connect(t, ST_ADMIN, *out);
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
    for(size_t i = 0; i < t->targetTrustN; i++)
        gds_buf_free(&t->targetTrust[i]);
    for(size_t i = 0; i < t->targetCrlN; i++)
        gds_buf_free(&t->targetCrl[i]);
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
    testca_free(&t->caInt);
    gds_buf_free(&t->caIntDer);
    gds_buf_free(&t->caIntCrl);
    gds_buf_free(&t->peerInt);
    gds_buf_free(&t->adminCert);
    gds_buf_free_secret(&t->adminKey);
    OPENSSL_cleanse(t->adminPassword, sizeof(t->adminPassword));
    OPENSSL_cleanse(t->userPassword, sizeof(t->userPassword));
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
    if(!c)
        return UA_STATUSCODE_BADSESSIONCLOSED;
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
    return st_write_trustlist_ex(c, tl, chunk, true, applyRequired, ctx);
}

/* ApplyChangesRequired of every UpdateCertificate and CloseAndUpdate (SRV-TXN-01) */
static st_acr_log acrLog;

const st_acr_log *st_acr(void) {
    return &acrLog;
}

static void acr_seen(bool v, const char *what) {
    acrLog.calls++;
    if(!v) {
        acrLog.falses++;
        acrLog.firstFalse = acrLog.firstFalse ? acrLog.firstFalse : what;
    }
}

UA_StatusCode st_tl_open_write(UA_Client *c, const UA_TrustListDataType *tl, size_t chunk,
                               UA_UInt32 *handle, ga_ctx *ctx) {
    *handle = 0;
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
    ga_note(ctx, "Write %zu bytes in %zu chunk(s)", total, chunks);
    *handle = h;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode st_tl_finish(UA_Client *c, UA_UInt32 h, bool update, bool *applyRequired,
                           ga_ctx *ctx) {
    *applyRequired = false;
    UA_Variant in;
    UA_Variant_setScalar(&in, &h, &UA_TYPES[UA_TYPES_UINT32]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    if(!update) { /* Close discards the written data (12 §7.8.2.1) */
        UA_StatusCode r = call(c, tl_node(),
                               UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_CLOSE,
                               1, &in, 0, &outN, &out);
        ga_note(ctx, "Close -> %s", UA_StatusCode_name(r));
        if(r == UA_STATUSCODE_GOOD)
            free_out(out, outN);
        return r;
    }
    UA_StatusCode r = call(c, tl_node(),
                           UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_CLOSEANDUPDATE,
                           1, &in, 1, &outN, &out);
    ga_note(ctx, "CloseAndUpdate -> %s", UA_StatusCode_name(r));
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_Boolean *acr = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(acr) {
        *applyRequired = *acr;
        acr_seen(*acr, "CloseAndUpdate");
    } else
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    free_out(out, outN);
    return r;
}

UA_StatusCode st_write_trustlist_ex(UA_Client *c, const UA_TrustListDataType *tl, size_t chunk,
                                    bool update, bool *applyRequired, ga_ctx *ctx) {
    *applyRequired = false;
    UA_UInt32 h = 0;
    UA_StatusCode r = st_tl_open_write(c, tl, chunk, &h, ctx);
    return r == UA_STATUSCODE_GOOD ? st_tl_finish(c, h, update, applyRequired, ctx) : r;
}

static bool lists_in_bounds(const UA_TrustListDataType *l) {
    return l->trustedCertificatesSize <= GDS_MAX_TRUSTLIST_ENTRIES &&
           l->trustedCrlsSize <= GDS_MAX_TRUSTLIST_ENTRIES &&
           l->issuerCertificatesSize <= GDS_MAX_TRUSTLIST_ENTRIES &&
           l->issuerCrlsSize <= GDS_MAX_TRUSTLIST_ENTRIES;
}

UA_StatusCode st_read_trustlist(UA_Client *c, UA_UInt32 masks, UA_TrustListDataType *out) {
    UA_TrustListDataType_init(out);
    gds_buf acc = {0};
    UA_StatusCode r = st_read_trustlist_raw(c, masks, &acc);
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

UA_StatusCode st_read_trustlist_raw(UA_Client *c, UA_UInt32 masks, gds_buf *raw) {
    raw->data = NULL;
    raw->len = 0;
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
    if(r == UA_STATUSCODE_GOOD)
        *raw = acc;
    else
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
    return st_csr_for(c, ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP),
                      t->certType, regen, nonce, csr);
}

UA_StatusCode st_csr_for(UA_Client *c, UA_NodeId group, UA_NodeId type, bool regen,
                         const UA_ByteString *nonce, gds_buf *csr) {
    csr->data = NULL;
    csr->len = 0;
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
    return st_update_cert_key(t, c, cert, issuers, issuersN, NULL, NULL, applyRequired);
}

static UA_StatusCode update_call(UA_Client *c, UA_NodeId type, const gds_buf *cert,
                                 const gds_buf *issuers, size_t issuersN, const char *keyFormat,
                                 const gds_buf *key, bool *applyRequired) {
    *applyRequired = false;
    UA_ByteString iss[GDS_MAX_CHAIN_LEN];
    if(issuersN > GDS_MAX_CHAIN_LEN)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    for(size_t i = 0; i < issuersN; i++) {
        iss[i].data = issuers[i].data;
        iss[i].length = issuers[i].len;
    }
    UA_NodeId group = ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_ByteString cb = {cert->len, cert->data};
    UA_String fmt = keyFormat ? UA_STRING((char *)(uintptr_t)keyFormat) : UA_STRING_NULL;
    UA_ByteString pk = UA_BYTESTRING_NULL;
    if(key) {
        pk.data = key->data;
        pk.length = key->len;
    }
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
    if(acr) {
        *applyRequired = *acr;
        acr_seen(*acr, "UpdateCertificate");
    } else
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    free_out(out, outN);
    return r;
}

UA_StatusCode st_update_cert_key(const srv_target *t, UA_Client *c, const gds_buf *cert,
                                 const gds_buf *issuers, size_t issuersN, const char *keyFormat,
                                 const gds_buf *key, bool *applyRequired) {
    return update_call(c, t->certType, cert, issuers, issuersN, keyFormat, key, applyRequired);
}

UA_StatusCode st_update_cert_as(UA_Client *c, UA_NodeId type, const gds_buf *cert,
                                bool *applyRequired) {
    return update_call(c, type, cert, NULL, 0, NULL, NULL, applyRequired);
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
    bool acr = false, keptKey = certChanged && t->keyReplaced;
    if(certChanged && !keptKey && !UA_NodeId_isNull(&t->certType))
        rc = st_update_cert(t, t->client, &t->snapCert, NULL, 0, &acr);
    certChanged = certChanged && !keptKey;
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
    if(keptKey)
        say(why, whyLen, "trust list restored; the certificate stays the TEST one of SRV-UPD-09, "
                         "which replaced the private key (selected by name): reinstall the "
                         "target's own certificate and key");
    t->restored = true;
    return UA_STATUSCODE_GOOD;
}

static bool cert_body(X509 *x, const testca_t *issuer, EVP_PKEY *key, const char *cn,
                      long fromSec, long toSec, bool isCa, size_t pad) {
    static unsigned char padding[ST_MAX_CERT_PAD];
    memset(padding, 'A', sizeof(padding));
    X509_NAME *nm = X509_NAME_new();
    BIGNUM *sn = BN_new();
    bool ok = nm && sn && pad <= sizeof(padding) && X509_set_version(x, 2) == 1 &&
              BN_rand(sn, 62, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) == 1 &&
              BN_to_ASN1_INTEGER(sn, X509_get_serialNumber(x)) &&
              X509_NAME_add_entry_by_txt(nm, "O", MBSTRING_UTF8,
                                         (const unsigned char *)TESTCA_ORG, -1, -1, 0) == 1 &&
              X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_UTF8, (const unsigned char *)cn, -1,
                                         -1, 0) == 1 &&
              X509_set_subject_name(x, nm) == 1 &&
              X509_set_issuer_name(x, issuer ? X509_get_subject_name(issuer->cert) : nm) == 1 &&
              X509_gmtime_adj(X509_getm_notBefore(x), fromSec) &&
              X509_gmtime_adj(X509_getm_notAfter(x), toSec) && X509_set_pubkey(x, key) == 1;
    if(ok && isCa) {
        BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();
        if(bc)
            bc->ca = 1;
        ok = bc && X509_add1_ext_i2d(x, NID_basic_constraints, bc, 1, 0) == 1;
        BASIC_CONSTRAINTS_free(bc);
    }
    if(ok) { /* key identifiers, so CRLs (AKI keyid:always) and chains match */
        X509V3_CTX v3;
        X509V3_set_ctx_nodb(&v3);
        X509V3_set_ctx(&v3, issuer ? issuer->cert : x, x, NULL, NULL, 0);
        X509_EXTENSION *ski = X509V3_EXT_conf_nid(NULL, &v3, NID_subject_key_identifier, "hash");
        ok = ski && X509_add_ext(x, ski, -1) == 1;
        X509_EXTENSION_free(ski);
        if(ok && issuer) {
            X509_EXTENSION *aki =
                X509V3_EXT_conf_nid(NULL, &v3, NID_authority_key_identifier, "keyid");
            ok = aki && X509_add_ext(x, aki, -1) == 1;
            X509_EXTENSION_free(aki);
        }
    }
    if(ok && pad) {
        ASN1_IA5STRING *cm = ASN1_IA5STRING_new();
        ok = cm && ASN1_STRING_set(cm, padding, (int)pad) == 1 &&
             X509_add1_ext_i2d(x, NID_netscape_comment, cm, 0, X509V3_ADD_DEFAULT) == 1;
        ASN1_IA5STRING_free(cm);
    }
    BN_free(sn);
    X509_NAME_free(nm);
    return ok;
}

gds_status st_make_cert(const testca_t *issuer, EVP_PKEY *key, const char *cn, long fromSec,
                        long toSec, bool isCa, size_t pad, gds_buf *out) {
    return st_make_leaf(issuer, key, cn, NULL, fromSec, toSec, isCa, pad, out);
}

static bool add_uri(X509 *x, const char *uri) {
    GENERAL_NAMES *gens = sk_GENERAL_NAME_new_null();
    GENERAL_NAME *g = GENERAL_NAME_new();
    ASN1_IA5STRING *u = ASN1_IA5STRING_new();
    bool ok = gens && g && u && ASN1_STRING_set(u, uri, -1) == 1;
    if(ok) {
        GENERAL_NAME_set0_value(g, GEN_URI, u);
        u = NULL;
        ok = sk_GENERAL_NAME_push(gens, g) > 0;
        if(ok)
            g = NULL;
    }
    ok = ok && X509_add1_ext_i2d(x, NID_subject_alt_name, gens, 0, 0) == 1;
    ASN1_IA5STRING_free(u);
    GENERAL_NAME_free(g);
    GENERAL_NAMES_free(gens);
    return ok;
}

gds_status st_make_leaf(const testca_t *issuer, EVP_PKEY *key, const char *cn, const char *uri,
                        long fromSec, long toSec, bool isCa, size_t pad, gds_buf *out) {
    out->data = NULL;
    out->len = 0;
    if(toSec > (long)TESTCA_MAX_DAYS * 86400L)
        return GDS_EINVAL; /* test certificates live at most TESTCA_MAX_DAYS */
    X509 *x = X509_new();
    unsigned char *der = NULL;
    int len = -1;
    if(x && cert_body(x, issuer, key, cn, fromSec, toSec, isCa, pad) && (!uri || add_uri(x, uri)) &&
       X509_sign(x, issuer ? issuer->key : key, EVP_sha256()) > 0)
        len = i2d_X509(x, &der);
    gds_status s = len > 0 ? gds_buf_dup(der, (size_t)len, out) : GDS_ECRYPTO;
    OPENSSL_free(der);
    X509_free(x);
    ERR_clear_error();
    return s;
}

void st_discard(UA_Client *c) {
    UA_NodeId m;
    if(uac_find_child(c, ns0(UA_NS0ID_SERVERCONFIGURATION), "CancelChanges", &m) ==
       UA_STATUSCODE_GOOD) {
        size_t outN = 0;
        UA_Variant *out = NULL;
        (void)UA_Client_call(c, ns0(UA_NS0ID_SERVERCONFIGURATION), m, 0, NULL, &outN, &out);
        free_out(out, outN);
    }
    UA_NodeId_clear(&m);
    st_client_free(c);
}

gds_status st_intermediate(srv_target *t) {
    if(t->caInt.cert)
        return GDS_OK;
    EVP_PKEY *k = EVP_RSA_gen(2048);
    EVP_PKEY *lk = EVP_RSA_gen(2048);
    gds_status s = k && lk ? st_make_cert(&t->ca, k, TESTCA_ORG " ca-int", -3600, 7 * 86400L,
                                          true, 0, &t->caIntDer)
                           : GDS_ECRYPTO;
    if(s == GDS_OK) {
        t->caInt.cert = x509_parse_cert(&t->caIntDer);
        t->caInt.key = k;
        k = NULL;
        s = t->caInt.cert ? GDS_OK : GDS_ECRYPTO;
    }
    if(s == GDS_OK)
        s = testca_crl_der(&t->caInt, &t->caIntCrl);
    if(s == GDS_OK)
        s = st_make_cert(&t->caInt, lk, TESTCA_ORG " peer-int", -3600, 7 * 86400L, false, 0,
                         &t->peerInt);
    EVP_PKEY_free(k);
    EVP_PKEY_free(lk);
    if(s != GDS_OK) {
        testca_free(&t->caInt);
        gds_buf_free(&t->caIntDer);
        gds_buf_free(&t->caIntCrl);
        gds_buf_free(&t->peerInt);
    }
    ERR_clear_error();
    return s;
}

/* t-withkey: a certificate for the target from the test CA, with a key the
 * Auditor generated, as PEM. */
gds_status st_withkey(const srv_target *t, gds_buf *cert, gds_buf *pem) {
    gds_buf der = {NULL, 0};
    pem->data = NULL;
    pem->len = 0;
    gds_status s = testca_issue(&t->ca, "OpenGDS Auditor TEST t-withkey", t->targetUri, NULL,
                                TESTCA_MAX_DAYS, cert, &der);
    if(s != GDS_OK)
        return s;
    const unsigned char *q = der.data;
    EVP_PKEY *k = d2i_AutoPrivateKey(NULL, &q, (long)der.len);
    gds_buf_free_secret(&der);
    BIO *bio = BIO_new(BIO_s_mem());
    char *data = NULL;
    long len = 0;
    s = GDS_ECRYPTO;
    if(k && bio && PEM_write_bio_PrivateKey(bio, k, NULL, NULL, 0, NULL, NULL) == 1 &&
       (len = BIO_get_mem_data(bio, &data)) > 0)
        s = gds_buf_dup(data, (size_t)len, pem);
    if(data && len > 0)
        OPENSSL_cleanse(data, (size_t)len);
    BIO_free(bio);
    EVP_PKEY_free(k);
    ERR_clear_error();
    if(s != GDS_OK)
        gds_buf_free(cert);
    return s;
}

EVP_PKEY *st_tgood_key(const srv_target *t) {
    X509 *x = x509_parse_cert(&t->tGood);
    EVP_PKEY *k = x ? X509_get_pubkey(x) : NULL;
    X509_free(x);
    ERR_clear_error();
    return k;
}

/* An anonymous session over SignAndEncrypt with the application identity
 * cert/key, trusting the test CA (which issues t-good) and the pinned
 * certificate. *out is NULL unless the session is activated. */
UA_StatusCode st_peer_connect(const srv_target *t, const gds_buf *cert, const gds_buf *key,
                              UA_Client **out) {
    *out = NULL;
    char uri[256];
    if(x509_san_uri(cert, uri, sizeof(uri)) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    gds_buf trust[2 + ST_MAX_TARGET_TRUST], crls[1 + ST_MAX_TARGET_TRUST];
    size_t n = 0, nc = 0;
    trust[n++] = t->caDer;
    crls[nc++] = t->caCrl;
    if(t->pinned.len) { /* and the issuers of a CA-issued pinned certificate */
        trust[n++] = t->pinned;
        for(size_t i = 0; i < t->targetTrustN; i++)
            trust[n++] = t->targetTrust[i];
        for(size_t i = 0; i < t->targetCrlN; i++)
            crls[nc++] = t->targetCrl[i];
    }
    UA_Client *c = uac_new_secure_mode(cert, key, trust, n, crls, nc, uri, POLICY_RSAPSS,
                                       UA_MESSAGESECURITYMODE_SIGNANDENCRYPT);
    if(!c)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode r = UA_Client_connect(c, t->url);
    if(r == UA_STATUSCODE_GOOD)
        *out = c;
    else
        st_client_free(c);
    return r;
}

/* A refusal that names the certificate, or hides it (Part 4 §6.1.3,
 * Part 6 §6.7.5: Bad_SecurityChecksFailed may stand for any of them).
 * Closed connections are how a server can end an OpenSecureChannel. */
bool st_cert_refusal(UA_StatusCode r) {
    static const UA_StatusCode codes[] = {
        UA_STATUSCODE_BADSECURITYCHECKSFAILED,       UA_STATUSCODE_BADCERTIFICATEUNTRUSTED,
        UA_STATUSCODE_BADCERTIFICATEREVOKED,         UA_STATUSCODE_BADCERTIFICATEINVALID,
        UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE, UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN,
        UA_STATUSCODE_BADCONNECTIONCLOSED,           UA_STATUSCODE_BADSECURECHANNELCLOSED,
    };
    for(size_t i = 0; i < GDS_ARRAY_SIZE(codes); i++)
        if(r == codes[i])
            return true;
    return false;
}

static UA_StatusCode run_restart_cmd(const char *cmd) {
    fflush(NULL);
    pid_t pid = fork();
    if(pid < 0)
        return UA_STATUSCODE_BADINTERNALERROR;
    if(pid == 0) {
        /* Only stdin, stdout and stderr: a server the command starts must not
         * keep the Auditor's other descriptors open, such as the desktop
         * UI's --events pipe, whose reader waits for end of file */
        for(int fd = 3; fd < 1024; fd++)
            close(fd);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    int st = 0;
    while(waitpid(pid, &st, 0) < 0)
        if(errno != EINTR)
            return UA_STATUSCODE_BADINTERNALERROR;
    return WIFEXITED(st) && WEXITSTATUS(st) == 0 ? UA_STATUSCODE_GOOD
                                                  : UA_STATUSCODE_BADINTERNALERROR;
}

/* Run cmd (or, without one, ask the operator at a terminal to do what
 * prompt says), then wait for GetEndpoints within the settle timeout. */
static UA_StatusCode hook(srv_target *t, const char *cmd, const char *option, const char *prompt,
                          ga_ctx *ctx) {
    st_close(t);
    UA_StatusCode r;
    if(cmd) {
        r = run_restart_cmd(cmd);
        ga_note(ctx, "%s -> %s", option, r == UA_STATUSCODE_GOOD ? "exit 0" : "failed");
        if(r != UA_STATUSCODE_GOOD)
            return r;
    } else if(isatty(STDIN_FILENO)) {
        fprintf(stderr, "%s, then press Enter: ", prompt);
        int ch;
        while((ch = getchar()) != EOF && ch != '\n')
            ;
    } else {
        return UA_STATUSCODE_BADNOTSUPPORTED;
    }
    time_t start = time(NULL);
    for(;;) {
        UA_EndpointDescription *eps = NULL;
        size_t n = 0;
        r = st_endpoints(t, &eps, &n);
        UA_Array_delete(eps, n, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
        if(r == UA_STATUSCODE_GOOD || (long)(time(NULL) - start) > t->settleSec)
            break;
        struct timespec ts = {0, 500000000L};
        nanosleep(&ts, NULL);
    }
    ga_note(ctx, "target back after %ld s (GetEndpoints -> %s)", (long)(time(NULL) - start),
            UA_StatusCode_name(r));
    return r;
}

UA_StatusCode st_restart(srv_target *t, ga_ctx *ctx) {
    return hook(t, t->restartCmd, "--restart-cmd", "Restart the target now", ctx);
}

UA_StatusCode st_setup_hook(srv_target *t, ga_ctx *ctx) {
    if(t->setupPrepared)
        return UA_STATUSCODE_GOOD;
    t->setupPrepared = true;
    UA_StatusCode r = hook(t, t->setupCmd, "--setup-cmd",
                           "Reset the target to its application setup state now", ctx);
    return r == UA_STATUSCODE_BADNOTSUPPORTED ? UA_STATUSCODE_GOOD : r; /* reset beforehand */
}
