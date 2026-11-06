/* OpenGDS spec tests: StartNewKeyPairRequest (OPC 10000-12 §7.9.4) and the
 * argument checks of StartSigningRequest (§7.9.3) that the T0 set left out.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids_gds.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

#include <string.h>
#include <unistd.h>

#include "common/limits.h"
#include "gds_target.h"
#include "spec_tests.h"
#include "common/banned.h"

#define URI_LEN (GDS_MAX_APPLICATION_URI + 1)
#define PFX_PASSWORD "auditor-test-only"

static bool setup_app(ga_ctx *ctx, gds_target *t, char *uri, size_t uriLen, UA_NodeId *id) {
    UA_StatusCode r = gt_session(t);
    if(r == UA_STATUSCODE_GOOD)
        r = gt_register(t, UA_APPLICATIONTYPE_CLIENT, uri, uriLen, id);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: session or RegisterApplication -> %s", UA_StatusCode_name(r));
        return false;
    }
    return true;
}

/* StartNewKeyPairRequest(applicationId, certificateGroupId, certificateTypeId,
 * subjectName, domainNames, privateKeyFormat, privateKeyPassword) */
static UA_StatusCode start_keypair(gds_target *t, const UA_NodeId *app, const char *format,
                                   const char *password, UA_NodeId *reqId) {
    UA_NodeId_init(reqId);
    UA_NodeId group = gt_default_group(t), type = gt_rsa_type();
    UA_String subject = UA_STRING_NULL, fmt = UA_STRING((char *)(uintptr_t)format),
              pw = password ? UA_STRING((char *)(uintptr_t)password) : UA_STRING_NULL;
    UA_Variant in[7];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)app, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &type, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[3], &subject, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setArray(&in[4], UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[5], &fmt, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[6], &pw, &UA_TYPES[UA_TYPES_STRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = gt_call(t, UA_GDSID_DIRECTORY_STARTNEWKEYPAIRREQUEST, 7, in, 1, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_NodeId *rid = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_NODEID]);
    r = rid ? UA_NodeId_copy(rid, reqId) : UA_STATUSCODE_BADTYPEMISMATCH;
    gt_free_out(out, outN);
    return r;
}

/* FinishRequest polling; on Good the caller owns cert and key. */
static UA_StatusCode finish(gds_target *t, ga_ctx *ctx, const UA_NodeId *app,
                            const UA_NodeId *reqId, gds_buf *cert, gds_buf *key) {
    memset(cert, 0, sizeof(*cert));
    memset(key, 0, sizeof(*key));
    UA_Variant fin[2];
    UA_Variant_setScalar(&fin[0], (void *)(uintptr_t)app, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&fin[1], (void *)(uintptr_t)reqId, &UA_TYPES[UA_TYPES_NODEID]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r;
    unsigned waited = 0;
    for(;;) {
        r = gt_call(t, UA_GDSID_DIRECTORY_FINISHREQUEST, 2, fin, 3, &outN, &out);
        if(r != UA_STATUSCODE_BADNOTHINGTODO || waited >= t->pollSeconds)
            break;
        waited++;
        sleep(1);
    }
    ga_note(ctx, "FinishRequest -> %s after %u pending poll(s)", UA_StatusCode_name(r), waited);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_ByteString *c = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
    const UA_ByteString *k = uac_out_scalar(out, outN, 1, &UA_TYPES[UA_TYPES_BYTESTRING]);
    gds_status s = GDS_EINVAL;
    if(c && k && c->length > 0 && k->length > 0) {
        s = gds_buf_dup(c->data, c->length, cert);
        if(s == GDS_OK)
            s = gds_buf_dup(k->data, k->length, key);
    }
    gt_free_out(out, outN);
    if(s != GDS_OK) {
        gds_buf_free(cert);
        gds_buf_free_secret(key);
        return UA_STATUSCODE_BADUNEXPECTEDERROR;
    }
    return UA_STATUSCODE_GOOD;
}

/* Does the PFX open with the password, and hold a key matching cert? */
static bool pfx_matches(const gds_buf *pfx, const gds_buf *certDer, bool *hasCert) {
    *hasCert = false;
    const unsigned char *pp = pfx->data;
    PKCS12 *p12 = d2i_PKCS12(NULL, &pp, (long)pfx->len);
    if(!p12)
        return false;
    EVP_PKEY *k = NULL;
    X509 *c = NULL;
    bool ok = PKCS12_parse(p12, PFX_PASSWORD, &k, &c, NULL) == 1 && k;
    *hasCert = c != NULL;
    X509 *issued = x509_parse_cert(certDer);
    if(ok && issued)
        ok = X509_check_private_key(issued, k) == 1;
    X509_free(issued);
    X509_free(c);
    EVP_PKEY_free(k);
    PKCS12_free(p12);
    x509_drain_errors("pfx");
    return ok;
}

static void keypair_case(ga_ctx *ctx, gds_target *t, const char *format) {
    char uri[URI_LEN];
    UA_NodeId id, req;
    if(!setup_app(ctx, t, uri, sizeof(uri), &id))
        return;
    UA_StatusCode r = start_keypair(t, &id, format, PFX_PASSWORD, &req);
    (void)gt_absent(ctx, r, false, "StartNewKeyPairRequest");
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "StartNewKeyPairRequest(%s) -> %s", format, UA_StatusCode_name(r));
        UA_NodeId_clear(&id);
        return;
    }
    gds_buf cert = {0}, key = {0};
    r = finish(t, ctx, &id, &req, &cert, &key);
    char san[URI_LEN] = "";
    bool pfxCert = false;
    if(r == UA_STATUSCODE_BADNOTHINGTODO)
        ga_not_tested(ctx, "request still pending after %u s (manual approval?)", t->pollSeconds);
    else if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "FinishRequest -> %s (a key pair request returns certificate and key)",
                UA_StatusCode_name(r));
    else if(x509_san_uri(&cert, san, sizeof(san)) != GDS_OK || strcmp(san, uri) != 0)
        ga_fail(ctx, "SAN URI '%s' differs from the registered ApplicationUri", san);
    else if(strcmp(format, "PFX") == 0 && !pfx_matches(&key, &cert, &pfxCert))
        ga_fail(ctx, "the PFX does not open with the password or its key does not match");
    else if(strcmp(format, "PFX") == 0 && !pfxCert)
        ga_fail(ctx, "the PFX holds no certificate (it shall include certificate and key)");
    else if(strcmp(format, "PEM") == 0 && !x509_key_matches(&cert, &key))
        ga_fail(ctx, "the PEM private key does not match the certificate");
    else
        ga_pass(ctx, "%s key pair: certificate for the record's URI with the matching key",
                format);
    gds_buf_free(&cert);
    gds_buf_free_secret(&key);
    UA_NodeId_clear(&req);
    UA_NodeId_clear(&id);
}

static void t_keypair_pfx(ga_ctx *ctx, void *p) {
    keypair_case(ctx, p, "PFX");
}

static void t_keypair_pem(ga_ctx *ctx, void *p) {
    keypair_case(ctx, p, "PEM");
}

static void t_keypair_bad_format(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    char uri[URI_LEN];
    UA_NodeId id, req;
    if(!setup_app(ctx, t, uri, sizeof(uri), &id))
        return;
    UA_StatusCode r = start_keypair(t, &id, "NOT-A-FORMAT", PFX_PASSWORD, &req);
    UA_NodeId_clear(&req);
    (void)gt_absent(ctx, r, false, "StartNewKeyPairRequest");
    if(r == UA_STATUSCODE_BADINVALIDARGUMENT)
        ga_pass(ctx, "BadInvalidArgument");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "StartNewKeyPairRequest accepted an unknown PrivateKeyFormat");
    else
        ga_warn(ctx, "refused with %s; the spec names BadInvalidArgument", UA_StatusCode_name(r));
    UA_NodeId_clear(&id);
}

static void t_keypair_unknown_app(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "session -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_NodeId id = UA_NODEID_GUID(t->ns, UA_Guid_random()), req;
    r = start_keypair(t, &id, "PFX", PFX_PASSWORD, &req);
    UA_NodeId_clear(&req);
    if(r == UA_STATUSCODE_BADMETHODINVALID || r == UA_STATUSCODE_BADNOTIMPLEMENTED)
        (void)gt_absent(ctx, r, false, "StartNewKeyPairRequest");
    if(r == UA_STATUSCODE_BADNOTFOUND)
        ga_pass(ctx, "BadNotFound");
    else if(r == UA_STATUSCODE_BADNODEIDUNKNOWN)
        ga_warn(ctx, "BadNodeIdUnknown (deprecated code; the spec now names BadNotFound)");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "key pair requested for an application that does not exist");
    else
        ga_warn(ctx, "refused with %s; the spec names BadNotFound", UA_StatusCode_name(r));
}

/* StartSigningRequest with chosen group and type (others as in gt_sign) */
static UA_StatusCode start_signing(gds_target *t, const UA_NodeId *app, UA_NodeId group,
                                   UA_NodeId type, const char *uri) {
    gds_buf key = {0}, csr = {0};
    if(x509_new_rsa_key(2048, &key) != GDS_OK ||
       x509_make_csr(&key, "OpenGDS Auditor test", uri, NULL, &csr) != GDS_OK) {
        gds_buf_free_secret(&key);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_ByteString csrBs = {csr.len, csr.data};
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)app, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &type, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[3], &csrBs, &UA_TYPES[UA_TYPES_BYTESTRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = gt_call(t, UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST, 4, in, 1, &outN, &out);
    gt_free_out(out, outN);
    gds_buf_free_secret(&key);
    gds_buf_free(&csr);
    return r;
}

static void t_sign_bad_group(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    char uri[URI_LEN];
    UA_NodeId id;
    if(!setup_app(ctx, t, uri, sizeof(uri), &id))
        return;
    UA_StatusCode r =
        start_signing(t, &id, UA_NODEID_GUID(t->ns, UA_Guid_random()), gt_rsa_type(), uri);
    if(r == UA_STATUSCODE_BADINVALIDARGUMENT)
        ga_pass(ctx, "BadInvalidArgument");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "StartSigningRequest accepted a CertificateGroupId that does not exist");
    else
        ga_warn(ctx, "refused with %s; the spec names BadInvalidArgument", UA_StatusCode_name(r));
    UA_NodeId_clear(&id);
}

/* A CertificateType that is not in the group's CertificateTypes: the
 * DefaultApplicationGroup never holds HTTPS certificates. */
static void t_sign_bad_type(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    char uri[URI_LEN];
    UA_NodeId id;
    if(!setup_app(ctx, t, uri, sizeof(uri), &id))
        return;
    UA_StatusCode r = start_signing(t, &id, gt_default_group(t),
                                    UA_NODEID_NUMERIC(0, UA_NS0ID_HTTPSCERTIFICATETYPE), uri);
    if(r == UA_STATUSCODE_BADINVALIDARGUMENT)
        ga_pass(ctx, "BadInvalidArgument");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "an HttpsCertificateType request accepted in DefaultApplicationGroup");
    else
        ga_warn(ctx, "refused with %s; the spec names BadInvalidArgument", UA_StatusCode_name(r));
    UA_NodeId_clear(&id);
}

static void t_sign_unknown_app(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "session -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_NodeId id = UA_NODEID_GUID(t->ns, UA_Guid_random());
    r = start_signing(t, &id, gt_default_group(t), gt_rsa_type(), "urn:opengds:auditor:none");
    if(r == UA_STATUSCODE_BADNOTFOUND)
        ga_pass(ctx, "BadNotFound");
    else if(r == UA_STATUSCODE_BADNODEIDUNKNOWN)
        ga_warn(ctx, "BadNodeIdUnknown (deprecated code; the spec now names BadNotFound)");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "signing request accepted for an application that does not exist");
    else
        ga_warn(ctx, "refused with %s; the spec names BadNotFound", UA_StatusCode_name(r));
}

/* A null CertificateGroupId selects DefaultApplicationGroup */
static void t_sign_null_group(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    char uri[URI_LEN];
    UA_NodeId id;
    if(!setup_app(ctx, t, uri, sizeof(uri), &id))
        return;
    UA_StatusCode r = start_signing(t, &id, UA_NODEID_NULL, UA_NODEID_NULL, uri);
    if(r == UA_STATUSCODE_GOOD)
        ga_pass(ctx, "null CertificateGroupId and CertificateTypeId accepted");
    else
        ga_fail(ctx, "StartSigningRequest with null group and type -> %s (the group defaults to "
                     "DefaultApplicationGroup)", UA_StatusCode_name(r));
    UA_NodeId_clear(&id);
}

const ga_test spec_keypair_tests[] = {
    {"gds.cm.keypair_pfx", "12 §7.9.4, §7.9.5", "StartNewKeyPairRequest delivers a PFX with certificate and key",
     true, false, t_keypair_pfx},
    {"gds.cm.keypair_pem", "12 §7.9.4, §7.9.5", "StartNewKeyPairRequest delivers a PEM key matching the certificate",
     true, false, t_keypair_pem},
    {"gds.cm.keypair_bad_format", "12 §7.9.4", "StartNewKeyPairRequest refuses an unknown PrivateKeyFormat",
     true, false, t_keypair_bad_format},
    {"gds.cm.keypair_unknown_app", "12 §7.9.4", "StartNewKeyPairRequest of an unknown application returns BadNotFound",
     false, false, t_keypair_unknown_app},
    {"gds.cm.sign_bad_group", "12 §7.9.3", "StartSigningRequest refuses an unknown CertificateGroupId",
     true, false, t_sign_bad_group},
    {"gds.cm.sign_bad_type", "12 §7.9.3", "StartSigningRequest refuses a CertificateType the group does not hold",
     true, false, t_sign_bad_type},
    {"gds.cm.sign_unknown_app", "12 §7.9.3", "StartSigningRequest of an unknown application returns BadNotFound",
     false, false, t_sign_unknown_app},
    {"gds.cm.sign_null_group", "12 §7.9.3", "StartSigningRequest with a null group uses DefaultApplicationGroup",
     true, false, t_sign_null_group},
};
const size_t spec_keypair_count = GDS_ARRAY_SIZE(spec_keypair_tests);
