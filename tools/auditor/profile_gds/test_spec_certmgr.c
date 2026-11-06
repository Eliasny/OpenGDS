/* OpenGDS T0 spec tests: CertificateManager pull methods (OPC 10000-12 §7.9).
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids_gds.h>

#include <string.h>

#include "common/limits.h"
#include "gds_target.h"
#include "spec_tests.h"
#include "common/banned.h"

#define URI_LEN (GDS_MAX_APPLICATION_URI + 1)

/* Common setup: a fresh registered client application */
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

static void t_groups(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    char uri[URI_LEN];
    UA_NodeId id;
    if(!setup_app(ctx, t, uri, sizeof(uri), &id))
        return;
    UA_Variant in;
    UA_Variant_setScalar(&in, &id, &UA_TYPES[UA_TYPES_NODEID]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = gt_call(t, UA_GDSID_DIRECTORY_GETCERTIFICATEGROUPS, 1, &in, 1, &outN, &out);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "GetCertificateGroups -> %s", UA_StatusCode_name(r));
        UA_NodeId_clear(&id);
        return;
    }
    const void *g = NULL;
    size_t n = 0;
    r = gds_arg_array(&out[0], &UA_TYPES[UA_TYPES_NODEID], GDS_MAX_ARRAY_FIELD, &g, &n);
    UA_NodeId def = gt_default_group(t);
    bool hasDefault = false;
    for(size_t i = 0; i < n; i++)
        hasDefault |= UA_NodeId_equal(&((const UA_NodeId *)g)[i], &def);
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "result is not a NodeId array: %s", UA_StatusCode_name(r));
    else if(n == 0)
        ga_fail(ctx, "no certificate group for a registered application");
    else if(!hasDefault)
        ga_warn(ctx, "%zu group(s) but not DefaultApplicationGroup", n);
    else
        ga_pass(ctx, "%zu group(s), DefaultApplicationGroup included", n);
    gt_free_out(out, outN);
    UA_NodeId_clear(&id);
}

static void t_groups_unknown(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "session -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_NodeId id = UA_NODEID_GUID(t->ns, UA_Guid_random());
    UA_Variant in;
    UA_Variant_setScalar(&in, &id, &UA_TYPES[UA_TYPES_NODEID]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    r = gt_call(t, UA_GDSID_DIRECTORY_GETCERTIFICATEGROUPS, 1, &in, 0, &outN, &out);
    gt_free_out(out, outN);
    if(r == UA_STATUSCODE_BADNOTFOUND)
        ga_pass(ctx, "BadNotFound");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "groups returned for an application that does not exist");
    else
        ga_warn(ctx, "refused with %s; the spec names BadNotFound", UA_StatusCode_name(r));
}

static void t_status_new(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    char uri[URI_LEN];
    UA_NodeId id;
    if(!setup_app(ctx, t, uri, sizeof(uri), &id))
        return;
    UA_NodeId group = gt_default_group(t), type = gt_rsa_type();
    UA_Variant in[3];
    UA_Variant_setScalar(&in[0], &id, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &type, &UA_TYPES[UA_TYPES_NODEID]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = gt_call(t, UA_GDSID_DIRECTORY_GETCERTIFICATESTATUS, 3, in, 1, &outN, &out);
    const UA_Boolean *upd = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "GetCertificateStatus -> %s", UA_StatusCode_name(r));
    else if(!upd)
        ga_fail(ctx, "result is not a Boolean");
    else if(!*upd)
        ga_fail(ctx, "updateRequired=false for an application that has no certificate");
    else
        ga_pass(ctx, "updateRequired=true before the first certificate");
    gt_free_out(out, outN);
    UA_NodeId_clear(&id);
}

static void t_bad_csr(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    char uri[URI_LEN];
    UA_NodeId id;
    if(!setup_app(ctx, t, uri, sizeof(uri), &id))
        return;
    static const uint8_t junk[] = {0x30, 0x03, 0x02, 0x01, 0x00}; /* valid DER, not a CSR */
    UA_NodeId group = gt_default_group(t), type = gt_rsa_type();
    UA_ByteString csr = {sizeof(junk), (UA_Byte *)(uintptr_t)junk};
    UA_Variant in[4];
    UA_Variant_setScalar(&in[0], &id, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &type, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[3], &csr, &UA_TYPES[UA_TYPES_BYTESTRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = gt_call(t, UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST, 4, in, 0, &outN, &out);
    gt_free_out(out, outN);
    if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "StartSigningRequest accepted a request that is not a CSR");
    else if(r == UA_STATUSCODE_BADINVALIDARGUMENT || r == UA_STATUSCODE_BADREQUESTNOTALLOWED)
        ga_pass(ctx, "refused with %s", UA_StatusCode_name(r));
    else
        ga_warn(ctx, "refused with %s; expected BadInvalidArgument", UA_StatusCode_name(r));
    UA_NodeId_clear(&id);
}

/* The thin-path signing flow: CSR -> FinishRequest -> certificate checks */
static void t_signing_flow(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    char uri[URI_LEN];
    UA_NodeId id;
    if(!setup_app(ctx, t, uri, sizeof(uri), &id))
        return;
    gds_buf key = {0}, csr = {0}, cert = {0}, issuer = {0};
    size_t privLen = 0;
    if(x509_new_rsa_key(2048, &key) != GDS_OK ||
       x509_make_csr(&key, "OpenGDS Auditor test", uri, "localhost", &csr) != GDS_OK) {
        ga_not_tested(ctx, "could not create a CSR");
        goto cleanup;
    }
    UA_StatusCode r = gt_sign(t, &id, &csr, ctx, &cert, &issuer, &privLen);
    if(r == UA_STATUSCODE_BADNOTHINGTODO) {
        ga_not_tested(ctx, "request still pending after %u s (manual approval?)", t->pollSeconds);
        goto cleanup;
    }
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "signing flow -> %s", UA_StatusCode_name(r));
        goto cleanup;
    }
    char san[URI_LEN];
    if(privLen > 0)
        ga_fail(ctx, "FinishRequest returned a private key for a CSR request");
    else if(!x509_cert_has_csr_key(&cert, &csr))
        ga_fail(ctx, "issued certificate does not carry the CSR's public key");
    else if(x509_san_uri(&cert, san, sizeof(san)) != GDS_OK || strcmp(san, uri) != 0)
        ga_fail(ctx, "SAN URI '%s' differs from the registered ApplicationUri", san);
    else if(issuer.len == 0)
        ga_fail(ctx, "no issuer certificate returned");
    else if(!x509_signed_by(&cert, &issuer))
        ga_fail(ctx, "certificate is not signed by the returned issuer");
    else
        ga_pass(ctx, "certificate carries the CSR key and the record's URI, signed by the issuer");
cleanup:
    gds_buf_free_secret(&key);
    gds_buf_free(&csr);
    gds_buf_free(&cert);
    gds_buf_free(&issuer);
    UA_NodeId_clear(&id);
}

/* Contents come from the record, never from the CSR (§7.9.4) */
static void t_csr_wrong_uri(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    char uri[URI_LEN];
    UA_NodeId id;
    if(!setup_app(ctx, t, uri, sizeof(uri), &id))
        return;
    gds_buf key = {0}, csr = {0}, cert = {0}, issuer = {0};
    size_t privLen = 0;
    if(x509_new_rsa_key(2048, &key) != GDS_OK ||
       x509_make_csr(&key, "OpenGDS Auditor test", "urn:opengds:auditor:someone-else", NULL,
                     &csr) != GDS_OK) {
        ga_not_tested(ctx, "could not create a CSR");
        goto cleanup;
    }
    UA_StatusCode r = gt_sign(t, &id, &csr, ctx, &cert, &issuer, &privLen);
    char san[URI_LEN] = "";
    if(r == UA_STATUSCODE_BADNOTHINGTODO)
        ga_not_tested(ctx, "request still pending after %u s", t->pollSeconds);
    else if(r != UA_STATUSCODE_GOOD)
        ga_pass(ctx, "request with a foreign SAN URI refused: %s", UA_StatusCode_name(r));
    else if(x509_san_uri(&cert, san, sizeof(san)) == GDS_OK && strcmp(san, uri) == 0)
        ga_pass(ctx, "SAN URI taken from the record, not the CSR");
    else
        ga_fail(ctx, "certificate issued with SAN URI '%s' from the CSR", san);
cleanup:
    gds_buf_free_secret(&key);
    gds_buf_free(&csr);
    gds_buf_free(&cert);
    gds_buf_free(&issuer);
    UA_NodeId_clear(&id);
}

static void t_finish_unknown(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    char uri[URI_LEN];
    UA_NodeId id;
    if(!setup_app(ctx, t, uri, sizeof(uri), &id))
        return;
    UA_NodeId req = UA_NODEID_GUID(t->ns, UA_Guid_random());
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &id, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &req, &UA_TYPES[UA_TYPES_NODEID]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = gt_call(t, UA_GDSID_DIRECTORY_FINISHREQUEST, 2, in, 0, &outN, &out);
    gt_free_out(out, outN);
    if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "FinishRequest succeeded for a request that does not exist");
    else if(r == UA_STATUSCODE_BADNOTHINGTODO)
        ga_fail(ctx, "BadNothingToDo for an unknown request: a client would poll forever");
    else if(r == UA_STATUSCODE_BADINVALIDARGUMENT || r == UA_STATUSCODE_BADNOTFOUND)
        ga_pass(ctx, "refused with %s", UA_StatusCode_name(r));
    else
        ga_warn(ctx, "refused with %s; expected BadInvalidArgument", UA_StatusCode_name(r));
    UA_NodeId_clear(&id);
}

static void t_status_after_issue(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    char uri[URI_LEN];
    UA_NodeId id;
    if(!setup_app(ctx, t, uri, sizeof(uri), &id))
        return;
    gds_buf key = {0}, csr = {0}, cert = {0}, issuer = {0};
    size_t privLen = 0;
    UA_StatusCode r = UA_STATUSCODE_BADINTERNALERROR;
    if(x509_new_rsa_key(2048, &key) == GDS_OK &&
       x509_make_csr(&key, "OpenGDS Auditor test", uri, NULL, &csr) == GDS_OK)
        r = gt_sign(t, &id, &csr, ctx, &cert, &issuer, &privLen);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: signing flow -> %s", UA_StatusCode_name(r));
    } else {
        UA_NodeId group = gt_default_group(t), type = gt_rsa_type();
        UA_Variant in[3];
        UA_Variant_setScalar(&in[0], &id, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&in[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&in[2], &type, &UA_TYPES[UA_TYPES_NODEID]);
        size_t outN = 0;
        UA_Variant *out = NULL;
        r = gt_call(t, UA_GDSID_DIRECTORY_GETCERTIFICATESTATUS, 3, in, 1, &outN, &out);
        const UA_Boolean *upd = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BOOLEAN]);
        if(r != UA_STATUSCODE_GOOD || !upd)
            ga_fail(ctx, "GetCertificateStatus -> %s", UA_StatusCode_name(r));
        else if(*upd)
            ga_fail(ctx, "updateRequired=true right after a certificate was issued");
        else
            ga_pass(ctx, "updateRequired=false after issuance");
        gt_free_out(out, outN);
    }
    gds_buf_free_secret(&key);
    gds_buf_free(&csr);
    gds_buf_free(&cert);
    gds_buf_free(&issuer);
    UA_NodeId_clear(&id);
}

const ga_test spec_certmgr_tests[] = {
    {"gds.cm.groups", "12 §7.9.7", "GetCertificateGroups lists the groups of a registered application",
     true, false, t_groups},
    {"gds.cm.groups_unknown", "12 §7.9.7", "GetCertificateGroups of an unknown application returns BadNotFound",
     false, false, t_groups_unknown},
    {"gds.cm.status_new", "12 §7.9.10", "GetCertificateStatus requires an update before the first certificate",
     true, false, t_status_new},
    {"gds.cm.bad_csr", "12 §7.9.4", "StartSigningRequest refuses data that is not a CSR",
     true, false, t_bad_csr},
    {"gds.cm.signing_flow", "12 §7.9.4, §7.9.6, Annex G.1", "Signing flow issues a certificate from the record and the CSR key",
     true, false, t_signing_flow},
    {"gds.cm.csr_wrong_uri", "12 §7.9.4", "A CSR's SAN URI never overrides the registered ApplicationUri",
     true, false, t_csr_wrong_uri},
    {"gds.cm.finish_unknown", "12 §7.9.6", "FinishRequest refuses an unknown request id",
     true, false, t_finish_unknown},
    {"gds.cm.status_after_issue", "12 §7.9.10", "GetCertificateStatus needs no update right after issuance",
     true, false, t_status_after_issue},
};
const size_t spec_certmgr_count = GDS_ARRAY_SIZE(spec_certmgr_tests);
