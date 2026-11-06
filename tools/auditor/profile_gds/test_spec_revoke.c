/* OpenGDS spec tests: certificates of an application and their revocation
 * (OPC 10000-12 §7.9.6 RevokeCertificate, §7.9.8 GetCertificates,
 * §7.9.11 CheckRevocationStatus).
 * Revocation on UnregisterApplication (§7.9.6) is gds.dir.unregister_revokes
 * in test_spec_directory.c.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids_gds.h>
#include <openssl/x509.h>

#include <string.h>

#include "common/limits.h"
#include "gds_target.h"
#include "spec_tests.h"
#include "common/banned.h"

#define URI_LEN (GDS_MAX_APPLICATION_URI + 1)

typedef struct {
    char uri[URI_LEN];
    UA_NodeId id;
    gds_buf cert, issuer;
} issued;

static bool issue(ga_ctx *ctx, gds_target *t, issued *a) {
    memset(a, 0, sizeof(*a));
    UA_StatusCode r = gt_session(t);
    if(r == UA_STATUSCODE_GOOD)
        r = gt_issue(t, ctx, a->uri, sizeof(a->uri), &a->id, &a->cert, &a->issuer);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: register and sign -> %s", UA_StatusCode_name(r));
        return false;
    }
    return true;
}

static void issued_clear(issued *a) {
    UA_NodeId_clear(&a->id);
    gds_buf_free(&a->cert);
    gds_buf_free(&a->issuer);
}

/* GetCertificates(applicationId, certificateGroupId) */
static UA_StatusCode get_certs(gds_target *t, const UA_NodeId *app, const UA_NodeId *group,
                               size_t *nTypes, size_t *nCerts, const gds_buf *find,
                               bool *found) {
    *nTypes = *nCerts = 0;
    if(found)
        *found = false;
    UA_NodeId nullId = UA_NODEID_NULL;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)app, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], group ? (void *)(uintptr_t)group : &nullId,
                         &UA_TYPES[UA_TYPES_NODEID]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = gt_call(t, UA_GDSID_DIRECTORY_GETCERTIFICATES, 2, in, 2, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const void *types = NULL, *certs = NULL;
    r = gds_arg_array(&out[0], &UA_TYPES[UA_TYPES_NODEID], GDS_MAX_ARRAY_FIELD, &types, nTypes);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_arg_array(&out[1], &UA_TYPES[UA_TYPES_BYTESTRING], GDS_MAX_ARRAY_FIELD, &certs,
                          nCerts);
    if(r == UA_STATUSCODE_GOOD && find && found) {
        UA_ByteString want = {find->len, find->data};
        for(size_t i = 0; i < *nCerts; i++)
            *found |= UA_ByteString_equal(&((const UA_ByteString *)certs)[i], &want);
    }
    gt_free_out(out, outN);
    return r;
}

static UA_StatusCode revoke(gds_target *t, const UA_NodeId *app, const gds_buf *cert) {
    UA_ByteString c = {cert->len, cert->data};
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], (void *)(uintptr_t)app, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &c, &UA_TYPES[UA_TYPES_BYTESTRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = gt_call(t, UA_GDSID_DIRECTORY_REVOKECERTIFICATE, 2, in, 0, &outN, &out);
    gt_free_out(out, outN);
    return r;
}

/* CheckRevocationStatus(certificate) -> certificateStatus, validityTime */
static UA_StatusCode check_status(gds_target *t, const gds_buf *cert, UA_StatusCode *status) {
    UA_ByteString c = {cert->len, cert->data};
    UA_Variant in;
    UA_Variant_setScalar(&in, &c, &UA_TYPES[UA_TYPES_BYTESTRING]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = gt_call(t, UA_GDSID_DIRECTORY_CHECKREVOCATIONSTATUS, 1, &in, 2, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    const UA_StatusCode *s = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_STATUSCODE]);
    const UA_DateTime *v = uac_out_scalar(out, outN, 1, &UA_TYPES[UA_TYPES_DATETIME]);
    if(!s || !v)
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    else
        *status = *s;
    gt_free_out(out, outN);
    return r;
}

/* Is cert listed in one of the CRLs of the trust list? */
static bool crl_lists(const UA_TrustListDataType *tl, const gds_buf *certDer) {
    X509 *x = x509_parse_cert(certDer);
    if(!x)
        return false;
    bool hit = false;
    const UA_ByteString *lists[2] = {tl->trustedCrls, tl->issuerCrls};
    size_t sizes[2] = {tl->trustedCrlsSize, tl->issuerCrlsSize};
    for(size_t l = 0; l < 2 && !hit; l++) {
        for(size_t i = 0; i < sizes[l] && !hit; i++) {
            const unsigned char *pp = lists[l][i].data;
            X509_CRL *crl = d2i_X509_CRL(NULL, &pp, (long)lists[l][i].length);
            if(!crl)
                continue;
            X509_REVOKED *rev = NULL;
            hit = X509_CRL_get0_by_cert(crl, &rev, x) == 1;
            X509_CRL_free(crl);
        }
    }
    X509_free(x);
    return hit;
}

static UA_StatusCode read_group_tl(gds_target *t, UA_TrustListDataType *tl) {
    UA_TrustListDataType_init(tl);
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    return uac_read_trustlist(
        t->client, gt_node(t, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST),
        tl);
}

static void t_get_certificates(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    issued a;
    if(!issue(ctx, t, &a))
        return;
    size_t nT = 0, nC = 0;
    bool found = false;
    UA_StatusCode r = get_certs(t, &a.id, NULL, &nT, &nC, &a.cert, &found);
    size_t nT2 = 0, nC2 = 0;
    bool found2 = false;
    UA_NodeId group = gt_default_group(t);
    UA_StatusCode r2 = get_certs(t, &a.id, &group, &nT2, &nC2, &a.cert, &found2);
    (void)gt_absent(ctx, r, true, "GetCertificates");
    if(r != UA_STATUSCODE_GOOD || r2 != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "GetCertificates -> %s (all groups) / %s (default group)",
                UA_StatusCode_name(r), UA_StatusCode_name(r2));
    else if(nT != nC || nT2 != nC2)
        ga_fail(ctx, "CertificateTypeIds and Certificates differ in length (%zu/%zu)", nT, nC);
    else if(!found)
        ga_fail(ctx, "the issued certificate is missing with a null CertificateGroupId");
    else if(!found2)
        ga_fail(ctx, "the issued certificate is missing for DefaultApplicationGroup");
    else
        ga_pass(ctx, "issued certificate returned for all groups and for its group");
    issued_clear(&a);
}

static void t_get_certificates_unknown(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "session -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_NodeId id = UA_NODEID_GUID(t->ns, UA_Guid_random());
    size_t nT = 0, nC = 0;
    r = get_certs(t, &id, NULL, &nT, &nC, NULL, NULL);
    if(r == UA_STATUSCODE_BADMETHODINVALID || r == UA_STATUSCODE_BADNOTIMPLEMENTED)
        (void)gt_absent(ctx, r, true, "GetCertificates");
    if(r == UA_STATUSCODE_BADNOTFOUND)
        ga_pass(ctx, "BadNotFound");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "certificates returned for an application that does not exist");
    else
        ga_warn(ctx, "refused with %s; the spec names BadNotFound", UA_StatusCode_name(r));
}

static void t_get_certificates_bad_group(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    char uri[URI_LEN];
    UA_NodeId id;
    UA_StatusCode r = gt_session(t);
    if(r == UA_STATUSCODE_GOOD)
        r = gt_register(t, UA_APPLICATIONTYPE_CLIENT, uri, sizeof(uri), &id);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: RegisterApplication -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_NodeId group = UA_NODEID_GUID(t->ns, UA_Guid_random());
    size_t nT = 0, nC = 0;
    r = get_certs(t, &id, &group, &nT, &nC, NULL, NULL);
    (void)gt_absent(ctx, r, true, "GetCertificates");
    if(r == UA_STATUSCODE_BADINVALIDARGUMENT)
        ga_pass(ctx, "BadInvalidArgument");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "GetCertificates accepted a CertificateGroupId that does not exist");
    else
        ga_warn(ctx, "refused with %s; the spec names BadInvalidArgument", UA_StatusCode_name(r));
    UA_NodeId_clear(&id);
}

/* Revoked: in the group's CRL, gone from GetCertificates (only valid ones) */
static void t_revoke(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    issued a;
    if(!issue(ctx, t, &a))
        return;
    UA_StatusCode r = revoke(t, &a.id, &a.cert);
    (void)gt_absent(ctx, r, true, "RevokeCertificate");
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "RevokeCertificate -> %s", UA_StatusCode_name(r));
        issued_clear(&a);
        return;
    }
    UA_TrustListDataType tl;
    r = read_group_tl(t, &tl);
    size_t nT = 0, nC = 0;
    bool still = false;
    UA_StatusCode rg = get_certs(t, &a.id, NULL, &nT, &nC, &a.cert, &still);
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "reading the group trust list after revocation -> %s", UA_StatusCode_name(r));
    else if(!crl_lists(&tl, &a.cert))
        ga_fail(ctx, "the revoked certificate is in no CRL of the group trust list");
    else if(rg == UA_STATUSCODE_GOOD && still)
        ga_fail(ctx, "GetCertificates still returns the revoked certificate");
    else
        ga_pass(ctx, "revoked certificate listed in the group CRL and no longer returned");
    UA_TrustListDataType_clear(&tl);
    issued_clear(&a);
}

static void t_revoke_foreign(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    issued a, b;
    if(!issue(ctx, t, &a))
        return;
    if(!issue(ctx, t, &b)) {
        issued_clear(&a);
        return;
    }
    UA_StatusCode r = revoke(t, &a.id, &b.cert); /* b's certificate under a's id */
    (void)gt_absent(ctx, r, true, "RevokeCertificate");
    if(r == UA_STATUSCODE_BADINVALIDARGUMENT)
        ga_pass(ctx, "BadInvalidArgument");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "revoked another application's certificate under this ApplicationId");
    else
        ga_warn(ctx, "refused with %s; the spec names BadInvalidArgument", UA_StatusCode_name(r));
    issued_clear(&a);
    issued_clear(&b);
}

static void t_revoke_unknown_app(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    issued a;
    if(!issue(ctx, t, &a))
        return;
    UA_NodeId other = UA_NODEID_GUID(t->ns, UA_Guid_random());
    UA_StatusCode r = revoke(t, &other, &a.cert);
    if(r == UA_STATUSCODE_BADMETHODINVALID || r == UA_STATUSCODE_BADNOTIMPLEMENTED)
        (void)gt_absent(ctx, r, true, "RevokeCertificate");
    if(r == UA_STATUSCODE_BADNOTFOUND)
        ga_pass(ctx, "BadNotFound");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "RevokeCertificate succeeded for an ApplicationId that does not exist");
    else
        ga_warn(ctx, "refused with %s; the spec names BadNotFound", UA_StatusCode_name(r));
    issued_clear(&a);
}

static void t_check_good(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    issued a;
    if(!issue(ctx, t, &a))
        return;
    UA_StatusCode st = UA_STATUSCODE_BADINTERNALERROR;
    UA_StatusCode r = check_status(t, &a.cert, &st);
    (void)gt_absent(ctx, r, true, "CheckRevocationStatus");
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "CheckRevocationStatus -> %s", UA_StatusCode_name(r));
    else if(st != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "a certificate just issued is reported as %s", UA_StatusCode_name(st));
    else
        ga_pass(ctx, "CertificateStatus Good for a valid certificate");
    issued_clear(&a);
}

static void t_check_revoked(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    issued a;
    if(!issue(ctx, t, &a))
        return;
    UA_StatusCode r = revoke(t, &a.id, &a.cert);
    (void)gt_absent(ctx, r, true, "RevokeCertificate");
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: RevokeCertificate -> %s", UA_StatusCode_name(r));
        issued_clear(&a);
        return;
    }
    UA_StatusCode st = UA_STATUSCODE_GOOD;
    r = check_status(t, &a.cert, &st);
    (void)gt_absent(ctx, r, true, "CheckRevocationStatus");
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "CheckRevocationStatus -> %s", UA_StatusCode_name(r));
    else if(st == UA_STATUSCODE_BADCERTIFICATEREVOKED)
        ga_pass(ctx, "CertificateStatus BadCertificateRevoked");
    else if(st == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "a revoked certificate is reported as Good");
    else
        ga_warn(ctx, "revoked certificate reported as %s, expected BadCertificateRevoked",
                UA_StatusCode_name(st));
    issued_clear(&a);
}

/* The CertificateManager shall verify the Certificate's signature (§7.9.11) */
static void t_check_bad_signature(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    issued a;
    if(!issue(ctx, t, &a))
        return;
    if(a.cert.len < 16) {
        ga_not_tested(ctx, "setup: certificate too short");
        issued_clear(&a);
        return;
    }
    a.cert.data[a.cert.len - 8] ^= 0x5a; /* inside the signature value */
    UA_StatusCode st = UA_STATUSCODE_GOOD;
    UA_StatusCode r = check_status(t, &a.cert, &st);
    (void)gt_absent(ctx, r, true, "CheckRevocationStatus");
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "CheckRevocationStatus -> %s", UA_StatusCode_name(r));
    else if(st == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "a certificate with a broken signature is reported as Good");
    else
        ga_pass(ctx, "broken signature reported as %s", UA_StatusCode_name(st));
    issued_clear(&a);
}

const ga_test spec_revoke_tests[] = {
    {"gds.cm.get_certificates", "12 §7.9.8", "GetCertificates returns the issued certificate",
     true, false, t_get_certificates},
    {"gds.cm.get_certificates_unknown", "12 §7.9.8", "GetCertificates of an unknown application returns BadNotFound",
     false, false, t_get_certificates_unknown},
    {"gds.cm.get_certificates_bad_group", "12 §7.9.8", "GetCertificates refuses an unknown CertificateGroupId",
     true, false, t_get_certificates_bad_group},
    {"gds.cm.revoke", "12 §7.9.6, §7.9.8", "RevokeCertificate puts the certificate in the group CRL",
     true, false, t_revoke},
    {"gds.cm.revoke_foreign", "12 §7.9.6", "RevokeCertificate refuses a certificate of another application",
     true, false, t_revoke_foreign},
    {"gds.cm.revoke_unknown_app", "12 §7.9.6", "RevokeCertificate of an unknown application returns BadNotFound",
     true, false, t_revoke_unknown_app},
    {"gds.cm.check_good", "12 §7.9.11", "CheckRevocationStatus reports Good for a valid certificate",
     true, false, t_check_good},
    {"gds.cm.check_revoked", "12 §7.9.11", "CheckRevocationStatus reports a revoked certificate",
     true, false, t_check_revoked},
    {"gds.cm.check_bad_signature", "12 §7.9.11", "CheckRevocationStatus verifies the certificate signature",
     true, false, t_check_bad_signature},
};
const size_t spec_revoke_count = GDS_ARRAY_SIZE(spec_revoke_tests);
