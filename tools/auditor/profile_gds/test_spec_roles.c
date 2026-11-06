/* OpenGDS spec tests: roles, privileges and channel security of the
 * Directory and CertificateManager methods (OPC 10000-12 §6.2, §7.2 and the
 * per-method access rules of §6.5, §7.8.2, §7.9).
 * The "outsider" is a session with the Auditor's application certificate and
 * no user: it holds no Role and is not the application it acts on, so every
 * call below must be refused. A GDS that refuses anonymous sessions passes
 * those tests outright.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_highlevel.h>
#include <open62541/nodeids_gds.h>

#include <string.h>

#include "common/limits.h"
#include "gds_tl.h"
#include "spec_tests.h"
#include "common/banned.h"

#define URI_LEN    (GDS_MAX_APPLICATION_URI + 1)
#define GDS_NS_URI "http://opcfoundation.org/UA/GDS/"

/* An application registered and certified by the admin, and an outsider session */
typedef struct {
    char uri[URI_LEN];
    UA_NodeId id;
    gds_buf cert, issuer;
    UA_Client *out;
    UA_UInt16 ns;
} victim;

/* false: verdict recorded (setup problem, or the outsider was refused a session) */
static bool setup(ga_ctx *ctx, gds_target *t, victim *v, bool certify) {
    memset(v, 0, sizeof(*v));
    UA_StatusCode r = gt_session(t);
    if(r == UA_STATUSCODE_GOOD)
        r = certify ? gt_issue(t, ctx, v->uri, sizeof(v->uri), &v->id, &v->cert, &v->issuer)
                    : gt_register(t, UA_APPLICATIONTYPE_CLIENT, v->uri, sizeof(v->uri), &v->id);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: admin register%s -> %s", certify ? " and sign" : "",
                      UA_StatusCode_name(r));
        return false;
    }
    v->out = gt_anon_session(t, &r);
    if(!v->out) {
        ga_pass(ctx, "a session without a user is refused (%s)", UA_StatusCode_name(r));
        return false;
    }
    r = UA_Client_getNamespaceIndex(v->out, UA_STRING(GDS_NS_URI), &v->ns);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "no GDS namespace: %s", UA_StatusCode_name(r));
        return false;
    }
    return true;
}

static void victim_clear(victim *v) {
    gt_drop(v->out);
    UA_NodeId_clear(&v->id);
    gds_buf_free(&v->cert);
    gds_buf_free(&v->issuer);
}

static UA_StatusCode out_call(victim *v, UA_UInt32 method, size_t inN, const UA_Variant *in) {
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = UA_Client_call(v->out, UA_NODEID_NUMERIC(v->ns, UA_GDSID_DIRECTORY),
                                     UA_NODEID_NUMERIC(v->ns, method), inN, in, &outN, &out);
    gt_free_out(out, outN);
    return r;
}

static void judge(ga_ctx *ctx, UA_StatusCode r, bool optional, const char *what) {
    if(r == UA_STATUSCODE_BADMETHODINVALID || r == UA_STATUSCODE_BADNOTIMPLEMENTED)
        (void)gt_absent(ctx, r, optional, what);
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "%s succeeded for a session without the Role or Privilege", what);
    else if(r == UA_STATUSCODE_BADUSERACCESSDENIED)
        ga_pass(ctx, "%s -> BadUserAccessDenied", what);
    else
        ga_warn(ctx, "%s refused with %s; the spec names BadUserAccessDenied", what,
                UA_StatusCode_name(r));
}

/* DiscoveryAdmin, or ApplicationSelfAdmin for its own record (§6.2) */
static void t_unregister_other(ga_ctx *ctx, void *p) {
    victim v;
    if(setup(ctx, p, &v, false)) {
        UA_Variant in;
        UA_Variant_setScalar(&in, &v.id, &UA_TYPES[UA_TYPES_NODEID]);
        judge(ctx, out_call(&v, UA_GDSID_DIRECTORY_UNREGISTERAPPLICATION, 1, &in), false,
              "UnregisterApplication of another application");
    }
    victim_clear(&v);
}

static void t_update_other(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    victim v;
    if(setup(ctx, t, &v, false)) {
        UA_ApplicationRecordDataType rec;
        UA_LocalizedText name;
        UA_String url;
        gt_record(&rec, v.uri, UA_APPLICATIONTYPE_CLIENT, &name, &url);
        rec.applicationId = v.id;
        rec.productUri = UA_STRING("urn:opengds:auditor:hijacked");
        gt_bind_ns(v.ns);
        UA_Variant in;
        UA_Variant_setScalar(&in, &rec, gt_record_type());
        judge(ctx, out_call(&v, UA_GDSID_DIRECTORY_UPDATEAPPLICATION, 1, &in), false,
              "UpdateApplication of another application");
        gt_bind_ns(t->ns);
    }
    victim_clear(&v);
}

/* ApplicationSelfAdmin covers only the application's own certificate (§7.2) */
static void t_sign_other(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    victim v;
    if(setup(ctx, t, &v, false)) {
        gds_buf key = {0}, csr = {0};
        if(x509_new_rsa_key(2048, &key) != GDS_OK ||
           x509_make_csr(&key, "OpenGDS Auditor test", v.uri, NULL, &csr) != GDS_OK) {
            ga_not_tested(ctx, "could not create a CSR");
        } else {
            UA_NodeId group = UA_NODEID_NUMERIC(v.ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP),
                      type = gt_rsa_type();
            UA_ByteString cb = {csr.len, csr.data};
            UA_Variant in[4];
            UA_Variant_setScalar(&in[0], &v.id, &UA_TYPES[UA_TYPES_NODEID]);
            UA_Variant_setScalar(&in[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
            UA_Variant_setScalar(&in[2], &type, &UA_TYPES[UA_TYPES_NODEID]);
            UA_Variant_setScalar(&in[3], &cb, &UA_TYPES[UA_TYPES_BYTESTRING]);
            judge(ctx, out_call(&v, UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST, 4, in), false,
                  "StartSigningRequest for another application");
        }
        gds_buf_free_secret(&key);
        gds_buf_free(&csr);
    }
    victim_clear(&v);
}

static void t_get_certificates_other(ga_ctx *ctx, void *p) {
    victim v;
    if(setup(ctx, p, &v, true)) {
        UA_NodeId nullId = UA_NODEID_NULL;
        UA_Variant in[2];
        UA_Variant_setScalar(&in[0], &v.id, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&in[1], &nullId, &UA_TYPES[UA_TYPES_NODEID]);
        judge(ctx, out_call(&v, UA_GDSID_DIRECTORY_GETCERTIFICATES, 2, in), true,
              "GetCertificates of another application");
    }
    victim_clear(&v);
}

/* CertificateAuthorityAdmin only (§7.9.6) */
static void t_revoke_needs_ca_admin(ga_ctx *ctx, void *p) {
    victim v;
    if(setup(ctx, p, &v, true)) {
        UA_ByteString cb = {v.cert.len, v.cert.data};
        UA_Variant in[2];
        UA_Variant_setScalar(&in[0], &v.id, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&in[1], &cb, &UA_TYPES[UA_TYPES_BYTESTRING]);
        judge(ctx, out_call(&v, UA_GDSID_DIRECTORY_REVOKECERTIFICATE, 2, in), true,
              "RevokeCertificate");
    }
    victim_clear(&v);
}

/* AddCertificate: CertificateAuthorityAdmin only (§7.8.2.6, PullManagement) */
static void t_tl_add_needs_ca_admin(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    victim v;
    if(setup(ctx, t, &v, false)) {
        EVP_PKEY *k = EVP_RSA_gen(2048);
        gds_buf cert = {0};
        char uri[URI_LEN];
        gt_unique_uri(t, uri, sizeof(uri));
        if(!k || gtl_make_cert(NULL, NULL, k, "OpenGDS Auditor outsider", uri, false, 7, &cert) !=
                     GDS_OK) {
            ga_not_tested(ctx, "setup: test certificate");
        } else {
            UA_NodeId tl = UA_NODEID_NUMERIC(v.ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST);
            UA_StatusCode r = gtl_add(v.out, tl, &cert, true);
            judge(ctx, r, false, "TrustList AddCertificate");
            char tp[X509_THUMBPRINT_LEN];
            if(r == UA_STATUSCODE_GOOD && x509_thumbprint(&cert, tp) == GDS_OK &&
               gtl_remove_thumb(t->client, gtl_default(t), tp, true) != UA_STATUSCODE_GOOD)
                ga_note(ctx, "could not remove the certificate again");
        }
        EVP_PKEY_free(k);
        gds_buf_free(&cert);
    }
    victim_clear(&v);
}

/* Methods that carry or create key material need an encrypted channel */
static void sign_only_case(ga_ctx *ctx, gds_target *t, bool keyPair) {
    char uri[URI_LEN];
    UA_NodeId id;
    UA_StatusCode r = gt_session(t);
    if(r == UA_STATUSCODE_GOOD)
        r = gt_register(t, UA_APPLICATIONTYPE_CLIENT, uri, sizeof(uri), &id);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: RegisterApplication -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_Client *c = gt_sign_only_session(t, &r);
    if(!c) {
        ga_pass(ctx, "no Sign-only session possible (%s): requests are always encrypted",
                UA_StatusCode_name(r));
        UA_NodeId_clear(&id);
        return;
    }
    UA_UInt16 ns = 0;
    r = UA_Client_getNamespaceIndex(c, UA_STRING(GDS_NS_URI), &ns);
    UA_NodeId group = UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP),
              type = gt_rsa_type();
    gds_buf key = {0}, csr = {0};
    size_t outN = 0;
    UA_Variant *out = NULL;
    if(r == UA_STATUSCODE_GOOD && keyPair) {
        UA_String subject = UA_STRING_NULL, fmt = UA_STRING("PFX"), pw = UA_STRING("x");
        UA_Variant in[7];
        UA_Variant_setScalar(&in[0], &id, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&in[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&in[2], &type, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&in[3], &subject, &UA_TYPES[UA_TYPES_STRING]);
        UA_Variant_setArray(&in[4], UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_STRING]);
        UA_Variant_setScalar(&in[5], &fmt, &UA_TYPES[UA_TYPES_STRING]);
        UA_Variant_setScalar(&in[6], &pw, &UA_TYPES[UA_TYPES_STRING]);
        r = UA_Client_call(c, UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY),
                           UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_STARTNEWKEYPAIRREQUEST), 7, in,
                           &outN, &out);
    } else if(r == UA_STATUSCODE_GOOD) {
        if(x509_new_rsa_key(2048, &key) != GDS_OK ||
           x509_make_csr(&key, "OpenGDS Auditor test", uri, NULL, &csr) != GDS_OK) {
            r = UA_STATUSCODE_BADINTERNALERROR;
        } else {
            UA_ByteString cb = {csr.len, csr.data};
            UA_Variant in[4];
            UA_Variant_setScalar(&in[0], &id, &UA_TYPES[UA_TYPES_NODEID]);
            UA_Variant_setScalar(&in[1], &group, &UA_TYPES[UA_TYPES_NODEID]);
            UA_Variant_setScalar(&in[2], &type, &UA_TYPES[UA_TYPES_NODEID]);
            UA_Variant_setScalar(&in[3], &cb, &UA_TYPES[UA_TYPES_BYTESTRING]);
            r = UA_Client_call(c, UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY),
                               UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST), 4,
                               in, &outN, &out);
        }
    }
    gt_free_out(out, outN);
    const char *what = keyPair ? "StartNewKeyPairRequest" : "StartSigningRequest";
    if(r == UA_STATUSCODE_BADMETHODINVALID || r == UA_STATUSCODE_BADNOTIMPLEMENTED)
        (void)gt_absent(ctx, r, false, what);
    else if(r == UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT)
        ga_pass(ctx, "%s over Sign-only -> BadSecurityModeInsufficient", what);
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "%s accepted over a Sign-only SecureChannel", what);
    else
        ga_warn(ctx, "%s over Sign-only refused with %s; the spec names "
                     "BadSecurityModeInsufficient", what, UA_StatusCode_name(r));
    gds_buf_free_secret(&key);
    gds_buf_free(&csr);
    gt_drop(c);
    UA_NodeId_clear(&id);
}

static void t_sign_sign_only(ga_ctx *ctx, void *p) {
    sign_only_case(ctx, p, false);
}

static void t_keypair_sign_only(ga_ctx *ctx, void *p) {
    sign_only_case(ctx, p, true);
}

const ga_test spec_roles_tests[] = {
    {"gds.acc.unregister_other", "12 §6.2, §6.5.8", "UnregisterApplication of another application needs DiscoveryAdmin",
     true, false, t_unregister_other},
    {"gds.acc.update_other", "12 §6.2, §6.5.7", "UpdateApplication of another application needs DiscoveryAdmin",
     true, false, t_update_other},
    {"gds.acc.sign_other", "12 §7.2, §7.9.3", "ApplicationSelfAdmin does not cover another application's certificate",
     true, false, t_sign_other},
    {"gds.acc.get_certificates_other", "12 §7.2, §7.9.8", "GetCertificates of another application is refused",
     true, false, t_get_certificates_other},
    {"gds.acc.revoke_needs_ca_admin", "12 §7.2, §7.9.6", "RevokeCertificate needs CertificateAuthorityAdmin",
     true, false, t_revoke_needs_ca_admin},
    {"gds.acc.tl_add_needs_ca_admin", "12 §7.2, §7.8.2.6", "TrustList AddCertificate needs CertificateAuthorityAdmin",
     true, false, t_tl_add_needs_ca_admin},
    {"gds.acc.sign_sign_only", "12 §7.9.3", "StartSigningRequest is refused over a SecureChannel that is not encrypted",
     true, false, t_sign_sign_only},
    {"gds.acc.keypair_sign_only", "12 §7.9.4", "StartNewKeyPairRequest is refused over a SecureChannel that is not encrypted",
     true, false, t_keypair_sign_only},
};
const size_t spec_roles_count = GDS_ARRAY_SIZE(spec_roles_tests);
