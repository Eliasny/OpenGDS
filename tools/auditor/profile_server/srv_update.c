/* OpenGDS Auditor server profile: certificate update (srv_update.c).
 * ConformanceUnit: Push Model for Global Certificate and TrustList Management.
 * Catalogue: docs/auditor/server-profile.md, "Certificate update".
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_highlevel.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "srv_target.h"
#include "srv_tests.h"
#include "x509util.h"
#include "common/banned.h"

/* SRV-UPD-01 (12 §7.10.5): UpdateCertificate(DefaultApplicationGroup, type,
 * t-good). t-good is issued by the test CA for the target's ApplicationUri
 * and the key of its CSR (RegeneratePrivateKey FALSE). The change stays
 * queued in the admin session for SRV-TXN-03. */
static void t_update_valid(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->tlPushed) {
        ga_not_tested(ctx, "builds on SRV-TL-02 (the test CA must be in the applied trust list)");
        return;
    }
    UA_StatusCode r = st_learn(t, ctx);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: ApplicationUri and CertificateTypes -> %s", UA_StatusCode_name(r));
        return;
    }
    gds_buf csr = {0};
    if((r = st_csr(t, t->client, false, NULL, &csr)) != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: CreateSigningRequest -> %s (SRV-CSR-01 checks it)",
                      UA_StatusCode_name(r));
        return;
    }
    gds_buf_free(&t->tGood);
    gds_status gs = testca_sign_csr(&t->ca, &csr, t->targetUri, TESTCA_MAX_DAYS, &t->tGood);
    gds_buf_free(&csr);
    if(gs != GDS_OK) {
        ga_not_tested(ctx, "setup: the test CA cannot sign the target's CSR: %s",
                      gds_status_name(gs));
        return;
    }
    bool acr = false;
    r = st_update_cert(t, t->client, &t->tGood, &t->caDer, 1, &acr);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "UpdateCertificate refused a valid certificate: %s", UA_StatusCode_name(r));
        return;
    }
    t->certQueued = true;
    bool present = false, txn = false;
    st_supports_transactions(t->client, &present, &txn);
    if(present && txn && !acr) {
        ga_fail(ctx, "SupportsTransactions is TRUE but ApplyChangesRequired is FALSE");
        return;
    }
    char tp[X509_THUMBPRINT_LEN] = "?";
    if(x509_thumbprint(&t->tGood, tp) != GDS_OK)
        tp[0] = '\0';
    ga_pass(ctx, "Good, ApplyChangesRequired %s (SupportsTransactions %s); t-good %s",
            acr ? "TRUE" : "FALSE", present ? (txn ? "TRUE" : "FALSE") : "absent", tp);
}

/* ---------------- SRV-UPD-02 to -08: certificates the target must refuse ----------------
 * They run on the admin session, which holds t-good from SRV-UPD-01: a
 * refused call leaves the transaction as it is (12 §7.10.2). If a target
 * accepts one, t-good is queued again so that SRV-TXN-03 applies a sound
 * certificate. */

#define WRONG_URI "urn:opengds:auditor:not-the-target"

static bool queued_or_not_tested(ga_ctx *ctx, srv_target *t) {
    if(!t->certQueued || !t->client) {
        ga_not_tested(ctx, "builds on SRV-UPD-01 (t-good queued, the test CA trusted)");
        return false;
    }
    return true;
}

static void requeue(ga_ctx *ctx, srv_target *t) {
    bool acr = false;
    UA_StatusCode r = st_update_cert(t, t->client, &t->tGood, &t->caDer, 1, &acr);
    if(r != UA_STATUSCODE_GOOD)
        ga_note(ctx, "queueing t-good again -> %s", UA_StatusCode_name(r));
}

/* The verdict for a call that must be refused. good: the codes that pass
 * (n of them, 0: any Bad code passes). */
static void expect_refused(ga_ctx *ctx, srv_target *t, UA_StatusCode r, const char *what,
                           const UA_StatusCode *good, size_t n) {
    if(r == UA_STATUSCODE_GOOD) {
        requeue(ctx, t);
        ga_fail(ctx, "UpdateCertificate accepted %s", what);
        return;
    }
    bool listed = n == 0;
    for(size_t i = 0; i < n && !listed; i++)
        listed = r == good[i];
    if(listed)
        ga_pass(ctx, "%s refused: %s", what, UA_StatusCode_name(r));
    else
        ga_warn(ctx, "%s refused with %s, not the expected code", what, UA_StatusCode_name(r));
}

/* A CSR for the active key (RegeneratePrivateKey FALSE) */
static UA_StatusCode active_csr(srv_target *t, gds_buf *csr) {
    return st_csr(t, t->client, false, NULL, csr);
}

static void t_update_wrong_key(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!queued_or_not_tested(ctx, t))
        return;
    gds_buf cert = {0}, key = {0};
    gds_status gs = testca_issue(&t->ca, "t-wrongkey", t->targetUri, "localhost", TESTCA_MAX_DAYS,
                                 &cert, &key);
    gds_buf_free_secret(&key);
    if(gs != GDS_OK) {
        ga_not_tested(ctx, "setup: t-wrongkey: %s", gds_status_name(gs));
        return;
    }
    bool acr = false;
    UA_StatusCode r = st_update_cert(t, t->client, &cert, &t->caDer, 1, &acr);
    gds_buf_free(&cert);
    expect_refused(ctx, t, r, "t-wrongkey (a key the target does not hold)", NULL, 0);
}

static void t_update_wrong_uri(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!queued_or_not_tested(ctx, t))
        return;
    gds_buf csr = {0}, cert = {0};
    UA_StatusCode r = active_csr(t, &csr);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_status_to_ua(testca_sign_csr(&t->ca, &csr, WRONG_URI, TESTCA_MAX_DAYS, &cert));
    gds_buf_free(&csr);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: t-wronguri -> %s", UA_StatusCode_name(r));
        return;
    }
    bool acr = false;
    r = st_update_cert(t, t->client, &cert, &t->caDer, 1, &acr);
    gds_buf_free(&cert);
    if(r == UA_STATUSCODE_GOOD) {
        /* Decision D3: Fail only after a UA-.NETStandard reference run confirms
         * the reading (§7.10.5 does not ask for the check, Part 6 §6.2.2 does);
         * until then an accepted certificate is a Warn. */
        requeue(ctx, t);
        ga_warn(ctx, "UpdateCertificate accepted t-wronguri (SAN URI " WRONG_URI "): the target "
                     "would present a certificate that breaks Part 6 §6.2.2 (Fail once the "
                     "reference run of decision D3 confirms)");
        return;
    }
    static const UA_StatusCode ok[] = {UA_STATUSCODE_BADCERTIFICATEURIINVALID,
                                       UA_STATUSCODE_BADCERTIFICATEINVALID};
    expect_refused(ctx, t, r, "t-wronguri (SAN URI " WRONG_URI ")", ok, GDS_ARRAY_SIZE(ok));
}

/* ca2: a CA the target does not trust, only passed in IssuerCertificates */
static void t_update_issuer_arg(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!queued_or_not_tested(ctx, t))
        return;
    testca_t ca2 = {0};
    gds_buf ca2Der = {0}, csr = {0}, cert = {0};
    ca2.key = EVP_RSA_gen(2048);
    gds_status gs = ca2.key ? st_make_cert(NULL, ca2.key, TESTCA_ORG " ca2", -3600, 7 * 86400L,
                                           true, 0, &ca2Der)
                            : GDS_ECRYPTO;
    if(gs == GDS_OK && !(ca2.cert = x509_parse_cert(&ca2Der)))
        gs = GDS_ECRYPTO;
    UA_StatusCode r = gds_status_to_ua(gs);
    if(r == UA_STATUSCODE_GOOD)
        r = active_csr(t, &csr);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_status_to_ua(testca_sign_csr(&ca2, &csr, t->targetUri, TESTCA_MAX_DAYS, &cert));
    gds_buf_free(&csr);
    if(r == UA_STATUSCODE_GOOD) {
        bool acr = false;
        r = st_update_cert(t, t->client, &cert, &ca2Der, 1, &acr);
        expect_refused(ctx, t, r, "a certificate from ca2 with ca2 only in IssuerCertificates",
                       NULL, 0);
    } else
        ga_not_tested(ctx, "setup: ca2 and its certificate -> %s", UA_StatusCode_name(r));
    gds_buf_free(&cert);
    gds_buf_free(&ca2Der);
    testca_free(&ca2);
}

static void t_update_bad_sig(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!queued_or_not_tested(ctx, t))
        return;
    gds_buf cert = {0};
    UA_StatusCode r = gds_status_to_ua(gds_buf_dup(t->tGood.data, t->tGood.len, &cert));
    if(r != UA_STATUSCODE_GOOD || cert.len < 16) {
        gds_buf_free(&cert);
        ga_not_tested(ctx, "setup: t-badsig -> %s", UA_StatusCode_name(r));
        return;
    }
    cert.data[cert.len - 1] ^= 0x01; /* last byte of the signature value */
    bool acr = false;
    r = st_update_cert(t, t->client, &cert, &t->caDer, 1, &acr);
    gds_buf_free(&cert);
    static const UA_StatusCode ok[] = {UA_STATUSCODE_BADCERTIFICATEINVALID,
                                       UA_STATUSCODE_BADSECURITYCHECKSFAILED};
    expect_refused(ctx, t, r, "t-badsig (t-good with one signature bit flipped)", ok,
                   GDS_ARRAY_SIZE(ok));
}

static void t_update_any_type(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!queued_or_not_tested(ctx, t))
        return;
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode r = UA_Client_readValueAttribute(
        t->client,
        UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_CERTIFICATETYPES),
        &v);
    static const UA_UInt32 cand[] = {UA_NS0ID_RSAMINAPPLICATIONCERTIFICATETYPE,
                                     UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE,
                                     UA_NS0ID_ECCNISTP256APPLICATIONCERTIFICATETYPE};
    UA_NodeId type = UA_NODEID_NULL;
    bool isArr = r == UA_STATUSCODE_GOOD && UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_NODEID]);
    for(size_t i = 0; isArr && UA_NodeId_isNull(&type) && i < GDS_ARRAY_SIZE(cand); i++) {
        UA_NodeId c = UA_NODEID_NUMERIC(0, cand[i]);
        bool listed = false;
        for(size_t k = 0; k < v.arrayLength && !listed; k++)
            listed = UA_NodeId_equal(&((const UA_NodeId *)v.data)[k], &c);
        if(!listed)
            type = c;
    }
    UA_Variant_clear(&v);
    if(UA_NodeId_isNull(&type)) {
        ga_not_tested(ctx, "setup: no CertificateTypeId outside the group's CertificateTypes (%s)",
                      UA_StatusCode_name(r));
        return;
    }
    bool acr = false;
    r = st_update_cert_as(t->client, type, &t->tGood, &acr);
    static const UA_StatusCode ok[] = {UA_STATUSCODE_BADINVALIDARGUMENT};
    expect_refused(ctx, t, r, "t-good under a CertificateTypeId the group does not list", ok, 1);
}

static void t_update_ecc(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!queued_or_not_tested(ctx, t))
        return;
    EVP_PKEY *k = EVP_EC_gen("P-256");
    gds_buf cert = {0};
    gds_status gs = k ? st_make_leaf(&t->ca, k, "t-ecc", t->targetUri, -3600, 7 * 86400L, false, 0,
                                     &cert)
                      : GDS_ECRYPTO;
    EVP_PKEY_free(k);
    if(gs != GDS_OK) {
        ga_not_tested(ctx, "setup: t-ecc: %s", gds_status_name(gs));
        return;
    }
    bool acr = false;
    UA_StatusCode r = st_update_cert(t, t->client, &cert, &t->caDer, 1, &acr);
    gds_buf_free(&cert);
    static const UA_StatusCode ok[] = {UA_STATUSCODE_BADCERTIFICATEINVALID};
    expect_refused(ctx, t, r, "t-ecc (NIST P-256) into the RSA slot", ok, 1);
}

static void t_update_expired(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!queued_or_not_tested(ctx, t))
        return;
    gds_buf csr = {0}, cert = {0};
    UA_StatusCode r = active_csr(t, &csr);
    const unsigned char *d = csr.data;
    X509_REQ *req = r == UA_STATUSCODE_GOOD && csr.len <= GDS_MAX_CSR_SIZE
                        ? d2i_X509_REQ(NULL, &d, (long)csr.len)
                        : NULL;
    EVP_PKEY *pub = req ? X509_REQ_get0_pubkey(req) : NULL;
    gds_status gs = pub ? st_make_leaf(&t->ca, pub, "t-expired", t->targetUri, -10 * 86400L,
                                       -86400L, false, 0, &cert)
                        : GDS_EINVAL;
    X509_REQ_free(req);
    gds_buf_free(&csr);
    ERR_clear_error();
    if(gs != GDS_OK) {
        ga_not_tested(ctx, "setup: t-expired (%s): %s", UA_StatusCode_name(r), gds_status_name(gs));
        return;
    }
    bool acr = false;
    r = st_update_cert(t, t->client, &cert, &t->caDer, 1, &acr);
    gds_buf_free(&cert);
    expect_refused(ctx, t, r, "t-expired (valid until yesterday)", NULL, 0);
}

const ga_test srv_update_tests[] = {
    {"SRV-UPD-01", "12 §7.10.5", "UpdateCertificate accepts a valid CA-issued certificate", true,
     false, t_update_valid},
    {"SRV-UPD-02", "12 §7.10.5", "A certificate for an unknown key is refused", true, false,
     t_update_wrong_key},
    {"SRV-UPD-03", "12 §7.10.5; 6 §6.2.2; 4 §6.1.3", "A SAN URI other than the ApplicationUri is refused",
     true, false, t_update_wrong_uri},
    {"SRV-UPD-04", "12 §7.10.5", "IssuerCertificates does not make an issuer trusted", true, false,
     t_update_issuer_arg},
    {"SRV-UPD-05", "12 §7.10.5; 4 §6.1.3", "A certificate with a bad signature is refused", true,
     false, t_update_bad_sig},
    {"SRV-UPD-06", "12 §7.10.5", "A CertificateTypeId outside the group is refused", true, false,
     t_update_any_type},
    {"SRV-UPD-07", "12 §7.10.5", "An ECC certificate is refused for an RSA slot", true, false,
     t_update_ecc},
    {"SRV-UPD-08", "12 §7.10.5; 4 §6.1.3", "An expired certificate is refused", true, false,
     t_update_expired},
};
const size_t srv_update_count = GDS_ARRAY_SIZE(srv_update_tests);
