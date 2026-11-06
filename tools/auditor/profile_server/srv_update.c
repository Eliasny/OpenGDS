/* OpenGDS Auditor server profile: certificate update (srv_update.c).
 * ConformanceUnit: Push Model for Global Certificate and TrustList Management.
 * Catalogue: docs/auditor/server-profile.md, "Certificate update".
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_highlevel.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <string.h>

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
    if(r != UA_STATUSCODE_GOOD) {
        ga_note(ctx, "queueing t-good again -> %s", UA_StatusCode_name(r));
        t->certQueued = false; /* what builds on t-good is not tested */
    }
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

/* The public key of t-good, which is the active key: certificates for it
 * are made without another CreateSigningRequest, so a target whose CSR
 * breaks after an accepted certificate does not take the next tests down. */
static EVP_PKEY *tgood_key(const srv_target *t) {
    X509 *x = x509_parse_cert(&t->tGood);
    EVP_PKEY *k = x ? X509_get_pubkey(x) : NULL;
    X509_free(x);
    ERR_clear_error();
    return k;
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
    /* Without transactions an accepted certificate is in use at once, and a
     * wrong ApplicationUri breaks the rest of the run (and the restore). */
    bool present = false, txn = false;
    st_supports_transactions(t->client, &present, &txn);
    if(!txn) {
        ga_not_tested(ctx, "SupportsTransactions is not TRUE: an accepted t-wronguri would be "
                           "in use at once and break the following tests");
        return;
    }
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
    if(r == UA_STATUSCODE_GOOD) { /* decision D3 */
        requeue(ctx, t);
        ga_fail(ctx, "UpdateCertificate accepted t-wronguri (SAN URI " WRONG_URI "): the target "
                     "would present a certificate that breaks Part 6 §6.2.2, and a URI mismatch "
                     "may not be suppressed (4 §6.1.3 Table 100)");
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
    gds_buf ca2Der = {0}, cert = {0};
    ca2.key = EVP_RSA_gen(2048);
    gds_status gs = ca2.key ? st_make_cert(NULL, ca2.key, TESTCA_ORG " ca2", -3600, 7 * 86400L,
                                           true, 0, &ca2Der)
                            : GDS_ECRYPTO;
    if(gs == GDS_OK && !(ca2.cert = x509_parse_cert(&ca2Der)))
        gs = GDS_ECRYPTO;
    EVP_PKEY *pub = gs == GDS_OK ? tgood_key(t) : NULL;
    if(gs == GDS_OK && !pub)
        gs = GDS_ECRYPTO;
    if(gs == GDS_OK)
        gs = st_make_leaf(&ca2, pub, "t-ca2", t->targetUri, -3600, TESTCA_MAX_DAYS * 86400L,
                          false, 0, &cert);
    EVP_PKEY_free(pub);
    UA_StatusCode r = gds_status_to_ua(gs);
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
    gds_buf cert = {0};
    EVP_PKEY *pub = tgood_key(t);
    gds_status gs = pub ? st_make_leaf(&t->ca, pub, "t-expired", t->targetUri, -10 * 86400L,
                                       -86400L, false, 0, &cert)
                        : GDS_ECRYPTO;
    EVP_PKEY_free(pub);
    if(gs != GDS_OK) {
        ga_not_tested(ctx, "setup: t-expired: %s", gds_status_name(gs));
        return;
    }
    bool acr = false;
    UA_StatusCode r = st_update_cert(t, t->client, &cert, &t->caDer, 1, &acr);
    gds_buf_free(&cert);
    if(r == UA_STATUSCODE_GOOD) { /* decision D2 */
        requeue(ctx, t);
        ga_warn(ctx, "UpdateCertificate accepted t-expired: Validity Period is a suppressible "
                     "error (4 §6.1.3 Table 100), which §7.10.5 lets a server ignore");
        return;
    }
    expect_refused(ctx, t, r, "t-expired (valid until yesterday)", NULL, 0);
}

/* ---------------- SRV-UPD-09, -10: a pushed private key ---------------- */

/* The first SupportedPrivateKeyFormats entry; false (and Not supported) if
 * the array is empty. */
static bool first_key_format(ga_ctx *ctx, srv_target *t, char *fmt, size_t len) {
    UA_StatusCode r = st_learn(t, ctx);
    if(r == UA_STATUSCODE_GOOD)
        r = st_admin(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: ApplicationUri and admin session -> %s", UA_StatusCode_name(r));
        return false;
    }
    UA_Variant v;
    UA_Variant_init(&v);
    r = UA_Client_readValueAttribute(
        t->client, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_SUPPORTEDPRIVATEKEYFORMATS), &v);
    bool any = r == UA_STATUSCODE_GOOD && UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_STRING]) &&
               v.arrayLength > 0;
    if(any) {
        const UA_String *f = v.data;
        (void)snprintf(fmt, len, "%.*s", (int)(f->length < 32 ? f->length : 32), (const char *)f->data);
    } else
        ga_not_supported(ctx, "SupportedPrivateKeyFormats is empty (%s): no private key is pushed",
                         UA_StatusCode_name(r));
    UA_Variant_clear(&v);
    if(any && strcmp(fmt, "PEM") != 0) {
        ga_not_tested(ctx, "the first advertised format is %s; the Auditor sends PEM only", fmt);
        any = false;
    }
    return any;
}

/* The test CA in the applied trust list (as SRV-TL-02 leaves it), for the
 * tests that also run on their own with --only. */
static bool ca_trusted(ga_ctx *ctx, srv_target *t) {
    if(t->tlPushed)
        return true;
    UA_TrustListDataType l;
    UA_TrustListDataType_init(&l);
    bool acr = false;
    UA_StatusCode r = st_snapshot(t, ctx);
    if(r == UA_STATUSCODE_GOOD)
        r = st_list_copy_add(&t->snap, &t->caDer, &t->caCrl, &l);
    if(r == UA_STATUSCODE_GOOD) {
        l.specifiedLists = ST_MASK_ALL;
        r = st_write_trustlist(t->client, &l, 16384, &acr, ctx);
    }
    if(r == UA_STATUSCODE_GOOD && acr)
        r = st_apply(t->client);
    UA_TrustListDataType_clear(&l);
    if(r != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup: trust list with the test CA -> %s", UA_StatusCode_name(r));
    t->tlPushed = r == UA_STATUSCODE_GOOD;
    return t->tlPushed;
}

/* SRV-UPD-09 puts a key the Auditor made in use: the snapshot cannot bring
 * the target's own key back, so it runs only when selected by name
 * (README, "Safety, snapshot and restore"). */
static void t_update_with_key(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    char fmt[40];
    if(!first_key_format(ctx, t, fmt, sizeof(fmt)))
        return;
    if(!t->only || strcmp(t->only, "SRV-UPD-09") != 0) {
        ga_not_tested(ctx, "replaces the target's private key, which the restore step cannot put "
                           "back: runs only with --only SRV-UPD-09");
        return;
    }
    if(!ca_trusted(ctx, t))
        return;
    gds_buf cert = {0}, pem = {0}, seen = {0};
    gds_status gs = st_withkey(t, &cert, &pem);
    if(gs != GDS_OK) {
        ga_not_tested(ctx, "setup: t-withkey: %s", gds_status_name(gs));
        return;
    }
    bool acr = false;
    UA_StatusCode r = st_update_cert_key(t, t->client, &cert, &t->caDer, 1, fmt, &pem, &acr);
    gds_buf_free_secret(&pem);
    if(r != UA_STATUSCODE_GOOD) {
        gds_buf_free(&cert);
        ga_fail(ctx, "UpdateCertificate(t-withkey, %s key) -> %s", fmt, UA_StatusCode_name(r));
        return;
    }
    t->keyReplaced = true; /* from here the restore cannot bring the old key back */
    if(acr && (r = st_apply(t->client)) != UA_STATUSCODE_GOOD) {
        gds_buf_free(&cert);
        ga_fail(ctx, "ApplyChanges -> %s", UA_StatusCode_name(r));
        return;
    }
    st_close(t);
    UA_Client *c = NULL;
    r = st_presented(t, &seen);
    bool presents = r == UA_STATUSCODE_GOOD && seen.len == cert.len &&
                    memcmp(seen.data, cert.data, cert.len) == 0;
    UA_StatusCode h = presents ? st_admin_fresh(t, false, &c) : UA_STATUSCODE_BADINVALIDSTATE;
    st_client_free(c);
    gds_buf_free(&seen);
    gds_buf_free(&cert);
    if(!presents)
        ga_fail(ctx, "after ApplyChanges the endpoint does not present t-withkey (%s)",
                UA_StatusCode_name(r));
    else if(h != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "the endpoint presents t-withkey but the handshake fails: %s",
                UA_StatusCode_name(h));
    else
        ga_pass(ctx, "t-withkey with its %s key in use; a session that trusts only the test CA "
                     "connects",
                fmt);
}

static void t_update_bad_key(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    char fmt[40];
    if(!first_key_format(ctx, t, fmt, sizeof(fmt)) || !ca_trusted(ctx, t))
        return;
    gds_buf cert = {0}, pem = {0}, other = {0}, otherPem = {0};
    gds_status gs = st_withkey(t, &cert, &pem);
    if(gs == GDS_OK)
        gs = st_withkey(t, &other, &otherPem);
    gds_buf_free_secret(&pem);
    gds_buf_free(&other);
    if(gs != GDS_OK) {
        gds_buf_free(&cert);
        gds_buf_free_secret(&otherPem);
        ga_not_tested(ctx, "setup: two t-withkey certificates: %s", gds_status_name(gs));
        return;
    }
    bool acr = false;
    UA_StatusCode r = st_update_cert_key(t, t->client, &cert, &t->caDer, 1, fmt, &otherPem, &acr);
    gds_buf_free_secret(&otherPem);
    gds_buf_free(&cert);
    if(r == UA_STATUSCODE_GOOD) {
        if(t->certQueued)
            requeue(ctx, t);
        else
            st_close(t); /* discards what was queued (12 §7.10.2) */
        ga_fail(ctx, "UpdateCertificate accepted a %s private key of another certificate", fmt);
    } else if(r == UA_STATUSCODE_BADNOTSUPPORTED)
        ga_pass(ctx, "a private key that does not match -> Bad_NotSupported");
    else
        ga_warn(ctx, "a private key that does not match refused with %s (Bad_NotSupported "
                     "expected)",
                UA_StatusCode_name(r));
}

/* ---------------- SRV-UPD-11 to -13: optional ServerConfiguration Methods ---------------- */

/* The Method `name` of ServerConfiguration; Not supported if absent. */
static bool optional_method(ga_ctx *ctx, srv_target *t, const char *name, UA_NodeId *m) {
    UA_StatusCode r = st_admin(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: admin session -> %s", UA_StatusCode_name(r));
        return false;
    }
    r = uac_find_child(t->client, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION), name, m);
    if(r != UA_STATUSCODE_GOOD) {
        UA_NodeId_clear(m);
        ga_not_supported(ctx, "ServerConfiguration has no %s (Optional, 12 §7.10.3)", name);
        return false;
    }
    return true;
}

static UA_NodeId dag(void) {
    return UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
}

static bool same_cert(const UA_ByteString *a, const gds_buf *b) {
    return a->length == b->len && b->len > 0 && memcmp(a->data, b->data, b->len) == 0;
}

static void t_update_get_certs(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    UA_NodeId m;
    if(!optional_method(ctx, t, "GetCertificates", &m))
        return;
    gds_buf cur = {0};
    UA_StatusCode r = st_presented(t, &cur);
    UA_NodeId g = dag();
    UA_Variant in;
    UA_Variant_setScalar(&in, &g, &UA_TYPES[UA_TYPES_NODEID]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Client_call(t->client, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION), m, 1, &in,
                           &outN, &out);
    UA_NodeId_clear(&m);
    bool shape = r == UA_STATUSCODE_GOOD && outN == 2 &&
                 UA_Variant_hasArrayType(&out[0], &UA_TYPES[UA_TYPES_NODEID]) &&
                 UA_Variant_hasArrayType(&out[1], &UA_TYPES[UA_TYPES_BYTESTRING]);
    bool found = false;
    for(size_t i = 0; shape && i < out[1].arrayLength && !found; i++)
        found = same_cert(&((const UA_ByteString *)out[1].data)[i], &cur);
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "GetCertificates(DefaultApplicationGroup) -> %s", UA_StatusCode_name(r));
    else if(!shape)
        ga_fail(ctx, "GetCertificates returned %zu outputs, not NodeId[] and ByteString[]", outN);
    else if(out[0].arrayLength != out[1].arrayLength)
        ga_fail(ctx, "%zu CertificateTypeIds but %zu Certificates", out[0].arrayLength,
                out[1].arrayLength);
    else if(!found)
        ga_fail(ctx, "the certificate the endpoint presents is not among the %zu returned",
                out[1].arrayLength);
    else
        ga_pass(ctx, "%zu type(s) and certificate(s), the presented certificate included",
                out[1].arrayLength);
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    gds_buf_free(&cur);
}

/* A call that must be refused with Bad_InvalidState on the admin session;
 * a Good on a queued transaction gets t-good queued again. */
static void expect_invalid_state(ga_ctx *ctx, srv_target *t, const char *name, size_t inN,
                                 const UA_Variant *in) {
    UA_NodeId m;
    if(!optional_method(ctx, t, name, &m))
        return;
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = UA_Client_call(t->client, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION),
                                     m, inN, in, &outN, &out);
    UA_NodeId_clear(&m);
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    if(r == UA_STATUSCODE_GOOD) {
        if(t->certQueued)
            requeue(ctx, t);
        ga_fail(ctx, "%s on the occupied DefaultApplicationGroup slot in use -> Good", name);
    } else if(r == UA_STATUSCODE_BADINVALIDSTATE)
        ga_pass(ctx, "%s -> Bad_InvalidState", name);
    else
        ga_warn(ctx, "%s refused with %s (Bad_InvalidState expected)", name, UA_StatusCode_name(r));
}

static void t_update_self_signed(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    UA_NodeId g = dag(), type = t->certType;
    if(UA_NodeId_isNull(&type) && st_learn(t, ctx) == UA_STATUSCODE_GOOD)
        type = t->certType;
    UA_String subject = UA_STRING_NULL;
    UA_UInt16 days = TESTCA_MAX_DAYS, bits = 2048;
    UA_Variant in[6];
    UA_Variant_setScalar(&in[0], &g, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &type, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &subject, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setArray(&in[3], UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[4], &days, &UA_TYPES[UA_TYPES_UINT16]);
    UA_Variant_setScalar(&in[5], &bits, &UA_TYPES[UA_TYPES_UINT16]);
    expect_invalid_state(ctx, t, "CreateSelfSignedCertificate", 6, in);
}

static void t_update_delete_in_use(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    UA_NodeId g = dag(), type = t->certType;
    if(UA_NodeId_isNull(&type) && st_learn(t, ctx) == UA_STATUSCODE_GOOD)
        type = t->certType;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &g, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &type, &UA_TYPES[UA_TYPES_NODEID]);
    expect_invalid_state(ctx, t, "DeleteCertificate", 2, in);
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
    {"SRV-UPD-09", "12 §7.10.5", "A pushed private key is put in use with its certificate", true,
     false, t_update_with_key},
    {"SRV-UPD-10", "12 §7.10.5", "A private key of another certificate is refused", true, false,
     t_update_bad_key},
    {"SRV-UPD-11", "12 §7.10.8", "GetCertificates matches the presented certificate", false,
     false, t_update_get_certs},
    {"SRV-UPD-12", "12 §7.10.6", "CreateSelfSignedCertificate refuses an occupied slot", true,
     false, t_update_self_signed},
    {"SRV-UPD-13", "12 §7.10.7", "DeleteCertificate refuses the certificate in use", true, false,
     t_update_delete_in_use},
};
const size_t srv_update_count = GDS_ARRAY_SIZE(srv_update_tests);
