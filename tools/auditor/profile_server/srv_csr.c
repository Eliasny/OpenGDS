/* OpenGDS Auditor server profile: signing request (srv_csr.c).
 * ConformanceUnit: Push Model for Global Certificate and TrustList Management.
 * Catalogue: docs/auditor/server-profile.md, "Signing request".
 *
 * CreateSigningRequest changes no certificate in use, but RegeneratePrivateKey
 * makes the target keep a new key pair (12 §7.10.10). Those calls run on their
 * own admin session, closed afterwards; the next CreateSigningRequest of the
 * run (SRV-UPD-01, RegeneratePrivateKey FALSE) discards the new key pair.
 * SRV-CSR-06 and -07 queue a certificate for a new key pair and run only
 * where SupportsTransactions is TRUE, so that closing the session discards it
 * (§7.10.2) instead of putting a key in use that the restore step cannot put
 * back.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_highlevel.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <string.h>

#include "srv_target.h"
#include "srv_tests.h"
#include "x509util.h"
#include "common/banned.h"

#define GOOD_NONCE 32 /* "at least 32 bytes" (§7.10.10) */
#define SHORT_NONCE 16

static UA_NodeId ns0(UA_UInt32 id) {
    return UA_NODEID_NUMERIC(0, id);
}

/* st_learn, the admin session and the certificate the endpoint presents */
static bool setup(ga_ctx *ctx, srv_target *t, gds_buf *presented) {
    presented->data = NULL;
    presented->len = 0;
    UA_StatusCode r = st_learn(t, ctx);
    if(r == UA_STATUSCODE_GOOD && (r = st_admin(t)) == UA_STATUSCODE_GOOD)
        r = st_presented(t, presented);
    if(r != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup: ApplicationUri, admin session and endpoint certificate -> %s",
                      UA_StatusCode_name(r));
    return r == UA_STATUSCODE_GOOD;
}

static X509_REQ *parse_req(const gds_buf *csr) {
    if(!csr->data || csr->len == 0 || csr->len > GDS_MAX_CSR_SIZE)
        return NULL;
    const unsigned char *p = csr->data;
    X509_REQ *req = d2i_X509_REQ(NULL, &p, (long)csr->len);
    if(req && p != csr->data + csr->len) { /* trailing bytes */
        X509_REQ_free(req);
        req = NULL;
    }
    ERR_clear_error();
    return req;
}

static UA_StatusCode nonce_of(size_t len, UA_Byte *buf, UA_ByteString *out) {
    out->data = buf;
    out->length = len;
    if(RAND_bytes(buf, (int)len) != 1) {
        ERR_clear_error();
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    return UA_STATUSCODE_GOOD;
}

/* A CSR on its own admin session (closed here). */
static UA_StatusCode csr_fresh(const srv_target *t, bool regen, size_t nonceLen, gds_buf *csr) {
    csr->data = NULL;
    csr->len = 0;
    UA_Byte buf[GOOD_NONCE];
    UA_ByteString nonce = UA_BYTESTRING_NULL;
    UA_StatusCode r = nonceLen ? nonce_of(nonceLen, buf, &nonce) : UA_STATUSCODE_GOOD;
    UA_Client *c = NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = st_admin_fresh(t, true, &c);
    if(r == UA_STATUSCODE_GOOD)
        r = st_csr(t, c, regen, nonceLen ? &nonce : NULL, csr);
    st_client_free(c);
    return r;
}

/* ---------------- SRV-CSR-01 ---------------- */

static void t_csr_active(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    gds_buf cur;
    if(!setup(ctx, t, &cur))
        return;
    gds_buf csr = {0};
    UA_StatusCode r = st_csr(t, t->client, false, NULL, &csr);
    X509_REQ *req = r == UA_STATUSCODE_GOOD ? parse_req(&csr) : NULL;
    EVP_PKEY *k = req ? X509_REQ_get0_pubkey(req) : NULL;
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "CreateSigningRequest(RegeneratePrivateKey FALSE) -> %s", UA_StatusCode_name(r));
    else if(!req)
        ga_fail(ctx, "the result is not a DER PKCS #10 request (%zu bytes)", csr.len);
    else if(!k || X509_REQ_verify(req, k) != 1)
        ga_fail(ctx, "the request's signature does not verify with its own public key");
    else if(!x509_cert_has_csr_key(&cur, &csr))
        ga_fail(ctx, "the request carries another key than the certificate the endpoint presents");
    else
        ga_pass(ctx, "DER PKCS #10 request, signature verifies, key of the presented certificate");
    ERR_clear_error();
    X509_REQ_free(req);
    gds_buf_free(&csr);
    gds_buf_free(&cur);
}

/* ---------------- SRV-CSR-02 ---------------- */

static void name_line(const X509_NAME *n, char *out, size_t len) {
    if(!n || X509_NAME_oneline(n, out, (int)len) == NULL)
        (void)snprintf(out, len, "?");
}

static void t_csr_subject(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    gds_buf cur;
    if(!setup(ctx, t, &cur))
        return;
    gds_buf csr = {0};
    UA_StatusCode r = st_csr(t, t->client, false, NULL, &csr);
    X509_REQ *req = r == UA_STATUSCODE_GOOD ? parse_req(&csr) : NULL;
    X509 *x = x509_parse_cert(&cur);
    if(!req || !x) {
        ga_not_tested(ctx, "setup: no parsable CSR (%s) or endpoint certificate (SRV-CSR-01 checks it)",
                      UA_StatusCode_name(r));
    } else {
        const X509_NAME *a = X509_REQ_get_subject_name(req), *b = X509_get_subject_name(x);
        char sa[256], sb[256];
        name_line(a, sa, sizeof(sa));
        name_line(b, sb, sizeof(sb));
        if(X509_NAME_cmp(a, b) == 0)
            ga_pass(ctx, "CSR subject equals the certificate's: %s", sa);
        else
            ga_fail(ctx, "CSR subject \"%s\", current certificate \"%s\"", sa, sb);
    }
    ERR_clear_error();
    X509_free(x);
    X509_REQ_free(req);
    gds_buf_free(&csr);
    gds_buf_free(&cur);
}

/* ---------------- SRV-CSR-03 ---------------- */

typedef struct {
    size_t uris, dnsOrIp;
    bool uriMatches;
    char firstUri[128];
} san_info;

static void san_count(GENERAL_NAMES *gens, const char *appUri, san_info *s) {
    for(int i = 0; gens && i < sk_GENERAL_NAME_num(gens); i++) {
        const GENERAL_NAME *g = sk_GENERAL_NAME_value(gens, i);
        if(g->type == GEN_DNS || g->type == GEN_IPADD)
            s->dnsOrIp++;
        if(g->type != GEN_URI)
            continue;
        const ASN1_IA5STRING *u = g->d.uniformResourceIdentifier;
        size_t len = (size_t)ASN1_STRING_length(u);
        const unsigned char *d = ASN1_STRING_get0_data(u);
        if(s->uris++ == 0) {
            (void)snprintf(s->firstUri, sizeof(s->firstUri), "%.*s", (int)(len < 120 ? len : 120),
                           (const char *)d);
            s->uriMatches = len == strlen(appUri) && memcmp(d, appUri, len) == 0;
        }
    }
}

static void t_csr_san(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    gds_buf cur;
    if(!setup(ctx, t, &cur))
        return;
    gds_buf csr = {0};
    UA_StatusCode r = st_csr(t, t->client, false, NULL, &csr);
    X509_REQ *req = r == UA_STATUSCODE_GOOD ? parse_req(&csr) : NULL;
    if(!req) {
        ga_not_tested(ctx, "setup: no parsable CSR (%s; SRV-CSR-01 checks it)", UA_StatusCode_name(r));
        gds_buf_free(&csr);
        gds_buf_free(&cur);
        return;
    }
    STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req);
    int idx = exts ? X509v3_get_ext_by_NID(exts, NID_subject_alt_name, -1) : -1;
    GENERAL_NAMES *gens =
        idx >= 0 ? X509V3_EXT_d2i(sk_X509_EXTENSION_value(exts, idx)) : NULL;
    san_info s = {0};
    san_count(gens, t->targetUri, &s);
    if(s.uris == 0)
        ga_fail(ctx, "the CSR has no subjectAltName URI");
    else if(s.uris > 1)
        ga_fail(ctx, "the CSR has %zu subjectAltName URIs (Part 6 §6.2.2: exactly one)", s.uris);
    else if(!s.uriMatches)
        ga_fail(ctx, "CSR URI \"%s\" differs from the ApplicationUri \"%s\"", s.firstUri,
                t->targetUri);
    else if(s.dnsOrIp == 0)
        ga_warn(ctx, "URI matches but the CSR has no DNS name or IP address");
    else
        ga_pass(ctx, "one URI equal to the ApplicationUri, %zu DNS name(s) or IP address(es)",
                s.dnsOrIp);
    GENERAL_NAMES_free(gens);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    ERR_clear_error();
    X509_REQ_free(req);
    gds_buf_free(&csr);
    gds_buf_free(&cur);
}

/* ---------------- SRV-CSR-04 ---------------- */

static void t_csr_regen(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    gds_buf cur;
    if(!setup(ctx, t, &cur))
        return;
    gds_buf csr = {0};
    UA_StatusCode r = csr_fresh(t, true, GOOD_NONCE, &csr);
    X509_REQ *req = r == UA_STATUSCODE_GOOD ? parse_req(&csr) : NULL;
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "CreateSigningRequest(RegeneratePrivateKey TRUE, 32-byte Nonce) -> %s",
                UA_StatusCode_name(r));
    else if(!req)
        ga_fail(ctx, "the result is not a DER PKCS #10 request");
    else if(x509_cert_has_csr_key(&cur, &csr))
        ga_fail(ctx, "RegeneratePrivateKey TRUE returned the key of the current certificate");
    else
        ga_pass(ctx, "the CSR carries a new public key");
    X509_REQ_free(req);
    gds_buf_free(&csr);
    gds_buf_free(&cur);
}

/* ---------------- SRV-CSR-05 ---------------- */

static void t_csr_short_nonce(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    gds_buf cur;
    if(!setup(ctx, t, &cur))
        return;
    gds_buf_free(&cur);
    gds_buf csr = {0};
    UA_StatusCode r = csr_fresh(t, true, SHORT_NONCE, &csr);
    gds_buf_free(&csr);
    if(r == UA_STATUSCODE_BADINVALIDARGUMENT)
        ga_pass(ctx, "16-byte Nonce with RegeneratePrivateKey TRUE -> Bad_InvalidArgument");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "16-byte Nonce accepted (§7.10.10: at least 32 bytes)");
    else
        ga_warn(ctx, "16-byte Nonce refused with %s (Bad_InvalidArgument expected)",
                UA_StatusCode_name(r));
}

/* ---------------- SRV-CSR-06, -07 ---------------- */

/* Shared gate: the test CA in the applied trust list (SRV-TL-02) and
 * SupportsTransactions TRUE (see the file comment). */
static bool may_queue(ga_ctx *ctx, srv_target *t) {
    gds_buf cur;
    if(!setup(ctx, t, &cur))
        return false;
    gds_buf_free(&cur);
    if(!t->tlPushed) {
        ga_not_tested(ctx, "builds on SRV-TL-02 (the test CA must be in the applied trust list)");
        return false;
    }
    bool present = false, txn = false;
    st_supports_transactions(t->client, &present, &txn);
    if(!present || !txn)
        ga_not_tested(ctx, "SupportsTransactions is not TRUE: a certificate for a new key pair "
                           "would be in use at once, and the restore step cannot put the old "
                           "key back");
    return present && txn;
}

static UA_StatusCode issue_for(const srv_target *t, const gds_buf *csr, gds_buf *cert) {
    return gds_status_to_ua(testca_sign_csr(&t->ca, csr, t->targetUri, TESTCA_MAX_DAYS, cert));
}

static void t_csr_other_session(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!may_queue(ctx, t))
        return;
    gds_buf csr = {0}, cert = {0};
    UA_StatusCode r = csr_fresh(t, true, GOOD_NONCE, &csr); /* session A, closed */
    if(r == UA_STATUSCODE_GOOD)
        r = issue_for(t, &csr, &cert);
    gds_buf_free(&csr);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: new key pair CSR and its certificate -> %s (SRV-CSR-04 checks it)",
                      UA_StatusCode_name(r));
        return;
    }
    UA_Client *c = NULL;
    if((r = st_admin_fresh(t, true, &c)) != UA_STATUSCODE_GOOD) {
        gds_buf_free(&cert);
        ga_not_tested(ctx, "setup: second admin session -> %s", UA_StatusCode_name(r));
        return;
    }
    bool acr = false;
    r = st_update_cert(t, c, &cert, &t->caDer, 1, &acr);
    st_discard(c); /* the queued certificate goes with the session (§7.10.2) */
    gds_buf_free(&cert);
    if(r == UA_STATUSCODE_GOOD)
        ga_pass(ctx, "a new Session's UpdateCertificate accepted the certificate for the new key");
    else if(r == UA_STATUSCODE_BADTRANSACTIONPENDING)
        ga_not_tested(ctx, "another Session holds a transaction: %s", UA_StatusCode_name(r));
    else
        ga_fail(ctx, "UpdateCertificate on a new Session refused the certificate for the new key "
                     "pair: %s (§7.10.10: usable from another Session)",
                UA_StatusCode_name(r));
}

static void t_csr_discards_old(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!may_queue(ctx, t))
        return;
    UA_Client *c = NULL;
    UA_StatusCode r = st_admin_fresh(t, true, &c);
    UA_Byte buf[GOOD_NONCE];
    UA_ByteString nonce;
    gds_buf first = {0}, second = {0}, cert = {0};
    if(r == UA_STATUSCODE_GOOD)
        r = nonce_of(GOOD_NONCE, buf, &nonce);
    if(r == UA_STATUSCODE_GOOD)
        r = st_csr(t, c, true, &nonce, &first);
    if(r == UA_STATUSCODE_GOOD)
        r = st_csr(t, c, true, &nonce, &second);
    if(r == UA_STATUSCODE_GOOD)
        r = issue_for(t, &first, &cert);
    gds_buf_free(&first);
    gds_buf_free(&second);
    if(r != UA_STATUSCODE_GOOD) {
        st_client_free(c);
        ga_not_tested(ctx, "setup: two new key pair CSRs and a certificate -> %s",
                      UA_StatusCode_name(r));
        return;
    }
    bool acr = false;
    r = st_update_cert(t, c, &cert, &t->caDer, 1, &acr);
    st_discard(c);
    gds_buf_free(&cert);
    if(r == UA_STATUSCODE_BADTRANSACTIONPENDING)
        ga_not_tested(ctx, "another Session holds a transaction: %s", UA_StatusCode_name(r));
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "a certificate for the first new key pair was accepted after a second "
                     "CreateSigningRequest (§7.10.10: the first is discarded)");
    else
        ga_pass(ctx, "certificate for the discarded key pair refused: %s", UA_StatusCode_name(r));
}

/* ---------------- SRV-CSR-08 ---------------- */

static const UA_UInt32 candidates[] = {
    UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE, UA_NS0ID_RSAMINAPPLICATIONCERTIFICATETYPE,
    UA_NS0ID_ECCNISTP256APPLICATIONCERTIFICATETYPE, UA_NS0ID_ECCNISTP384APPLICATIONCERTIFICATETYPE,
    UA_NS0ID_ECCBRAINPOOLP256R1APPLICATIONCERTIFICATETYPE,
    UA_NS0ID_ECCBRAINPOOLP384R1APPLICATIONCERTIFICATETYPE,
    UA_NS0ID_ECCCURVE25519APPLICATIONCERTIFICATETYPE, UA_NS0ID_ECCCURVE448APPLICATIONCERTIFICATETYPE};

/* The first candidate that the DefaultApplicationGroup does not list */
static UA_StatusCode unlisted_type(UA_Client *c, UA_NodeId *out) {
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode r = UA_Client_readValueAttribute(
        c, ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_CERTIFICATETYPES),
        &v);
    if(r == UA_STATUSCODE_GOOD && !UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_NODEID]))
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    const UA_NodeId *types = r == UA_STATUSCODE_GOOD ? v.data : NULL;
    size_t n = r == UA_STATUSCODE_GOOD ? v.arrayLength : 0;
    bool found = false;
    for(size_t i = 0; r == UA_STATUSCODE_GOOD && !found && i < GDS_ARRAY_SIZE(candidates); i++) {
        UA_NodeId cand = ns0(candidates[i]);
        bool listed = false;
        for(size_t k = 0; k < n && !listed; k++)
            listed = UA_NodeId_equal(&types[k], &cand);
        if(!listed) {
            *out = cand;
            found = true;
        }
    }
    UA_Variant_clear(&v);
    if(r == UA_STATUSCODE_GOOD && !found)
        r = UA_STATUSCODE_BADNOTFOUND;
    return r;
}

static void t_csr_unlisted_type(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    gds_buf cur;
    if(!setup(ctx, t, &cur))
        return;
    gds_buf_free(&cur);
    UA_NodeId type;
    UA_StatusCode r = unlisted_type(t->client, &type);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: no CertificateTypeId outside the group's CertificateTypes -> %s",
                      UA_StatusCode_name(r));
        return;
    }
    gds_buf csr = {0};
    r = st_csr_for(t->client,
                   ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP),
                   type, false, NULL, &csr);
    gds_buf_free(&csr);
    if(r == UA_STATUSCODE_BADINVALIDARGUMENT)
        ga_pass(ctx, "ns=0;i=%u (not in CertificateTypes) -> Bad_InvalidArgument",
                (unsigned)type.identifier.numeric);
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "CreateSigningRequest for ns=0;i=%u, which the group does not list, -> Good",
                (unsigned)type.identifier.numeric);
    else
        ga_warn(ctx, "ns=0;i=%u refused with %s (Bad_InvalidArgument expected)",
                (unsigned)type.identifier.numeric, UA_StatusCode_name(r));
}

const ga_test srv_csr_tests[] = {
    {"SRV-CSR-01", "12 §7.10.10", "CSR for the active key pair", true, false, t_csr_active},
    {"SRV-CSR-02", "12 §7.10.10", "CSR subject is the current certificate's", true, false,
     t_csr_subject},
    {"SRV-CSR-03", "12 §7.10.10; 6 §6.2.2", "CSR subjectAltName carries the ApplicationUri", true,
     false, t_csr_san},
    {"SRV-CSR-04", "12 §7.10.10", "RegeneratePrivateKey TRUE makes a new key pair", true, false,
     t_csr_regen},
    {"SRV-CSR-05", "12 §7.10.10", "A Nonce under 32 bytes is refused", true, false,
     t_csr_short_nonce},
    {"SRV-CSR-06", "12 §7.10.10", "The new key pair is usable from another Session", true, false,
     t_csr_other_session},
    {"SRV-CSR-07", "12 §7.10.10", "A second CreateSigningRequest discards the first new key pair",
     true, false, t_csr_discards_old},
    {"SRV-CSR-08", "12 §7.10.10", "A CertificateTypeId outside the group is refused", true, false,
     t_csr_unlisted_type},
};
const size_t srv_csr_count = GDS_ARRAY_SIZE(srv_csr_tests);
