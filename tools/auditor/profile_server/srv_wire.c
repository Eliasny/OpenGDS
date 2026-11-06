/* OpenGDS Auditor server profile: on the wire (srv_wire.c).
 * ConformanceUnit: Push Model for Global Certificate and TrustList Management.
 * Catalogue: docs/auditor/server-profile.md, "On the wire".
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>
#include <time.h>

#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>

#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "srv_target.h"
#include "srv_tests.h"
#include "common/banned.h"

static bool client_has_policy(UA_Client *c, const UA_String *uri) {
    const UA_ClientConfig *cfg = UA_Client_getConfig(c);
    for(size_t i = 0; i < cfg->securityPoliciesSize; i++)
        if(UA_String_equal(&cfg->securityPolicies[i].policyUri, uri))
            return true;
    return false;
}

typedef struct {
    size_t checked, stale, noChannel, other;
    char first[160];
} wire_tally;

static void first_problem(wire_tally *w, const char *pol, const char *mode, const char *what,
                          UA_StatusCode r) {
    if(w->first[0])
        return;
    if(gds_path(w->first, sizeof(w->first), "%s %s: %s%s%s", pol, mode, what,
                r != UA_STATUSCODE_GOOD ? " -> " : "",
                r != UA_STATUSCODE_GOOD ? UA_StatusCode_name(r) : "") != GDS_OK)
        w->first[0] = '\0';
}

/* One endpoint: GetEndpoints view, then a SecureChannel trusting only ca. */
static void check_endpoint(ga_ctx *ctx, const srv_target *t, const UA_EndpointDescription *e,
                           wire_tally *w) {
    UA_NodeId type = st_policy_cert_type(&e->securityPolicyUri);
    char pol[96];
    if(gds_path(pol, sizeof(pol), "%s", st_short_policy(&e->securityPolicyUri)) != GDS_OK)
        pol[0] = '\0';
    const char *mode = e->securityMode == UA_MESSAGESECURITYMODE_SIGN ? "Sign" : "SignAndEncrypt";
    if(!UA_NodeId_equal(&type, &t->certType)) {
        ga_note(ctx, "%s %s: another CertificateType, not checked", pol, mode);
        w->other++;
        return;
    }
    w->checked++;
    UA_ByteString good = {t->tGood.len, t->tGood.data};
    if(!UA_ByteString_equal(&e->serverCertificate, &good)) {
        w->stale++;
        first_problem(w, pol, mode, "GetEndpoints advertises another certificate",
                      UA_STATUSCODE_GOOD);
        return;
    }
    char polUri[256];
    if(e->securityPolicyUri.length >= sizeof(polUri))
        return;
    memcpy(polUri, e->securityPolicyUri.data, e->securityPolicyUri.length);
    polUri[e->securityPolicyUri.length] = '\0';
    UA_Client *c = st_new_client(t, ST_ADMIN, false, polUri, e->securityMode);
    if(!c) {
        w->noChannel++;
        first_problem(w, pol, mode, "no client", UA_STATUSCODE_BADOUTOFMEMORY);
        return;
    }
    if(!client_has_policy(c, &e->securityPolicyUri)) {
        ga_note(ctx, "%s %s: the Auditor has no such policy; GetEndpoints only", pol, mode);
        st_client_free(c);
        return;
    }
    UA_StatusCode r = UA_Client_connectSecureChannel(c, t->url);
    st_client_free(c);
    if(r != UA_STATUSCODE_GOOD) {
        w->noChannel++;
        first_problem(w, pol, mode, "OpenSecureChannel trusting only the test CA", r);
    }
}

/* SRV-WIRE-01 (12 §7.10.9, §7.8.4.8, §7.8.4.9): after SRV-TXN-03, every
 * endpoint whose SecurityPolicy uses the updated CertificateType advertises
 * t-good in GetEndpoints, and a SecureChannel opens on it with a client that
 * trusts only the test CA. Endpoints of other CertificateTypes use another
 * slot of the group and are listed as evidence. */
static void t_wire_new_cert(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->applied) {
        ga_not_tested(ctx, "builds on SRV-TXN-03 (t-good applied)");
        return;
    }
    UA_EndpointDescription *eps = NULL;
    size_t n = 0;
    UA_StatusCode r = st_endpoints(t, &eps, &n);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "GetEndpoints -> %s", UA_StatusCode_name(r));
        return;
    }
    wire_tally w;
    memset(&w, 0, sizeof(w));
    for(size_t i = 0; i < n; i++)
        if(eps[i].securityMode == UA_MESSAGESECURITYMODE_SIGN ||
           eps[i].securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
            check_endpoint(ctx, t, &eps[i], &w);
    UA_Array_delete(eps, n, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    if(w.checked == 0)
        ga_fail(ctx, "no endpoint uses the updated CertificateType (%zu of other types)", w.other);
    else if(w.stale || w.noChannel)
        ga_fail(ctx, "%zu of %zu endpoint(s) still on the old certificate, %zu without a channel; %s",
                w.stale, w.checked, w.noChannel, w.first);
    else
        ga_pass(ctx, "all %zu endpoint(s) of the updated CertificateType present t-good", w.checked);
}

/* ---------------- SRV-WIRE-04 to -06: client certificates ---------------- */

#define PEER_REVOKED_URI "urn:opengds:auditor:peer-revoked"
#define PEER_UNKNOWN_URI "urn:opengds:auditor:peer-unknown"

/* An anonymous session over SignAndEncrypt with the application identity
 * cert/key, trusting the test CA (which issues t-good) and the pinned
 * certificate. *out is NULL unless the session is activated. */
static UA_StatusCode peer_connect(const srv_target *t, const gds_buf *cert, const gds_buf *key,
                                  UA_Client **out) {
    *out = NULL;
    char uri[256];
    if(x509_san_uri(cert, uri, sizeof(uri)) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    gds_buf trust[2];
    size_t n = 0;
    trust[n++] = t->caDer;
    if(t->pinned.len)
        trust[n++] = t->pinned;
    UA_Client *c = uac_new_secure_mode(cert, key, trust, n, &t->caCrl, 1, uri, POLICY_RSAPSS,
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
static bool cert_refusal(UA_StatusCode r) {
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

/* SRV-WIRE-04: with ca in the applied trust list (SRV-TXN-03), peer-good
 * gets a session. */
static void t_wire_peer_good(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->applied) {
        ga_not_tested(ctx, "builds on SRV-TXN-03 (a trust list with ca applied)");
        return;
    }
    UA_Client *c = NULL;
    UA_StatusCode r = peer_connect(t, &t->peerCert, &t->peerKey, &c);
    st_client_free(c);
    if(r == UA_STATUSCODE_GOOD)
        ga_pass(ctx, "session created as peer-good (issued by ca)");
    else if(cert_refusal(r))
        ga_fail(ctx, "peer-good refused although ca is in the applied trust list: %s",
                UA_StatusCode_name(r));
    else
        ga_not_tested(ctx, "peer-good session -> %s (not a certificate refusal)",
                      UA_StatusCode_name(r));
}

/* A CRL from the test CA that lists `revoked` (number 2: it replaces the
 * empty one). */
static gds_status revoking_crl(const testca_t *ca, const gds_buf *revoked, gds_buf *out) {
    gds_status ret = GDS_ECRYPTO;
    out->data = NULL;
    out->len = 0;
    X509 *x = x509_parse_cert(revoked);
    X509_CRL *crl = X509_CRL_new();
    X509_REVOKED *rv = X509_REVOKED_new();
    ASN1_TIME *now = ASN1_TIME_adj(NULL, time(NULL), 0, -3600);
    ASN1_TIME *next = ASN1_TIME_adj(NULL, time(NULL), TESTCA_MAX_DAYS, 0);
    ASN1_INTEGER *num = ASN1_INTEGER_new();
    X509_EXTENSION *ex = NULL;
    unsigned char *der = NULL;
    X509V3_CTX v3;
    bool ok = x && crl && rv && now && next && num &&
              X509_CRL_set_version(crl, 1) == 1 &&
              X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca->cert)) == 1 &&
              X509_CRL_set1_lastUpdate(crl, now) == 1 && X509_CRL_set1_nextUpdate(crl, next) == 1 &&
              X509_REVOKED_set_serialNumber(rv, X509_get_serialNumber(x)) == 1 &&
              X509_REVOKED_set_revocationDate(rv, now) == 1 && X509_CRL_add0_revoked(crl, rv) == 1;
    if(ok)
        rv = NULL; /* owned by crl */
    if(ok) {
        X509V3_set_ctx_nodb(&v3);
        X509V3_set_ctx(&v3, ca->cert, NULL, NULL, crl, 0);
        ex = X509V3_EXT_conf_nid(NULL, &v3, NID_authority_key_identifier, "keyid:always");
        ok = ex && X509_CRL_add_ext(crl, ex, -1) == 1 && ASN1_INTEGER_set(num, 2) == 1 &&
             X509_CRL_add1_ext_i2d(crl, NID_crl_number, num, 0, 0) == 1 &&
             X509_CRL_sort(crl) == 1 && X509_CRL_sign(crl, ca->key, EVP_sha256()) > 0;
    }
    int n = ok ? i2d_X509_CRL(crl, &der) : 0;
    if(n > 0 && der)
        ret = gds_buf_dup(der, (size_t)n, out);
    OPENSSL_free(der);
    X509_EXTENSION_free(ex);
    ASN1_INTEGER_free(num);
    ASN1_TIME_free(now);
    ASN1_TIME_free(next);
    X509_REVOKED_free(rv);
    X509_CRL_free(crl);
    X509_free(x);
    ERR_clear_error();
    return ret;
}

/* l with every copy of `old` among the CRLs replaced by `crl` */
static UA_StatusCode swap_crl(UA_TrustListDataType *l, const gds_buf *old, const gds_buf *crl) {
    UA_ByteString o = {old->len, old->data}, nw = {crl->len, crl->data};
    UA_ByteString *lists[2] = {l->trustedCrls, l->issuerCrls};
    size_t sizes[2] = {l->trustedCrlsSize, l->issuerCrlsSize};
    size_t swapped = 0;
    for(size_t k = 0; k < 2; k++)
        for(size_t i = 0; i < sizes[k]; i++)
            if(UA_ByteString_equal(&lists[k][i], &o)) {
                UA_ByteString_clear(&lists[k][i]);
                if(UA_ByteString_copy(&nw, &lists[k][i]) != UA_STATUSCODE_GOOD)
                    return UA_STATUSCODE_BADOUTOFMEMORY;
                swapped++;
            }
    return swapped ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADNOTFOUND;
}

/* SRV-WIRE-05: ca's CRL listing peer-revoked applied; peer-revoked is refused. */
static void t_wire_revoked(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->applied) {
        ga_not_tested(ctx, "builds on SRV-TXN-03 (a trust list with ca applied)");
        return;
    }
    gds_buf cert = {0}, key = {0}, crl = {0};
    UA_TrustListDataType l;
    UA_TrustListDataType_init(&l);
    UA_StatusCode r = st_admin(t);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_status_to_ua(testca_issue(&t->ca, "peer-revoked", PEER_REVOKED_URI, "localhost",
                                          TESTCA_MAX_DAYS, &cert, &key));
    if(r == UA_STATUSCODE_GOOD)
        r = gds_status_to_ua(revoking_crl(&t->ca, &cert, &crl));
    if(r == UA_STATUSCODE_GOOD)
        r = st_read_trustlist(t->client, ST_MASK_ALL, &l);
    if(r == UA_STATUSCODE_GOOD)
        r = swap_crl(&l, &t->caCrl, &crl);
    bool acr = false;
    if(r == UA_STATUSCODE_GOOD)
        r = st_write_trustlist(t->client, &l, 4096, &acr, ctx);
    if(r == UA_STATUSCODE_GOOD)
        r = st_apply(t->client);
    UA_TrustListDataType_clear(&l);
    gds_buf_free(&crl);
    if(r != UA_STATUSCODE_GOOD) {
        gds_buf_free(&cert);
        gds_buf_free_secret(&key);
        ga_not_tested(ctx, "setup: apply the trust list with a CRL that lists peer-revoked -> %s",
                      UA_StatusCode_name(r));
        return;
    }
    UA_Client *c = NULL;
    r = peer_connect(t, &cert, &key, &c);
    st_client_free(c);
    gds_buf_free(&cert);
    gds_buf_free_secret(&key);
    if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "session created as peer-revoked although ca's applied CRL lists it");
    else if(cert_refusal(r))
        ga_pass(ctx, "peer-revoked refused: %s", UA_StatusCode_name(r));
    else
        ga_not_tested(ctx, "peer-revoked session -> %s (not a certificate refusal)",
                      UA_StatusCode_name(r));
}

/* SRV-WIRE-06: a self-signed client certificate the target never trusted */
static void t_wire_unknown(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    EVP_PKEY *k = EVP_RSA_gen(2048);
    gds_buf cert = {0}, key = {0};
    gds_status gs = k ? st_make_leaf(NULL, k, "peer-unknown", PEER_UNKNOWN_URI, -3600,
                                     7 * 86400L, false, 0, &cert)
                      : GDS_ECRYPTO;
    if(gs == GDS_OK)
        gs = x509_key_to_der(k, &key);
    EVP_PKEY_free(k);
    ERR_clear_error();
    if(gs != GDS_OK) {
        gds_buf_free(&cert);
        ga_not_tested(ctx, "setup: peer-unknown: %s", gds_status_name(gs));
        return;
    }
    UA_Client *c = NULL;
    UA_StatusCode r = peer_connect(t, &cert, &key, &c);
    st_client_free(c);
    gds_buf_free(&cert);
    gds_buf_free_secret(&key);
    if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "session created as peer-unknown (self-signed, never trusted)");
    else if(cert_refusal(r))
        ga_pass(ctx, "peer-unknown refused: %s", UA_StatusCode_name(r));
    else
        ga_not_tested(ctx, "peer-unknown session -> %s (not a certificate refusal)",
                      UA_StatusCode_name(r));
}

/* ---------------- SRV-WIRE-07, -08: sessions after a trust list change ---------------- */

#define WATCH_WARN_SEC 30
#define TL_OBJ UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST

static void nap_ms(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

/* Write l on the admin session and apply it (Bad_NothingToDo: the target
 * has no transactions and put it in use at once). */
static UA_StatusCode push_apply(srv_target *t, const UA_TrustListDataType *l, ga_ctx *ctx) {
    UA_StatusCode r = st_admin(t);
    bool acr = false;
    if(r == UA_STATUSCODE_GOOD)
        r = st_write_trustlist(t->client, l, 4096, &acr, ctx);
    if(r == UA_STATUSCODE_GOOD)
        r = st_apply(t->client);
    return r == UA_STATUSCODE_BADNOTHINGTODO ? UA_STATUSCODE_GOOD : r;
}

/* Read ServerStatus/State on c until the Read fails: the session is gone.
 * Within 30 s passes, within the settle timeout warns, else fails. */
static void watch_closed(ga_ctx *ctx, const srv_target *t, UA_Client *c, const char *what) {
    time_t start = time(NULL);
    long waited = 0;
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    while(waited <= t->settleSec) {
        UA_Variant v;
        UA_Variant_init(&v);
        r = UA_Client_readValueAttribute(c, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS_STATE),
                                         &v);
        UA_Variant_clear(&v);
        if(r != UA_STATUSCODE_GOOD)
            break;
        nap_ms(500);
        waited = (long)(time(NULL) - start);
    }
    if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "the session of %s is still open after the settle timeout (%ld s)", what,
                t->settleSec);
    else if(waited > WATCH_WARN_SEC)
        ga_warn(ctx, "the session of %s was closed only after %ld s (%s)", what, waited,
                UA_StatusCode_name(r));
    else
        ga_pass(ctx, "the session of %s was closed within %ld s (Read -> %s)", what, waited,
                UA_StatusCode_name(r));
}

static UA_StatusCode remove_trusted(UA_Client *c, const gds_buf *cert) {
    char tp[X509_THUMBPRINT_LEN];
    if(x509_thumbprint(cert, tp) != GDS_OK)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_String thumb = UA_STRING(tp);
    UA_Boolean tr = true;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &thumb, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &tr, &UA_TYPES[UA_TYPES_BOOLEAN]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = UA_Client_call(
        c, UA_NODEID_NUMERIC(0, TL_OBJ),
        UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_REMOVECERTIFICATE),
        2, in, &outN, &out);
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

/* SRV-WIRE-07 (12 §7.8.2.5): peer-good trusted on its own (ca only as an
 * issuer), a session as peer-good, RemoveCertificate(peer-good), apply. */
static void t_wire_removed(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->applied) {
        ga_not_tested(ctx, "builds on SRV-TXN-03 (the test CA's t-good in use)");
        return;
    }
    UA_TrustListDataType l;
    UA_TrustListDataType_init(&l);
    UA_ByteString ca = {t->caDer.len, t->caDer.data}, crl = {t->caCrl.len, t->caCrl.data};
    UA_StatusCode r = st_list_copy_add(&t->snap, &t->peerCert, NULL, &l);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Array_appendCopy((void **)&l.issuerCertificates, &l.issuerCertificatesSize, &ca,
                                &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Array_appendCopy((void **)&l.issuerCrls, &l.issuerCrlsSize, &crl,
                                &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(r == UA_STATUSCODE_GOOD)
        r = push_apply(t, &l, ctx);
    UA_TrustListDataType_clear(&l);
    UA_Client *c = NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = peer_connect(t, &t->peerCert, &t->peerKey, &c);
    UA_StatusCode rm = r == UA_STATUSCODE_GOOD ? remove_trusted(t->client, &t->peerCert) : r;
    UA_StatusCode ra = rm == UA_STATUSCODE_GOOD ? st_apply(t->client) : rm;
    if(ra == UA_STATUSCODE_BADNOTHINGTODO)
        ra = UA_STATUSCODE_GOOD; /* RemoveCertificate was in use at once */
    if(r != UA_STATUSCODE_GOOD || rm != UA_STATUSCODE_GOOD || ra != UA_STATUSCODE_GOOD) {
        st_client_free(c);
        ga_not_tested(ctx, "setup: peer-good trusted and connected -> %s; RemoveCertificate -> "
                           "%s; ApplyChanges -> %s",
                      UA_StatusCode_name(r), UA_StatusCode_name(rm), UA_StatusCode_name(ra));
        return;
    }
    watch_closed(ctx, t, c, "peer-good after RemoveCertificate");
    st_client_free(c);
}

/* SRV-WIRE-08: ca trusted with its empty CRL, a session as peer-good, then a
 * CRL from ca that lists peer-good is applied. */
static void t_wire_crl_session(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->applied) {
        ga_not_tested(ctx, "builds on SRV-TXN-03 (the test CA's t-good in use)");
        return;
    }
    UA_TrustListDataType l;
    UA_TrustListDataType_init(&l);
    gds_buf crl = {0};
    UA_Client *c = NULL;
    UA_StatusCode r = push_apply(t, &t->pushed, ctx);
    if(r == UA_STATUSCODE_GOOD)
        r = peer_connect(t, &t->peerCert, &t->peerKey, &c);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_status_to_ua(revoking_crl(&t->ca, &t->peerCert, &crl));
    if(r == UA_STATUSCODE_GOOD)
        r = UA_TrustListDataType_copy(&t->pushed, &l);
    if(r == UA_STATUSCODE_GOOD)
        r = swap_crl(&l, &t->caCrl, &crl);
    if(r == UA_STATUSCODE_GOOD)
        r = push_apply(t, &l, ctx);
    UA_TrustListDataType_clear(&l);
    gds_buf_free(&crl);
    if(r != UA_STATUSCODE_GOOD) {
        st_client_free(c);
        ga_not_tested(ctx, "setup: peer-good connected, then a CRL listing it applied -> %s",
                      UA_StatusCode_name(r));
        return;
    }
    watch_closed(ctx, t, c, "peer-good after a CRL that lists it");
    st_client_free(c);
}

const ga_test srv_wire_tests[] = {
    {"SRV-WIRE-01", "12 §7.10.9, §7.8.4.8, §7.8.4.9",
     "Every endpoint of the updated CertificateType presents the new certificate", true, false,
     t_wire_new_cert},
    {"SRV-WIRE-04", "12 §7.10.9; 4 §6.1.3", "A client certificate from a CA in the applied list is accepted",
     true, false, t_wire_peer_good},
    {"SRV-WIRE-05", "12 §7.10.9; 4 §6.1.3", "A client certificate in an applied CRL is refused", true,
     false, t_wire_revoked},
    {"SRV-WIRE-06", "4 §6.1.3", "An untrusted client certificate is refused", false, false,
     t_wire_unknown},
    {"SRV-WIRE-07", "12 §7.8.2.5", "Sessions of a removed client certificate are closed", true,
     false, t_wire_removed},
    {"SRV-WIRE-08", "12 §7.8.2.5; 4 §6.1.3", "Sessions of a newly revoked client are closed", true,
     false, t_wire_crl_session},
};
const size_t srv_wire_count = GDS_ARRAY_SIZE(srv_wire_tests);
