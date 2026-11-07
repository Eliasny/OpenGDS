/* OpenGDS Auditor server profile: persistence across a restart
 * (srv_persistence.c). Each test restarts the target with --restart-cmd or
 * an operator prompt (st_restart).
 * ConformanceUnit: Push Model for Global Certificate and TrustList Management.
 * Catalogue: docs/auditor/server-profile.md, "Persistence".
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>

#include <open62541/client_highlevel.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "srv_target.h"
#include "srv_tests.h"
#include "x509util.h"
#include "common/banned.h"

#define LUT_NODE UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_LASTUPDATETIME

static bool same(const gds_buf *a, const gds_buf *b) {
    return a->len == b->len && a->len && memcmp(a->data, b->data, a->len) == 0;
}

static UA_StatusCode read_lut(UA_Client *c, UA_DateTime *out) {
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode r = UA_Client_readValueAttribute(c, UA_NODEID_NUMERIC(0, LUT_NODE), &v);
    if(r == UA_STATUSCODE_GOOD && !UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_DATETIME]))
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    if(r == UA_STATUSCODE_GOOD)
        *out = *(const UA_DateTime *)v.data;
    UA_Variant_clear(&v);
    return r;
}

/* The presented certificate, the trust list and LastUpdateTime (admin). */
typedef struct {
    gds_buf cert;
    UA_TrustListDataType list;
    UA_DateTime lut;
    bool lutOk;
} state;

static UA_StatusCode state_read(srv_target *t, state *s) {
    memset(s, 0, sizeof(*s));
    UA_StatusCode r = st_presented(t, &s->cert);
    if(r == UA_STATUSCODE_GOOD)
        r = st_admin(t);
    if(r == UA_STATUSCODE_GOOD)
        r = st_read_trustlist(t->client, ST_MASK_ALL, &s->list);
    if(r == UA_STATUSCODE_GOOD)
        s->lutOk = read_lut(t->client, &s->lut) == UA_STATUSCODE_GOOD;
    return r;
}

static void state_clear(state *s) {
    gds_buf_free(&s->cert);
    UA_TrustListDataType_clear(&s->list);
}

/* A restart that did not happen is Not tested: the verdict needs one. */
static bool restarted(ga_ctx *ctx, srv_target *t) {
    UA_StatusCode r = st_restart(t, ctx);
    if(r == UA_STATUSCODE_BADNOTSUPPORTED)
        ga_not_tested(ctx, "needs --restart-cmd or an operator at the terminal");
    else if(r != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "the restart failed or the target did not come back within %ld s (%s)",
                      t->settleSec, UA_StatusCode_name(r));
    return r == UA_STATUSCODE_GOOD;
}

static bool supports_transactions(srv_target *t) {
    bool present = false, value = false;
    if(st_admin(t) == UA_STATUSCODE_GOOD)
        st_supports_transactions(t->client, &present, &value);
    return present && value;
}

/* SRV-PER-01 (12 §7.10.9; decision D1): what SRV-TXN-03 and the wire tests
 * applied is still in use after a restart. Part 12 states no persistence
 * rule, so a revert is a Warn. */
static void t_per_applied(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->applied) {
        ga_not_tested(ctx, "builds on SRV-TXN-03 (t-good and a new trust list applied)");
        return;
    }
    state before, after;
    UA_StatusCode r = state_read(t, &before);
    if(r != UA_STATUSCODE_GOOD) {
        state_clear(&before);
        ga_not_tested(ctx, "setup: read the state before the restart -> %s", UA_StatusCode_name(r));
        return;
    }
    if(!restarted(ctx, t)) {
        state_clear(&before);
        return;
    }
    t->restarted = true;
    r = state_read(t, &after);
    t->lutKnown = r == UA_STATUSCODE_GOOD && before.lutOk && after.lutOk;
    t->lutBefore = before.lut;
    t->lutAfter = after.lut;
    char why[160] = "";
    bool certKept = same(&before.cert, &after.cert);
    bool listKept = r == UA_STATUSCODE_GOOD && st_lists_equal(&before.list, &after.list, why,
                                                              sizeof(why));
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "after the restart the trust list cannot be read as admin: %s",
                UA_StatusCode_name(r));
    else if(certKept && listKept)
        ga_pass(ctx, "the applied certificate and trust list are in use after the restart");
    else
        ga_warn(ctx, "after the restart %s%s%s (Part 12 states no persistence rule, decision D1)",
                certKept ? "" : "another certificate is presented",
                !certKept && !listKept ? " and " : "",
                listKept ? "" : "the trust list differs");
    if(!listKept && why[0])
        ga_note(ctx, "trust list: %s", why);
    state_clear(&before);
    state_clear(&after);
}

/* SRV-PER-02 (12 §7.8.2.1): LastUpdateTime is when the list was last
 * updated, which a restart is not. */
static void t_per_lut(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->restarted || !t->lutKnown) {
        ga_not_tested(ctx, "builds on SRV-PER-01 (LastUpdateTime read around its restart)");
        return;
    }
    if(t->lutAfter == t->lutBefore)
        ga_pass(ctx, "LastUpdateTime unchanged by the restart");
    else if(t->lutAfter == 0)
        ga_pass(ctx, "LastUpdateTime is DateTime.MinValue after the restart");
    else
        ga_fail(ctx, "LastUpdateTime moved by %.1f s over the restart",
                (double)(t->lutAfter - t->lutBefore) / (double)UA_DATETIME_SEC);
}

static UA_StatusCode cancel(UA_Client *c) {
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = UA_Client_call(c, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION),
                                     UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CANCELCHANGES),
                                     0, NULL, &outN, &out);
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

/* SRV-PER-03 (12 §7.10.10): the new key pair of a CreateSigningRequest
 * with RegeneratePrivateKey TRUE survives a restart until a certificate
 * for it is applied. With transactions the update is cancelled, so the
 * target keeps its key; without, the new key is in use from here on. */
static void t_per_csr_key(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->applied) {
        ga_not_tested(ctx, "builds on SRV-TXN-03 (the test CA trusted, t-good in use)");
        return;
    }
    unsigned char n[32];
    if(RAND_bytes(n, sizeof(n)) != 1) {
        ERR_clear_error();
        ga_not_tested(ctx, "setup: no random nonce");
        return;
    }
    UA_ByteString nonce = {sizeof(n), n};
    gds_buf csr = {0}, cert = {0};
    UA_StatusCode r = st_admin(t);
    if(r == UA_STATUSCODE_GOOD)
        r = st_csr(t, t->client, true, &nonce, &csr);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: CreateSigningRequest(RegeneratePrivateKey TRUE) -> %s "
                           "(SRV-CSR-04 checks it)",
                      UA_StatusCode_name(r));
        return;
    }
    gds_status gs = testca_sign_csr(&t->ca, &csr, t->targetUri, TESTCA_MAX_DAYS, &cert);
    gds_buf_free(&csr);
    if(gs != GDS_OK) {
        ga_not_tested(ctx, "setup: certificate for the CSR: %s", gds_status_name(gs));
        return;
    }
    if(!restarted(ctx, t)) {
        gds_buf_free(&cert);
        return;
    }
    bool txn = supports_transactions(t);
    bool acr = false;
    r = st_admin(t);
    if(r == UA_STATUSCODE_GOOD)
        r = st_update_cert(t, t->client, &cert, &t->caDer, 1, &acr);
    if(r == UA_STATUSCODE_GOOD && txn) {
        UA_StatusCode c = cancel(t->client);
        ga_note(ctx, "CancelChanges -> %s (the target keeps its key)", UA_StatusCode_name(c));
    } else if(r == UA_STATUSCODE_GOOD) {
        t->keyReplaced = true; /* in use at once: the restore cannot bring the old key back */
        gds_buf_free(&t->tGood);
        t->tGood = cert;
        cert = (gds_buf){0};
    }
    gds_buf_free(&cert);
    if(r == UA_STATUSCODE_GOOD)
        ga_pass(ctx, "UpdateCertificate for the new key pair after the restart -> Good");
    else
        ga_fail(ctx, "UpdateCertificate for the CSR's new key pair after the restart -> %s: the "
                     "key pair was lost",
                UA_StatusCode_name(r));
}

/* SRV-PER-04 (12 §7.10.2): a transaction not applied is gone after a
 * restart. */
static void t_per_uncommitted(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->applied) {
        ga_not_tested(ctx, "builds on SRV-TXN-03 (the test CA trusted, t-good in use)");
        return;
    }
    if(!supports_transactions(t)) {
        ga_not_tested(ctx, "SupportsTransactions is not TRUE: changes are in use at once");
        return;
    }
    state before, after;
    memset(&after, 0, sizeof(after));
    UA_StatusCode r = state_read(t, &before);
    gds_buf cert = {0}, extra = {0};
    EVP_PKEY *pub = st_tgood_key(t);
    gds_status gs = pub ? st_make_leaf(&t->ca, pub, "t-per-04", t->targetUri, -3600,
                                       TESTCA_MAX_DAYS * 86400L, false, 0, &cert)
                        : GDS_ECRYPTO;
    if(gs == GDS_OK) /* a certificate only the queued list trusts */
        gs = st_make_leaf(&t->ca, pub, "t-per-04-trusted", NULL, -3600, 86400L, false, 0, &extra);
    EVP_PKEY_free(pub);
    ERR_clear_error();
    if(r == UA_STATUSCODE_GOOD)
        r = gds_status_to_ua(gs);
    UA_TrustListDataType l;
    UA_TrustListDataType_init(&l);
    bool acr = false;
    if(r == UA_STATUSCODE_GOOD)
        r = st_update_cert(t, t->client, &cert, &t->caDer, 1, &acr);
    if(r == UA_STATUSCODE_GOOD)
        r = st_list_copy_add(&before.list, &extra, NULL, &l);
    if(r == UA_STATUSCODE_GOOD) {
        l.specifiedLists = ST_MASK_ALL;
        r = st_write_trustlist(t->client, &l, 16384, &acr, ctx);
    }
    UA_TrustListDataType_clear(&l);
    gds_buf_free(&extra);
    if(r != UA_STATUSCODE_GOOD) {
        if(t->client)
            (void)cancel(t->client);
        gds_buf_free(&cert);
        state_clear(&before);
        ga_not_tested(ctx, "setup: queue t-per-04 and a trust list -> %s", UA_StatusCode_name(r));
        return;
    }
    if(!restarted(ctx, t)) {
        gds_buf_free(&cert);
        state_clear(&before);
        return;
    }
    r = state_read(t, &after);
    char why[160] = "";
    bool certQueued = same(&after.cert, &cert);
    bool certKept = same(&after.cert, &before.cert);
    bool listKept = r == UA_STATUSCODE_GOOD && st_lists_equal(&before.list, &after.list, why,
                                                              sizeof(why));
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "after the restart the trust list cannot be read as admin: %s",
                UA_StatusCode_name(r));
    else if(certQueued || !listKept)
        ga_fail(ctx, "a change queued but never applied is in use after the restart: %s%s%s",
                certQueued ? "t-per-04 is presented" : "",
                certQueued && !listKept ? "; " : "", listKept ? "" : why);
    else if(!certKept)
        ga_not_tested(ctx, "after the restart neither the old certificate nor t-per-04 is "
                           "presented (SRV-PER-01 covers a revert)");
    else
        ga_pass(ctx, "after the restart the old certificate and trust list are in use");
    gds_buf_free(&cert);
    state_clear(&before);
    state_clear(&after);
}

const ga_test srv_persistence_tests[] = {
    {"SRV-PER-01", "12 §7.10.9", "Applied certificate and trust list survive a restart", true,
     false, t_per_applied},
    {"SRV-PER-02", "12 §7.8.2.1", "A restart does not move LastUpdateTime", true, false,
     t_per_lut},
    {"SRV-PER-03", "12 §7.10.10", "The CSR's new key pair survives a restart", true, false,
     t_per_csr_key},
    {"SRV-PER-04", "12 §7.10.2", "A transaction not applied is gone after a restart", true, false,
     t_per_uncommitted},
};
const size_t srv_persistence_count = GDS_ARRAY_SIZE(srv_persistence_tests);
