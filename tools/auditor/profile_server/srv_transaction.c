/* OpenGDS Auditor server profile: transactions (srv_transaction.c).
 * ConformanceUnit: Server PushManagement Transactions; SRV-TXN-03: Push
 * Model for Global Certificate and TrustList Management.
 * Catalogue: docs/auditor/server-profile.md, "Transactions".
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <string.h>
#include <time.h>

#include <open62541/client_highlevel.h>

#include "srv_target.h"
#include "srv_tests.h"
#include "common/banned.h"

#define APPLY_WAIT_MS 10000

static bool same(const gds_buf *a, const gds_buf *b) {
    return a->len == b->len && a->len && memcmp(a->data, b->data, a->len) == 0;
}

static void nap_ms(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

#define LUT_NODE UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_LASTUPDATETIME
#define TL_OBJ UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST
#define TL_M(x) UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_##x

static UA_NodeId ns0(UA_UInt32 id) {
    return UA_NODEID_NUMERIC(0, id);
}

/* The new list of SRV-TXN-02/-03: the applied list of SRV-TL-02 plus
 * peer-good, queued in the admin session next to t-good. */
static UA_StatusCode queue_new_list(srv_target *t, ga_ctx *ctx) {
    UA_TrustListDataType_clear(&t->queued);
    UA_StatusCode r = st_list_copy_add(&t->pushed, &t->peerCert, NULL, &t->queued);
    bool acr = false;
    if(r == UA_STATUSCODE_GOOD)
        r = st_write_trustlist(t->client, &t->queued, 4096, &acr, ctx);
    t->listQueued = r == UA_STATUSCODE_GOOD;
    return r;
}

static bool session_live(UA_Client *c) {
    if(!c)
        return false;
    UA_SecureChannelState cs;
    UA_SessionState ss;
    UA_StatusCode st;
    UA_Client_getState(c, &cs, &ss, &st);
    return ss == UA_SESSIONSTATE_ACTIVATED;
}

/* SupportsTransactions TRUE, else Not supported (the Transactions CU) */
static bool transactions(ga_ctx *ctx, srv_target *t) {
    UA_StatusCode r = st_admin(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: admin session -> %s", UA_StatusCode_name(r));
        return false;
    }
    bool present = false, value = false;
    st_supports_transactions(t->client, &present, &value);
    if(!present || !value)
        ga_not_supported(ctx, "SupportsTransactions is %s", present ? "FALSE" : "absent");
    return present && value;
}

/* The state after SRV-TXN-03: t-good and t->queued in use */
static bool after_apply(ga_ctx *ctx, srv_target *t) {
    if(!transactions(ctx, t))
        return false;
    if(!t->applied) {
        ga_not_tested(ctx, "builds on SRV-TXN-03 (t-good and the new trust list in use)");
        return false;
    }
    return true;
}

static UA_StatusCode last_update(UA_Client *c, UA_DateTime *out) {
    *out = 0;
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode r = UA_Client_readValueAttribute(c, ns0(LUT_NODE), &v);
    if(r == UA_STATUSCODE_GOOD && UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_DATETIME]))
        *out = *(UA_DateTime *)v.data;
    else if(r == UA_STATUSCODE_GOOD)
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    UA_Variant_clear(&v);
    return r;
}

static UA_StatusCode cfg_call(UA_Client *c, UA_UInt32 method, size_t inN, const UA_Variant *in) {
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r =
        UA_Client_call(c, ns0(UA_NS0ID_SERVERCONFIGURATION), ns0(method), inN, in, &outN, &out);
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    return r;
}

static UA_StatusCode cancel(UA_Client *c) {
    return cfg_call(c, UA_NS0ID_SERVERCONFIGURATION_CANCELCHANGES, 0, NULL);
}

/* t-good2: another certificate from the test CA for the active key */
static UA_StatusCode t_good2(srv_target *t, gds_buf *cert) {
    gds_buf csr = {0};
    UA_StatusCode r = st_csr(t, t->client, false, NULL, &csr);
    if(r == UA_STATUSCODE_GOOD)
        r = gds_status_to_ua(testca_sign_csr(&t->ca, &csr, t->targetUri, TESTCA_MAX_DAYS, cert));
    gds_buf_free(&csr);
    return r;
}

/* What a fresh connection sees: does the
 * endpoint present `cert`, and is `list` the trust list in use? */
static void observe(srv_target *t, const gds_buf *cert, const UA_TrustListDataType *list,
                    bool *certSeen, bool *listSeen) {
    *certSeen = *listSeen = false;
    gds_buf now = {0};
    if(st_presented(t, &now) == UA_STATUSCODE_GOOD)
        *certSeen = same(&now, cert);
    gds_buf_free(&now);
    UA_Client *c = NULL; /* trusts the pinned certificate and the test CA */
    if(st_admin_fresh(t, true, &c) != UA_STATUSCODE_GOOD)
        return;
    UA_TrustListDataType back;
    if(st_read_trustlist(c, ST_MASK_ALL, &back) == UA_STATUSCODE_GOOD) {
        char why[8];
        *listSeen = st_lists_equal(list, &back, why, sizeof(why));
        UA_TrustListDataType_clear(&back);
    }
    st_client_free(c);
}

/* ---------------- SRV-TXN-01 ---------------- */

static void t_acr_always(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!transactions(ctx, t))
        return;
    const st_acr_log *l = st_acr();
    if(l->calls == 0)
        ga_not_tested(ctx, "no Good UpdateCertificate or CloseAndUpdate earlier in the run");
    else if(l->falses)
        ga_fail(ctx, "ApplyChangesRequired FALSE in %zu of %zu calls (first: %s) with "
                     "SupportsTransactions TRUE",
                l->falses, l->calls, l->firstFalse ? l->firstFalse : "?");
    else
        ga_pass(ctx, "ApplyChangesRequired TRUE in all %zu UpdateCertificate and CloseAndUpdate "
                     "calls so far",
                l->calls);
}

/* ---------------- SRV-TXN-02 ---------------- */

static void t_not_early(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!transactions(ctx, t))
        return;
    if(!t->certQueued || !session_live(t->client)) {
        ga_not_tested(ctx, "builds on SRV-UPD-01 (t-good queued in the admin session)");
        return;
    }
    UA_StatusCode r = queue_new_list(t, ctx);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: queueing the new trust list -> %s", UA_StatusCode_name(r));
        return;
    }
    bool certSeen = false, newListSeen = false, oldCert = false, oldList = false;
    observe(t, &t->tGood, &t->queued, &certSeen, &newListSeen);
    observe(t, &t->snapCert, &t->pushed, &oldCert, &oldList);
    if(certSeen || newListSeen)
        ga_fail(ctx, "before ApplyChanges a second session sees the queued %s",
                certSeen && newListSeen ? "certificate and trust list"
                                        : (certSeen ? "certificate" : "trust list"));
    else if(!oldList)
        ga_not_tested(ctx, "the second session could not read the applied trust list back");
    else
        ga_pass(ctx, "a second session sees the old certificate%s and the old trust list",
                oldCert ? "" : " (not the snapshot one)");
}

/* SRV-TXN-03 (12 §7.10.9): with t-good queued by SRV-UPD-01, queue a new
 * trust list in the same session (the applied list plus peer-good), call
 * ApplyChanges, then check on a fresh connection that trusts only the test
 * CA: the endpoint presents t-good and the new list is read back. */
static void t_apply_both(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->certQueued || !t->client) {
        ga_not_tested(ctx, "builds on SRV-UPD-01 (a queued certificate in the admin session)");
        return;
    }
    UA_SecureChannelState cs;
    UA_SessionState ss;
    UA_StatusCode st;
    UA_Client_getState(t->client, &cs, &ss, &st);
    if(ss != UA_SESSIONSTATE_ACTIVATED) {
        ga_not_tested(ctx, "the admin session that queued t-good was lost");
        return;
    }
    UA_StatusCode r = t->listQueued ? UA_STATUSCODE_GOOD : queue_new_list(t, ctx);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: queueing the new trust list -> %s (SRV-TL-02 checks it)",
                      UA_StatusCode_name(r));
        return;
    }
    r = st_apply(t->client);
    ga_note(ctx, "ApplyChanges -> %s", UA_StatusCode_name(r));
    /* the server closes channels after a certificate change (§7.10.9) */
    st_close(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "ApplyChanges with a queued certificate and trust list -> %s",
                UA_StatusCode_name(r));
        return;
    }
    gds_buf now = {0};
    long waited = 0;
    for(;;) {
        gds_buf_free(&now);
        r = st_presented(t, &now);
        if((r == UA_STATUSCODE_GOOD && same(&now, &t->tGood)) || waited >= APPLY_WAIT_MS)
            break;
        nap_ms(200);
        waited += 200;
    }
    bool certInUse = r == UA_STATUSCODE_GOOD && same(&now, &t->tGood);
    char tp[X509_THUMBPRINT_LEN] = "?";
    if(now.len && x509_thumbprint(&now, tp) != GDS_OK)
        tp[0] = '\0';
    gds_buf_free(&now);
    if(!certInUse) {
        ga_fail(ctx, "after ApplyChanges the endpoint presents %s, not t-good (waited %ld ms)", tp,
                waited);
        return;
    }
    UA_Client *c = NULL;
    r = st_admin_fresh(t, false, &c);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "a fresh connection trusting only the test CA failed: %s",
                UA_StatusCode_name(r));
        return;
    }
    UA_TrustListDataType back;
    r = st_read_trustlist(c, ST_MASK_ALL, &back);
    st_client_free(c);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "trust list read-back on the fresh connection -> %s", UA_StatusCode_name(r));
        return;
    }
    char why[160];
    if(st_lists_equal(&t->queued, &back, why, sizeof(why))) {
        t->applied = true;
        ga_pass(ctx, "t-good presented (%s) and the new trust list in use", tp);
    } else {
        ga_fail(ctx, "t-good presented, but the trust list is not the one queued: %s", why);
    }
    UA_TrustListDataType_clear(&back);
}

/* ---------------- SRV-TXN-04: CancelChanges ---------------- */

/* Queue t-good2 and `list` on c. */
static UA_StatusCode queue_both(srv_target *t, UA_Client *c, const gds_buf *cert,
                                const UA_TrustListDataType *list, ga_ctx *ctx) {
    bool acr = false;
    UA_StatusCode r = st_update_cert(t, c, cert, &t->caDer, 1, &acr);
    if(r == UA_STATUSCODE_GOOD)
        r = st_write_trustlist(c, list, 4096, &acr, ctx);
    return r;
}

static void t_cancel(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!after_apply(ctx, t))
        return;
    UA_NodeId m;
    if(uac_find_child(t->client, ns0(UA_NS0ID_SERVERCONFIGURATION), "CancelChanges", &m) !=
       UA_STATUSCODE_GOOD) {
        UA_NodeId_clear(&m);
        ga_not_supported(ctx, "ServerConfiguration has no CancelChanges");
        return;
    }
    UA_NodeId_clear(&m);
    gds_buf g2 = {0};
    UA_DateTime before = 0, after = 0;
    UA_StatusCode r = last_update(t->client, &before);
    if(r == UA_STATUSCODE_GOOD)
        r = t_good2(t, &g2);
    if(r == UA_STATUSCODE_GOOD)
        r = queue_both(t, t->client, &g2, &t->pushed, ctx);
    if(r != UA_STATUSCODE_GOOD) {
        gds_buf_free(&g2);
        ga_not_tested(ctx, "setup: LastUpdateTime, t-good2 and a trust list queued -> %s",
                      UA_StatusCode_name(r));
        return;
    }
    r = cancel(t->client);
    bool g2Seen = false, listKept = false;
    observe(t, &g2, &t->queued, &g2Seen, &listKept);
    UA_StatusCode lr = last_update(t->client, &after);
    gds_buf_free(&g2);
    if(r != UA_STATUSCODE_GOOD)
        ga_fail(ctx, "CancelChanges -> %s", UA_StatusCode_name(r));
    else if(g2Seen || !listKept)
        ga_fail(ctx, "after CancelChanges %s in use", g2Seen ? "t-good2 is" : "another trust list is");
    else if(lr != UA_STATUSCODE_GOOD || after != before)
        ga_fail(ctx, "after CancelChanges LastUpdateTime moved (%s)", UA_StatusCode_name(lr));
    else
        ga_pass(ctx, "Good; t-good and the old trust list in use, LastUpdateTime unchanged");
}

/* ---------------- SRV-TXN-05: a transaction ends with its Session ---------------- */

static void t_session_end(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!after_apply(ctx, t))
        return;
    gds_buf g2 = {0};
    UA_Client *a = NULL, *b = NULL;
    UA_StatusCode r = t_good2(t, &g2);
    if(r == UA_STATUSCODE_GOOD)
        r = st_admin_fresh(t, true, &a);
    if(r == UA_STATUSCODE_GOOD)
        r = queue_both(t, a, &g2, &t->pushed, ctx);
    st_client_free(a); /* closes the Session: its transaction goes (§7.10.2) */
    if(r == UA_STATUSCODE_GOOD)
        r = st_admin_fresh(t, false, &b);
    if(r != UA_STATUSCODE_GOOD) {
        gds_buf_free(&g2);
        ga_not_tested(ctx, "setup: queue on session A, close it, connect B -> %s",
                      UA_StatusCode_name(r));
        return;
    }
    r = st_apply(b);
    st_client_free(b);
    bool g2Seen = false, listKept = false;
    observe(t, &g2, &t->queued, &g2Seen, &listKept);
    gds_buf_free(&g2);
    if(r == UA_STATUSCODE_GOOD || g2Seen || !listKept)
        ga_fail(ctx, "after session A closed, ApplyChanges on B -> %s; %s", UA_StatusCode_name(r),
                g2Seen || !listKept ? "A's changes are in use" : "nothing changed");
    else if(r == UA_STATUSCODE_BADNOTHINGTODO)
        ga_pass(ctx, "ApplyChanges on a new Session -> Bad_NothingToDo; the old state in use");
    else
        ga_warn(ctx, "ApplyChanges on a new Session -> %s (Bad_NothingToDo expected); the old "
                     "state in use",
                UA_StatusCode_name(r));
}

/* ---------------- SRV-TXN-06, -07: another Session ---------------- */

/* Session A (the admin session) holds a transaction with t->pushed queued. */
static bool hold(ga_ctx *ctx, srv_target *t, UA_Client **b) {
    *b = NULL;
    if(!after_apply(ctx, t))
        return false;
    bool acr = false;
    UA_StatusCode r = st_write_trustlist(t->client, &t->pushed, 4096, &acr, ctx);
    if(r == UA_STATUSCODE_GOOD)
        r = st_admin_fresh(t, true, b);
    if(r != UA_STATUSCODE_GOOD) {
        (void)cancel(t->client);
        ga_not_tested(ctx, "setup: transaction on session A and a session B -> %s",
                      UA_StatusCode_name(r));
        return false;
    }
    return true;
}

/* B's call: Bad_TransactionPending passes; counts the others */
static void pending(ga_ctx *ctx, const char *what, UA_StatusCode r, size_t *good, size_t *other) {
    ga_note(ctx, "session B %s -> %s", what, UA_StatusCode_name(r));
    if(r == UA_STATUSCODE_GOOD)
        (*good)++;
    else if(r != UA_STATUSCODE_BADTRANSACTIONPENDING)
        (*other)++;
}

static void t_interleave(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    UA_Client *b = NULL;
    if(!hold(ctx, t, &b))
        return;
    size_t good = 0, other = 0;
    bool acr = false;
    pending(ctx, "UpdateCertificate(t-good)", st_update_cert(t, b, &t->tGood, &t->caDer, 1, &acr),
            &good, &other);
    UA_Byte mode = ST_OPEN_WRITE_ERASE;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &mode, &UA_TYPES[UA_TYPES_BYTE]);
    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_StatusCode r = UA_Client_call(b, ns0(TL_OBJ), ns0(TL_M(OPEN)), 1, in, &outN, &out);
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    pending(ctx, "Open(Write|EraseExisting)", r, &good, &other);
    UA_ByteString pc = {t->peerCert.len, t->peerCert.data};
    UA_Boolean tr = true;
    UA_Variant_setScalar(&in[0], &pc, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&in[1], &tr, &UA_TYPES[UA_TYPES_BOOLEAN]);
    out = NULL;
    outN = 0;
    r = UA_Client_call(b, ns0(TL_OBJ), ns0(TL_M(ADDCERTIFICATE)), 2, in, &outN, &out);
    UA_Array_delete(out, outN, &UA_TYPES[UA_TYPES_VARIANT]);
    pending(ctx, "AddCertificate(peer-good)", r, &good, &other);
    st_discard(b);
    (void)cancel(t->client);
    if(good)
        ga_fail(ctx, "%zu of 3 calls of session B succeeded during A's transaction", good);
    else if(other)
        ga_warn(ctx, "%zu of 3 calls of session B refused with another code than "
                     "Bad_TransactionPending",
                other);
    else
        ga_pass(ctx, "UpdateCertificate, Open and AddCertificate of session B -> "
                     "Bad_TransactionPending");
}

static void t_other_apply(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    UA_Client *b = NULL;
    if(!hold(ctx, t, &b))
        return;
    UA_StatusCode ra = st_apply(b);
    UA_StatusCode rc = cancel(b);
    st_client_free(b);
    (void)cancel(t->client);
    ga_note(ctx, "session B ApplyChanges -> %s, CancelChanges -> %s", UA_StatusCode_name(ra),
            UA_StatusCode_name(rc));
    bool listKept = false, unused = false;
    observe(t, &t->tGood, &t->queued, &unused, &listKept);
    if(ra == UA_STATUSCODE_GOOD || rc == UA_STATUSCODE_GOOD || !listKept)
        ga_fail(ctx, "session B could act on A's transaction (ApplyChanges %s, CancelChanges %s)",
                UA_StatusCode_name(ra), UA_StatusCode_name(rc));
    else if(ra == UA_STATUSCODE_BADSESSIONIDINVALID && rc == UA_STATUSCODE_BADSESSIONIDINVALID)
        ga_pass(ctx, "ApplyChanges and CancelChanges of session B -> Bad_SessionIdInvalid");
    else
        ga_warn(ctx, "refused with ApplyChanges %s, CancelChanges %s (Bad_SessionIdInvalid "
                     "expected)",
                UA_StatusCode_name(ra), UA_StatusCode_name(rc));
}

/* ---------------- SRV-TXN-08: ApplyChanges while a TrustList is open ---------------- */

static void t_apply_open(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    UA_StatusCode r = st_admin(t);
    if(r != UA_STATUSCODE_GOOD || !t->applied) {
        ga_not_tested(ctx, "builds on SRV-TXN-03 (%s)", UA_StatusCode_name(r));
        return;
    }
    /* a transaction (t->pushed queued), then a second list written, still open */
    bool acr = false;
    UA_UInt32 h = 0;
    r = st_write_trustlist(t->client, &t->pushed, 4096, &acr, ctx);
    if(r == UA_STATUSCODE_GOOD)
        r = st_tl_open_write(t->client, &t->queued, 4096, &h, ctx);
    if(r != UA_STATUSCODE_GOOD) {
        (void)cancel(t->client);
        ga_not_tested(ctx, "setup: a queued list and an open write handle -> %s",
                      UA_StatusCode_name(r));
        return;
    }
    UA_StatusCode first = st_apply(t->client);
    bool unused = false, untouched = false;
    observe(t, &t->tGood, &t->queued, &unused, &untouched);
    UA_StatusCode cu = st_tl_finish(t->client, h, true, &acr, ctx);
    UA_StatusCode second = cu == UA_STATUSCODE_GOOD ? st_apply(t->client) : cu;
    bool applied = false;
    observe(t, &t->tGood, &t->queued, &unused, &applied);
    ga_note(ctx, "ApplyChanges with the handle open -> %s; CloseAndUpdate -> %s; ApplyChanges -> %s",
            UA_StatusCode_name(first), UA_StatusCode_name(cu), UA_StatusCode_name(second));
    if(first == UA_STATUSCODE_GOOD || !untouched)
        ga_fail(ctx, "ApplyChanges with a TrustList open for writing changed the state (%s)",
                UA_StatusCode_name(first));
    else if(second != UA_STATUSCODE_GOOD || !applied)
        ga_fail(ctx, "after CloseAndUpdate, ApplyChanges -> %s; list in use: %s",
                UA_StatusCode_name(second), applied ? "yes" : "no");
    else if(first != UA_STATUSCODE_BADINVALIDSTATE)
        ga_warn(ctx, "first ApplyChanges refused with %s (Bad_InvalidState expected)",
                UA_StatusCode_name(first));
    else
        ga_pass(ctx, "Bad_InvalidState with nothing applied, then applied after CloseAndUpdate");
}

/* ---------------- SRV-TXN-09 ---------------- */

static void t_nothing(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    UA_Client *c = NULL;
    UA_StatusCode r = st_admin_fresh(t, true, &c);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: fresh admin session -> %s", UA_StatusCode_name(r));
        return;
    }
    r = st_apply(c);
    st_client_free(c);
    if(r == UA_STATUSCODE_BADNOTHINGTODO)
        ga_pass(ctx, "ApplyChanges without a transaction -> Bad_NothingToDo");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "ApplyChanges without a transaction -> Good");
    else
        ga_warn(ctx, "ApplyChanges without a transaction -> %s (Bad_NothingToDo expected)",
                UA_StatusCode_name(r));
}

/* ---------------- SRV-TXN-10, -11: one transaction, several calls ---------------- */

static void t_fail_keeps(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!after_apply(ctx, t))
        return;
    gds_buf wk = {0}, wkKey = {0};
    gds_status gs = testca_issue(&t->ca, "t-wrongkey", t->targetUri, "localhost", TESTCA_MAX_DAYS,
                                 &wk, &wkKey);
    gds_buf_free_secret(&wkKey);
    bool acr = false;
    UA_StatusCode r = gds_status_to_ua(gs);
    if(r == UA_STATUSCODE_GOOD)
        r = st_write_trustlist(t->client, &t->pushed, 4096, &acr, ctx);
    if(r != UA_STATUSCODE_GOOD) {
        gds_buf_free(&wk);
        (void)cancel(t->client);
        ga_not_tested(ctx, "setup: t-wrongkey and a queued trust list -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_StatusCode bad = st_update_cert(t, t->client, &wk, &t->caDer, 1, &acr);
    gds_buf_free(&wk);
    if(bad == UA_STATUSCODE_GOOD) {
        (void)cancel(t->client);
        ga_not_tested(ctx, "UpdateCertificate(t-wrongkey) was accepted (SRV-UPD-02 reports it)");
        return;
    }
    r = st_apply(t->client);
    bool unused = false, applied = false;
    observe(t, &t->tGood, &t->pushed, &unused, &applied);
    if(r == UA_STATUSCODE_GOOD && applied) {
        UA_TrustListDataType_clear(&t->queued); /* t->pushed is now in use */
        if(UA_TrustListDataType_copy(&t->pushed, &t->queued) != UA_STATUSCODE_GOOD)
            t->applied = false;
        ga_pass(ctx, "UpdateCertificate(t-wrongkey) -> %s; ApplyChanges applied the trust list",
                UA_StatusCode_name(bad));
    } else
        ga_fail(ctx, "after a failed UpdateCertificate (%s), ApplyChanges -> %s and the trust list "
                     "is %sin use: the failed call discarded the transaction",
                UA_StatusCode_name(bad), UA_StatusCode_name(r), applied ? "" : "not ");
}

static void t_partial(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!after_apply(ctx, t))
        return;
    gds_buf g2 = {0};
    UA_Client *c = NULL;
    bool acr = false;
    UA_StatusCode r = t_good2(t, &g2);
    if(r == UA_STATUSCODE_GOOD)
        r = st_admin_fresh(t, true, &c);
    if(r == UA_STATUSCODE_GOOD) /* the snapshot list: without ca */
        r = st_write_trustlist(c, &t->snap, 4096, &acr, ctx);
    if(r != UA_STATUSCODE_GOOD) {
        gds_buf_free(&g2);
        st_discard(c);
        ga_not_tested(ctx, "setup: t-good2 and the trust list without ca queued -> %s",
                      UA_StatusCode_name(r));
        return;
    }
    UA_StatusCode ru = st_update_cert(t, c, &g2, &t->caDer, 1, &acr);
    if(ru != UA_STATUSCODE_GOOD) {
        st_discard(c); /* the queued list goes with the session */
        gds_buf_free(&g2);
        ga_pass(ctx, "UpdateCertificate(t-good2) refused (%s): its issuer is not in the queued "
                     "trust list",
                UA_StatusCode_name(ru));
        return;
    }
    UA_StatusCode ra = st_apply(c);
    st_client_free(c);
    bool g2Seen = false, newList = false, oldCert = false, oldList = false;
    observe(t, &g2, &t->snap, &g2Seen, &newList);
    observe(t, &t->tGood, &t->queued, &oldCert, &oldList);
    gds_buf_free(&g2);
    if(ra != UA_STATUSCODE_GOOD && oldList && !g2Seen)
        ga_pass(ctx, "ApplyChanges -> %s with nothing applied", UA_StatusCode_name(ra));
    else if(ra == UA_STATUSCODE_GOOD && g2Seen && newList)
        ga_warn(ctx, "ApplyChanges applied both: the endpoint presents t-good2, which its own "
                     "trust list cannot validate");
    else
        ga_fail(ctx, "ApplyChanges -> %s and only some changes are in use (t-good2 %s, the list "
                     "without ca %s)",
                UA_StatusCode_name(ra), g2Seen ? "yes" : "no", newList ? "yes" : "no");
}

const ga_test srv_transaction_tests[] = {
    {"SRV-TXN-01", "12 §7.10.2", "ApplyChangesRequired is always TRUE with transactions", true,
     false, t_acr_always},
    {"SRV-TXN-02", "12 §7.10.2, §7.8.2.5", "Queued changes are not visible before ApplyChanges",
     true, false, t_not_early},
    {"SRV-TXN-03", "12 §7.10.9",
     "ApplyChanges puts the queued certificate and trust list in use together", true, false,
     t_apply_both},
    {"SRV-TXN-04", "12 §7.10.2, §7.10.11", "CancelChanges discards the whole transaction", true,
     false, t_cancel},
    {"SRV-TXN-05", "12 §7.10.2, §7.10.9", "A transaction ends with its Session", true, false,
     t_session_end},
    {"SRV-TXN-06", "12 §7.10.2, §7.10.5, §7.8.2.2, §7.8.2.6",
     "Another Session gets Bad_TransactionPending", true, false, t_interleave},
    {"SRV-TXN-07", "12 §7.10.9, §7.10.11", "Another Session cannot apply or cancel", true, false,
     t_other_apply},
    {"SRV-TXN-08", "12 §7.10.9", "ApplyChanges refuses while a TrustList is open for writing",
     true, false, t_apply_open},
    {"SRV-TXN-09", "12 §7.10.9", "ApplyChanges without a transaction is Bad_NothingToDo", true,
     false, t_nothing},
    {"SRV-TXN-10", "12 §7.10.2", "A failed call keeps the transaction", true, false,
     t_fail_keeps},
    {"SRV-TXN-11", "12 §7.10.2", "ApplyChanges applies all or nothing", true, false, t_partial},
};
const size_t srv_transaction_count = GDS_ARRAY_SIZE(srv_transaction_tests);
