/* OpenGDS Auditor client profile - Faults (CLI-FLT-*): bad certificates,
 * malformed or over-long answers and closed sessions must leave the client
 * running with its last good state. Rows of docs/auditor/client-profile.md,
 * "Faults (cli_faults.c)".
 * SPDX-License-Identifier: MPL-2.0 */
#include "client_profile.h"
#include "common/banned.h"

/* suppressible: Part 4 Table 100 lets an application suppress this check, so
 * installing the certificate is a Warn, not a Fail (decision D2) */
static void not_installed(cli_profile *p, ga_ctx *ctx, fault_id fault, const char *what,
                          bool suppressible) {
    if(!cli_base_cycle(p, ctx))
        return;
    const fg_event *good = cli_last_issued();
    if(!good) {
        ga_not_tested(ctx, "the client holds no certificate from the GDS yet");
        return;
    }
    /* the client connects with what it has now; then the faulty cycle */
    cli_probe_result before;
    if(!cli_probe(p, FG_CA_MAIN, ctx, &before))
        return;
    bool worked = before.connected;
    cli_probe_clear(&before);
    if(!worked) {
        ga_not_tested(ctx, "the client does not connect to the probe server even before the fault");
        return;
    }
    cli_cycle c;
    if(!cli_cycle_for(p, fault, ctx, &c))
        return;
    const fg_event *bad = NULL;
    for(size_t i = c.first; i < c.end && !bad; i++) {
        const fg_event *ev = fg_event_at(i);
        if(ev->method == FG_M_FINISH && ev->result == UA_STATUSCODE_GOOD && ev->issued.len)
            bad = ev;
    }
    if(!bad) {
        ga_not_tested(ctx, "the client fetched no certificate in the cycle");
        return;
    }
    cli_probe_result pr;
    if(!cli_probe(p, FG_CA_MAIN, ctx, &pr))
        return;
    if(!pr.connected)
        ga_fail(ctx, "after it was offered the %s certificate the client no longer connects with "
                     "its own (it was installed or broke the old one)", what);
    else if(cli_cert_is(&pr.cert, &bad->issued) && suppressible)
        ga_warn(ctx, "the client installed the %s certificate (the check can be suppressed, "
                     "Part 4 Table 100)", what);
    else if(cli_cert_is(&pr.cert, &bad->issued))
        ga_fail(ctx, "the client installed the %s certificate", what);
    else if(cli_cert_is(&pr.cert, &good->issued))
        ga_pass(ctx, "the %s certificate was refused; the previous one is still in use", what);
    else
        ga_fail(ctx, "the client lost its previous certificate (it presents another one)");
    cli_probe_clear(&pr);
}

static void t_flt_untrusted(ga_ctx *ctx, void *profile) {
    not_installed(profile, ctx, FAULT_ISSUE_UNTRUSTED, "untrusted", false);
}
static void t_flt_wrong_key(ga_ctx *ctx, void *profile) {
    not_installed(profile, ctx, FAULT_ISSUE_WRONG_KEY, "wrong-key", false);
}
static void t_flt_wrong_uri(ga_ctx *ctx, void *profile) {
    not_installed(profile, ctx, FAULT_ISSUE_WRONG_URI, "wrong-URI", false);
}
static void t_flt_expired(ga_ctx *ctx, void *profile) {
    not_installed(profile, ctx, FAULT_ISSUE_EXPIRED, "expired", true);
}

/* After a fault the client still runs and connects as before */
static bool still_good(cli_profile *p, const cli_cycle *c, const fg_event *good, ga_ctx *ctx,
                       const char *what) {
    if(!cli_survived(&c->run)) {
        ga_fail(ctx, "the client crashed or hung on %s (exit %d%s)", what, c->run.exitStatus,
                c->run.exited ? "" : ", killed after the timeout");
        return false;
    }
    cli_probe_result pr;
    if(!cli_probe(p, FG_CA_MAIN, ctx, &pr))
        return false;
    bool ok = false;
    if(!pr.connected)
        ga_fail(ctx, "after %s the client no longer connects as before (its trust list or "
                     "certificate was replaced)", what);
    else if(good && !cli_cert_is(&pr.cert, &good->issued))
        ga_fail(ctx, "after %s the client presents another certificate", what);
    else
        ok = true;
    cli_probe_clear(&pr);
    return ok;
}

static const fg_event *baseline(cli_profile *p, ga_ctx *ctx) {
    if(!cli_base_cycle(p, ctx))
        return NULL;
    const fg_event *good = cli_last_issued();
    if(!good)
        ga_not_tested(ctx, "the client holds no certificate from the GDS yet");
    return good;
}

static void t_flt_garbage(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    const fg_event *good = baseline(p, ctx);
    if(!good)
        return;
    cli_cycle c;
    if(!cli_cycle_for(p, FAULT_TL_GARBAGE, ctx, &c))
        return;
    if(!cli_count(&c, FG_M_TL_READ)) {
        ga_not_tested(ctx, "the client did not read the changed trust list");
        return;
    }
    if(still_good(p, &c, good, ctx, "a malformed trust list"))
        ga_pass(ctx, "the malformed trust list was refused; the previous list is in use");
}

static void t_flt_lengths(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    const fg_event *good = baseline(p, ctx);
    if(!good)
        return;
    cli_cycle c;
    if(!cli_cycle_for(p, FAULT_HUGE_ISSUERS, ctx, &c))
        return;
    const fg_event *fin = NULL;
    for(size_t i = c.first; i < c.end && !fin; i++)
        if(fg_event_at(i)->method == FG_M_FINISH && fg_event_at(i)->issued.len)
            fin = fg_event_at(i);
    if(!fin) {
        ga_not_tested(ctx, "the client fetched no certificate in the cycle");
        return;
    }
    if(!still_good(p, &c, good, ctx, "10 000 IssuerCertificates"))
        return;
    if(!cli_cycle_for(p, FAULT_TL_OVER_READ, ctx, &c))
        return;
    if(!cli_count(&c, FG_M_TL_READ)) {
        ga_not_tested(ctx, "the client did not read the changed trust list");
        return;
    }
    if(still_good(p, &c, good, ctx, "a Read longer than requested"))
        ga_pass(ctx, "10 000 IssuerCertificates and an over-long Read were both refused");
}

static void t_flt_reconnect(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    if(!cli_base_cycle(p, ctx))
        return;
    cli_cycle c;
    if(!cli_cycle_for(p, FAULT_CLOSE_SESSIONS, ctx, &c))
        return;
    size_t first = 0, end = 0, killed = 0, burst = 0;
    cli_sessions(&c, &first, &end);
    for(size_t i = first; i < end; i++) {
        const fg_session *s = fg_session_at(i);
        killed += s->killed;
        size_t n = 0;
        for(size_t j = i; j < end && fg_session_at(j)->tOpen - s->tOpen <= 10000.0; j++)
            n++;
        if(n > burst)
            burst = n;
    }
    if(!killed)
        ga_not_tested(ctx, "the client made no call, so no session was closed");
    else if(burst > 4)
        ga_warn(ctx, "%zu sessions within 10 s after the GDS closed the session (12 §6.3)", burst);
    else
        ga_pass(ctx, "%zu session(s) after the GDS closed the session; no reconnect storm",
                end - first);
}

/* CLI-FLT-01: the session drops halfway through the trust list Reads */
static void t_flt_partial(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    const fg_event *good = baseline(p, ctx);
    if(!good)
        return;
    cli_cycle c;
    if(!cli_cycle_for(p, FAULT_TL_DROP, ctx, &c))
        return;
    if(!cli_count(&c, FG_M_TL_READ)) {
        ga_not_tested(ctx, "the client did not read the changed trust list");
        return;
    }
    if(still_good(p, &c, good, ctx, "a trust list download cut off halfway"))
        ga_pass(ctx, "the cut-off download left the previous trust list in use");
}

/* CLI-FLT-07: FinishRequest does not answer */
static void t_flt_hang(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    if(!cli_base_cycle(p, ctx))
        return;
    cli_cycle c;
    if(!cli_cycle_for(p, FAULT_FINISH_HANG, ctx, &c))
        return;
    const fg_event *fin = cli_find(&c, FG_M_FINISH, 0);
    if(!fin) {
        ga_not_tested(ctx, "the client made no FinishRequest in the cycle");
        return;
    }
    if(!fin->clientGone) {
        ga_warn(ctx, "the client still waited for FinishRequest after %.0f s", fin->hungMs / 1000.0);
        return;
    }
    cli_cycle next;
    if(!cli_cycle_for(p, FAULT_NONE, ctx, &next))
        return;
    if(next.end == next.first)
        ga_warn(ctx, "the client gave up after %.0f s but made no call in the next cycle",
                fin->hungMs / 1000.0);
    else
        ga_pass(ctx, "the client gave up the unanswered call after %.0f s and ran the next cycle",
                fin->hungMs / 1000.0);
}

const ga_test cli_faults_tests[] = {
    {"CLI-FLT-03", "12 §7.9.5; 4 §6.1.3", "A certificate from an untrusted CA is not installed", false, true, t_flt_untrusted},
    {"CLI-FLT-04", "12 §7.9.5", "A certificate for another key is not installed", false, true, t_flt_wrong_key},
    {"CLI-FLT-05", "12 §7.9.5; 6 §6.2.2", "A certificate for another ApplicationUri is not installed", false, true, t_flt_wrong_uri},
    {"CLI-FLT-06", "12 §7.9.5; 4 §6.1.3", "An expired certificate is not installed (installed: Warn)", false, true, t_flt_expired},
    {"CLI-FLT-01", "12 §7.6, §7.8.2.4", "A cut-off trust list download is not installed", false, true, t_flt_partial},
    {"CLI-FLT-02", "12 §7.8.2.8", "A malformed trust list is refused", false, true, t_flt_garbage},
    {"CLI-FLT-07", "12 §7.6", "An unanswered call is given up", false, true, t_flt_hang},
    {"CLI-FLT-08", "12 §7.8.2.4; 10000-20 §4.2.4", "Over-long arrays and Reads are refused", false, true, t_flt_lengths},
    {"CLI-FLT-09", "12 §6.3", "No reconnect storm when the GDS closes the session", false, true, t_flt_reconnect},
};
const size_t cli_faults_count = GDS_ARRAY_SIZE(cli_faults_tests);
