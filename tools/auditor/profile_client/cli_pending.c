/* OpenGDS Auditor client profile - Pending approval (CLI-PEN-*).
 * Rows of docs/auditor/client-profile.md, "Pending approval (cli_pending.c)".
 * CLI-PEN-08 is slow.
 * SPDX-License-Identifier: MPL-2.0 */
#include "client_profile.h"
#include "common/banned.h"

#define PEN_MAX_CYCLES 5
#define PEN_MIN_INTERVAL_MS 900.0 /* "after a short delay" (12 §7.6); 1 s less jitter */
#define PEN_MAX_POLLS 3           /* per request and cycle; §7.6 says about 2 */

/* A new request that stays pending for 3 FinishRequest calls, over up to 5 cycles */
typedef struct {
    cli_cycle c[PEN_MAX_CYCLES];
    size_t n;
    const fg_event *sign;     /* the request that went pending */
    const fg_event *issued;   /* FinishRequest Good for it, or NULL */
    size_t issuedCycle;
    gds_status st;
} pen_run;

static const fg_event *finish_good(const cli_cycle *c, const UA_NodeId *rid) {
    for(size_t i = c->first; i < c->end; i++) {
        const fg_event *ev = fg_event_at(i);
        if(ev->method == FG_M_FINISH && ev->result == UA_STATUSCODE_GOOD &&
           UA_NodeId_equal(&ev->requestId, rid))
            return ev;
    }
    return NULL;
}

static const pen_run *pending_run(cli_profile *p, ga_ctx *ctx) {
    static pen_run r;
    static bool done;
    if(!cli_base_cycle(p, ctx))
        return NULL;
    while(!done && r.n < PEN_MAX_CYCLES && !r.issued) {
        cli_cycle *c = &r.c[r.n];
        if((r.st = cli_run_cycle(p, FAULT_PENDING, c)) != GDS_OK)
            break;
        r.n++;
        if(!r.sign)
            r.sign = cli_find(c, FG_M_SIGN, 0);
        if(r.sign && (r.issued = finish_good(c, &r.sign->requestId)) != NULL)
            r.issuedCycle = r.n - 1;
    }
    done = true;
    if(r.st != GDS_OK) {
        ga_not_tested(ctx, "the trigger could not be started: %s", gds_status_name(r.st));
        return NULL;
    }
    if(!r.sign) {
        ga_not_tested(ctx, "UpdateRequired was TRUE but the client made no signing request");
        return NULL;
    }
    ga_note(ctx, "pending scenario: %zu cycle(s), issued %s", r.n, r.issued ? "yes" : "no");
    return &r;
}

static void t_pen_complete(ga_ctx *ctx, void *profile) {
    const pen_run *r = pending_run(profile, ctx);
    if(!r)
        return;
    if(r->issued)
        ga_pass(ctx, "the pending request was issued in cycle %zu with the same RequestId",
                r->issuedCycle + 1);
    else
        ga_fail(ctx, "the pending request did not complete within %d cycles", PEN_MAX_CYCLES);
}

static void t_pen_backoff(ga_ctx *ctx, void *profile) {
    const pen_run *r = pending_run(profile, ctx);
    if(!r)
        return;
    double minGap = -1.0;
    size_t maxPolls = 0, total = 0;
    for(size_t k = 0; k < r->n; k++) {
        const fg_event *prev = NULL;
        size_t polls = 0;
        for(size_t i = r->c[k].first; i < r->c[k].end; i++) {
            const fg_event *ev = fg_event_at(i);
            if(ev->method != FG_M_FINISH)
                continue;
            polls++;
            if(prev && (minGap < 0 || ev->tMs - prev->tMs < minGap))
                minGap = ev->tMs - prev->tMs;
            prev = ev;
        }
        total += polls;
        if(polls > maxPolls)
            maxPolls = polls;
    }
    if(total == 0)
        ga_not_tested(ctx, "no FinishRequest while the request was pending");
    else if(minGap >= 0 && minGap < PEN_MIN_INTERVAL_MS)
        ga_warn(ctx, "FinishRequest calls %.0f ms apart (at least 1 s expected)", minGap);
    else if(maxPolls > PEN_MAX_POLLS)
        ga_warn(ctx, "%zu FinishRequest calls in one cycle (12 §7.6: about 2)", maxPolls);
    else
        ga_pass(ctx, "%zu FinishRequest call(s), at most %zu per cycle, gaps >= 1 s", total, maxPolls);
}

static void t_pen_resume(ga_ctx *ctx, void *profile) {
    const pen_run *r = pending_run(profile, ctx);
    if(!r)
        return;
    if(r->n < 2) {
        ga_not_tested(ctx, "the request completed within the first cycle");
        return;
    }
    const cli_cycle *c = &r->c[1];
    for(size_t i = c->first; i < c->end; i++) {
        const fg_event *ev = fg_event_at(i);
        if(ev->method == FG_M_SIGN || ev->method == FG_M_NEWKEYPAIR) {
            ga_warn(ctx, "the next cycle began with a new %s instead of the pending request",
                    fg_method_name(ev->method));
            return;
        }
        if(ev->method == FG_M_FINISH) {
            if(UA_NodeId_equal(&ev->requestId, &r->sign->requestId))
                ga_pass(ctx, "the next cycle began with FinishRequest for the pending RequestId");
            else
                ga_warn(ctx, "the next cycle polled another RequestId");
            return;
        }
    }
    ga_warn(ctx, "the next cycle did not come back to the pending request");
}

static void t_pen_reject(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    if(!cli_base_cycle(p, ctx))
        return;
    cli_cycle a, b;
    if(!cli_cycle_for(p, FAULT_REJECT, ctx, &a) || !cli_cycle_for(p, FAULT_NONE, ctx, &b))
        return;
    const fg_event *rej = NULL;
    size_t after = 0;
    for(size_t i = a.first; i < b.end; i++) {
        const fg_event *ev = fg_event_at(i);
        if(ev->method != FG_M_FINISH)
            continue;
        if(!rej && ev->result == UA_STATUSCODE_BADREQUESTNOTALLOWED)
            rej = ev;
        else if(rej && UA_NodeId_equal(&ev->requestId, &rej->requestId))
            after++;
    }
    if(!rej)
        ga_not_tested(ctx, "the client did not call FinishRequest for the rejected request");
    else if(after)
        ga_fail(ctx, "FinishRequest called %zu more time(s) for the rejected RequestId", after);
    else
        ga_pass(ctx, "the rejected RequestId was not polled again (this and the next cycle)");
}

static void t_pen_sessions(ga_ctx *ctx, void *profile) {
    const cli_cycle *c = cli_base_cycle(profile, ctx);
    if(!c)
        return;
    size_t first = 0, end = 0, open = 0;
    cli_sessions(c, &first, &end);
    if(first == end) {
        ga_not_tested(ctx, "no session in the cycle");
        return;
    }
    for(size_t i = first; i < end; i++)
        open += !fg_session_at(i)->closed;
    if(open)
        ga_fail(ctx, "%zu of %zu session(s) still open after the cycle ended (12 §6.3)", open,
                end - first);
    else
        ga_pass(ctx, "all %zu session(s) closed when the cycle ended", end - first);
}

/* CLI-PEN-06: the session drops after StartSigningRequest and the GDS has
 * forgotten the request; the client must recover in a later cycle. */
static void t_pen_recover(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    if(!cli_base_cycle(p, ctx))
        return;
    cli_cycle c;
    if(!cli_cycle_for(p, FAULT_DROP_AFTER_SIGN, ctx, &c))
        return;
    if(!cli_count(&c, FG_M_SIGN)) {
        ga_not_tested(ctx, "the client made no signing request in the faulty cycle");
        return;
    }
    size_t invalid = 0;
    for(int k = 0; k < 2; k++) {
        if(!cli_cycle_for(p, FAULT_RENEW, ctx, &c))
            return;
        if(cli_count(&c, FG_M_SIGN) || cli_count(&c, FG_M_NEWKEYPAIR)) {
            ga_pass(ctx, "a new request in cycle %d after the forgotten one", k + 2);
            return;
        }
        for(size_t i = c.first; i < c.end; i++)
            invalid += fg_event_at(i)->method == FG_M_FINISH &&
                       fg_event_at(i)->result == UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    ga_warn(ctx, "stuck: no new request in 2 cycles (%zu FinishRequest calls answered "
                 "Bad_InvalidArgument)", invalid);
}

/* CLI-PEN-04: the client restarts while a request is pending; it must
 * resume the persisted RequestId (12 §7.6) */
static void t_pen_restart(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    if(!cli_base_cycle(p, ctx))
        return;
    cli_cycle c;
    if(!cli_cycle_for(p, FAULT_PENDING_HOLD, ctx, &c))
        return;
    const fg_event *sign = NULL;
    for(size_t i = c.first; i < c.end; i++)
        if((fg_event_at(i)->method == FG_M_SIGN || fg_event_at(i)->method == FG_M_NEWKEYPAIR) &&
           fg_event_at(i)->result == UA_STATUSCODE_GOOD)
            sign = fg_event_at(i);
    if(!sign) {
        ga_not_tested(ctx, "the client made no request in the pending cycle");
        return;
    }
    if(!cli_restart(p, ctx) || !cli_cycle_for(p, FAULT_NONE, ctx, &c))
        return;
    for(size_t i = c.first; i < c.end; i++) {
        const fg_event *ev = fg_event_at(i);
        if(ev->method == FG_M_SIGN || ev->method == FG_M_NEWKEYPAIR) {
            ga_warn(ctx, "after the restart the client made a new %s instead of resuming the "
                         "pending request", fg_method_name(ev->method));
            return;
        }
        if(ev->method == FG_M_FINISH) {
            if(UA_NodeId_equal(&ev->requestId, &sign->requestId))
                ga_pass(ctx, "after the restart the client resumed the pending RequestId");
            else
                ga_warn(ctx, "after the restart the client polled another RequestId");
            return;
        }
    }
    ga_warn(ctx, "after the restart the client did not come back to the pending request");
}

/* CLI-PEN-08 (slow): the second cycle of the client's own schedule starts
 * after a random delay of 1 % up to at least 10 % of the period (12 §6.3).
 * Three runs; the delay is the start-to-start time less the period. */
#define PEN_JITTER_RUNS 3
static void t_pen_jitter(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    if(!cli_slow_ready(p, ctx) || !cli_base_cycle(p, ctx))
        return;
    double periodMs = 1000.0 * (double)p->period, d[PEN_JITTER_RUNS];
    for(int k = 0; k < PEN_JITTER_RUNS; k++) {
        cli_cycle c;
        if(!cli_run_for(p, FAULT_NONE, p->period + p->period / 5 + 10, ctx, &c))
            return;
        /* cycle starts: sessions more than half a period apart */
        double t1 = -1, t2 = -1;
        for(size_t i = c.sessFirst; i < c.sessEnd && t2 < 0; i++) {
            const fg_session *s = fg_session_at(i);
            if(t1 < 0)
                t1 = s->tOpen;
            else if(s->tOpen - t1 > periodMs / 2)
                t2 = s->tOpen;
        }
        if(t2 < 0) {
            ga_not_tested(ctx, "run %d: the client ran no second cycle", k + 1);
            return;
        }
        d[k] = t2 - t1 - periodMs;
        ga_note(ctx, "run %d: second cycle %.0f ms after the period (%.1f %%)", k + 1, d[k],
                100.0 * d[k] / periodMs);
    }
    double lo = d[0], hi = d[0];
    for(int k = 1; k < PEN_JITTER_RUNS; k++) {
        lo = d[k] < lo ? d[k] : lo;
        hi = d[k] > hi ? d[k] : hi;
    }
    if(lo < 0.01 * periodMs)
        ga_warn(ctx, "a second cycle started %.0f ms after the period, under 1 %% of it", lo);
    else if(hi - lo < 0.002 * periodMs)
        ga_warn(ctx, "the delays of %d runs are the same within %.0f ms: not random",
                PEN_JITTER_RUNS, hi - lo);
    else
        ga_pass(ctx, "delays %.1f to %.1f %% of the period", 100.0 * lo / periodMs,
                100.0 * hi / periodMs);
}

const ga_test cli_pending_tests[] = {
    {"CLI-PEN-01", "12 §7.9.5, §7.6", "A pending request is completed", false, true, t_pen_complete},
    {"CLI-PEN-02", "12 §7.6, §7.9.5", "FinishRequest is polled with a delay", false, true, t_pen_backoff},
    {"CLI-PEN-03", "12 §7.6", "The next cycle resumes the pending request", false, true, t_pen_resume},
    {"CLI-PEN-04", "12 §7.6", "A pending request survives a restart", false, true, t_pen_restart},
    {"CLI-PEN-05", "12 §7.9.5, §7.6", "A rejected request is not polled again", false, true, t_pen_reject},
    {"CLI-PEN-06", "12 §7.9.5", "Recovers when the GDS forgot the pending request", false, true, t_pen_recover},
    {"CLI-PEN-07", "12 §6.3", "No session is held between cycles", false, true, t_pen_sessions},
    {"CLI-PEN-08", "12 §6.3", "The second cycle starts after a random delay (slow)", false, true, t_pen_jitter},
};
const size_t cli_pending_count = GDS_ARRAY_SIZE(cli_pending_tests);
