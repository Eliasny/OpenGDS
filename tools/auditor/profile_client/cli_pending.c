/* OpenGDS Auditor client profile - Pending approval (CLI-PEN-*).
 * Rows of docs/auditor/client-profile.md, "Pending approval (cli_pending.c)".
 * CLI-PEN-04 (restart hook), -06 (session drop) and -08 (slow) follow.
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

const ga_test cli_pending_tests[] = {
    {"CLI-PEN-01", "12 §7.9.5, §7.6", "A pending request is completed", false, true, t_pen_complete},
    {"CLI-PEN-02", "12 §7.6, §7.9.5", "FinishRequest is polled with a delay", false, true, t_pen_backoff},
    {"CLI-PEN-03", "12 §7.6", "The next cycle resumes the pending request", false, true, t_pen_resume},
    {"CLI-PEN-05", "12 §7.9.5, §7.6", "A rejected request is not polled again", false, true, t_pen_reject},
    {"CLI-PEN-07", "12 §6.3", "No session is held between cycles", false, true, t_pen_sessions},
};
const size_t cli_pending_count = GDS_ARRAY_SIZE(cli_pending_tests);
