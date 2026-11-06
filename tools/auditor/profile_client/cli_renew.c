/* OpenGDS Auditor client profile - Renewal (CLI-REN-*).
 * Rows of docs/auditor/client-profile.md, "Renewal (cli_renew.c)".
 * CLI-REN-04 is in cli_install.c (probe server).
 * SPDX-License-Identifier: MPL-2.0 */
#include "client_profile.h"
#include "common/banned.h"

static void t_ren_required(ga_ctx *ctx, void *profile) {
    const cli_cycle *c = cli_shared_cycle(profile, CLI_SHARED_RENEW, ctx);
    if(!c)
        return;
    size_t n = cli_count(c, FG_M_SIGN) + cli_count(c, FG_M_NEWKEYPAIR);
    if(cli_count(c, FG_M_STATUS) == 0)
        ga_not_tested(ctx, "the client did not call GetCertificateStatus");
    else if(n == 0)
        ga_fail(ctx, "UpdateRequired was TRUE but the client made no request in the cycle");
    else
        ga_pass(ctx, "UpdateRequired TRUE: %zu request(s) in the same cycle", n);
}

static void t_ren_not_required(ga_ctx *ctx, void *profile) {
    const cli_cycle *c = cli_shared_cycle(profile, CLI_SHARED_SECOND, ctx);
    if(!c)
        return;
    size_t n = cli_count(c, FG_M_SIGN) + cli_count(c, FG_M_NEWKEYPAIR);
    if(n)
        ga_warn(ctx, "%zu new request(s) while UpdateRequired was FALSE and the certificate is new", n);
    else
        ga_pass(ctx, "no request while UpdateRequired is FALSE");
}

static const char *token_name(fg_token t) {
    switch(t) {
    case FG_TOKEN_ANONYMOUS: return "Anonymous";
    case FG_TOKEN_USERNAME: return "UserName";
    case FG_TOKEN_X509: return "X509";
    case FG_TOKEN_OTHER:
    default: return "another token";
    }
}

static void t_ren_identity(ga_ctx *ctx, void *profile) {
    const cli_cycle *c = cli_shared_cycle(profile, CLI_SHARED_RENEW, ctx);
    if(!c)
        return;
    size_t first = 0, end = 0, user = 0;
    cli_sessions(c, &first, &end);
    if(first == end) {
        ga_not_tested(ctx, "no session in the renewal cycle");
        return;
    }
    for(size_t i = first; i < end; i++)
        user += fg_session_at(i)->token == FG_TOKEN_USERNAME;
    if(user)
        ga_warn(ctx, "%zu of %zu session(s) used UserName credentials while the client holds a "
                     "valid certificate (Annex G.1: ApplicationSelfAdmin)", user, end - first);
    else
        ga_pass(ctx, "renewed with %s (%zu session(s))", token_name(fg_session_at(first)->token),
                end - first);
}

/* CLI-REN-03 (slow): a certificate that expires after 3 cycle periods; the
 * client's own schedule must renew it in time (12 §7.6 sets no lead time) */
static void t_ren_expiry(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    if(!cli_slow_ready(p, ctx) || !cli_base_cycle(p, ctx))
        return;
    p->lifetimeS = 3 * p->period;
    cli_cycle c;
    if(!cli_cycle_for(p, FAULT_ISSUE_SHORT, ctx, &c))
        return;
    const fg_event *iss = cli_last_issued();
    if(!iss || iss->issueMode != FG_ISSUE_SHORT || (size_t)(iss - fg_event_at(0)) < c.first) {
        ga_not_tested(ctx, "the client did not take the short-lived certificate");
        return;
    }
    double expires = iss->tMs + 1000.0 * (double)p->lifetimeS;
    if(!cli_run_for(p, FAULT_NONE, p->lifetimeS + 5, ctx, &c))
        return;
    for(size_t i = c.first; i < c.end; i++) {
        const fg_event *ev = fg_event_at(i);
        if(ev->method == FG_M_FINISH && ev->result == UA_STATUSCODE_GOOD && ev->issued.len &&
           ev->tMs < expires) {
            ga_pass(ctx, "renewed %.0f s before the certificate expired (lifetime %ld s)",
                    (expires - ev->tMs) / 1000.0, p->lifetimeS);
            return;
        }
    }
    ga_warn(ctx, "the certificate (lifetime %ld s) expired without a renewal", p->lifetimeS);
}

const ga_test cli_renew_tests[] = {
    {"CLI-REN-01", "12 §7.9.10, §7.6", "UpdateRequired TRUE starts a request", false, true, t_ren_required},
    {"CLI-REN-02", "12 §7.9.10, §7.6", "No request while UpdateRequired is FALSE", false, true, t_ren_not_required},
    {"CLI-REN-03", "12 §7.6", "A certificate is renewed before it expires (slow)", false, true, t_ren_expiry},
    {"CLI-REN-05", "12 Annex G.1, §7.6", "Renewal authenticates with the certificate, not a password", false, true, t_ren_identity},
};
const size_t cli_renew_count = GDS_ARRAY_SIZE(cli_renew_tests);
