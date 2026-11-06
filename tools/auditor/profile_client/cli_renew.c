/* OpenGDS Auditor client profile - Renewal (CLI-REN-*).
 * Rows of docs/auditor/client-profile.md, "Renewal (cli_renew.c)".
 * CLI-REN-03 (slow) and CLI-REN-04 (probe server) follow.
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

const ga_test cli_renew_tests[] = {
    {"CLI-REN-01", "12 §7.9.10, §7.6", "UpdateRequired TRUE starts a request", false, true, t_ren_required},
    {"CLI-REN-02", "12 §7.9.10, §7.6", "No request while UpdateRequired is FALSE", false, true, t_ren_not_required},
    {"CLI-REN-05", "12 Annex G.1, §7.6", "Renewal authenticates with the certificate, not a password", false, true, t_ren_identity},
};
const size_t cli_renew_count = GDS_ARRAY_SIZE(cli_renew_tests);
