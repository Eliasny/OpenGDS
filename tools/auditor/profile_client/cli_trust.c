/* OpenGDS Auditor client profile - Trust in the GDS (CLI-TRU-*): the client
 * talks only to the GDS it trusts, over a channel fit for the methods.
 * Rows of docs/auditor/client-profile.md, "Trust in the GDS (cli_trust.c)".
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>

#include "client_profile.h"
#include "common/banned.h"

/* A cycle against a GDS presenting a faulty certificate, after the base
 * cycle (the client holds its certificate, as in normal operation). */
static bool trust_cycle(cli_profile *p, fault_id fault, ga_ctx *ctx, cli_cycle *c) {
    if(!cli_base_cycle(p, ctx))
        return false;
    return cli_cycle_for(p, fault, ctx, c);
}

static void t_tru_no_secret(ga_ctx *ctx, void *profile) {
    cli_cycle c;
    if(!trust_cycle(profile, FAULT_GDS_ROGUE, ctx, &c))
        return;
    size_t first = 0, end = 0, users = 0;
    cli_sessions(&c, &first, &end);
    for(size_t i = first; i < end; i++)
        users += fg_session_at(i)->token == FG_TOKEN_USERNAME;
    if(users)
        ga_fail(ctx, "%zu session(s) with a UserName password to the untrusted gds-rogue", users);
    else
        ga_pass(ctx, "no password sent to gds-rogue (%zu session(s), %zu calls)", end - first,
                c.end - c.first);
}

static void t_tru_nothing_installed(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    if(!cli_base_cycle(p, ctx))
        return;
    const fg_event *good = cli_last_issued();
    if(!good) {
        ga_not_tested(ctx, "the client holds no certificate from the GDS yet");
        return;
    }
    cli_cycle c;
    if(!cli_cycle_for(p, FAULT_GDS_ROGUE, ctx, &c))
        return;
    const fg_event *rogue = NULL;
    for(size_t i = c.first; i < c.end && !rogue; i++) {
        const fg_event *ev = fg_event_at(i);
        if(ev->method == FG_M_FINISH && ev->result == UA_STATUSCODE_GOOD && ev->issued.len)
            rogue = ev;
    }
    cli_probe_result pr;
    if(!cli_probe(p, FG_CA_ROGUE, ctx, &pr))
        return;
    bool trustsRogue = pr.connected;
    cli_probe_clear(&pr);
    if(trustsRogue) {
        ga_fail(ctx, "the client trusts a server certificate from ca-rogue: it installed the "
                     "rogue GDS's trust list");
        return;
    }
    if(!cli_probe(p, FG_CA_MAIN, ctx, &pr))
        return;
    if(!pr.connected)
        ga_fail(ctx, "after the rogue cycle the client no longer connects with its certificate");
    else if(rogue && cli_cert_is(&pr.cert, &rogue->issued))
        ga_fail(ctx, "the client installed the certificate the rogue GDS issued");
    else if(cli_cert_is(&pr.cert, &good->issued))
        ga_pass(ctx, "nothing from gds-rogue was installed; the previous certificate is in use");
    else
        ga_fail(ctx, "the client presents another certificate than its previous one");
    cli_probe_clear(&pr);
}

/* Calls the client made to a GDS whose certificate it must not accept */
static void no_calls(cli_profile *p, ga_ctx *ctx, fault_id fault, const char *what, bool warnOnly) {
    cli_cycle c;
    if(!trust_cycle(p, fault, ctx, &c))
        return;
    size_t n = c.end - c.first;
    if(n == 0)
        ga_pass(ctx, "no GDS method called against %s", what);
    else if(warnOnly)
        ga_warn(ctx, "%zu calls against %s without asking (validity may be suppressed only "
                     "on purpose)", n, what);
    else
        ga_fail(ctx, "%zu calls against %s, first %s", n, what,
                fg_method_name(fg_event_at(c.first)->method));
}

static void t_tru_revoked(ga_ctx *ctx, void *profile) {
    no_calls(profile, ctx, FAULT_GDS_REVOKED, "gds-revoked (its certificate is on the CRL)", false);
}
static void t_tru_expired(ga_ctx *ctx, void *profile) {
    no_calls(profile, ctx, FAULT_GDS_EXPIRED, "gds-expired", true);
}
static void t_tru_wrong_uri(ga_ctx *ctx, void *profile) {
    no_calls(profile, ctx, FAULT_GDS_WRONG_URI,
             "gds-wronguri (its certificate does not name its ApplicationUri)", false);
}

static const char *mode_name(UA_MessageSecurityMode m) {
    switch(m) {
    case UA_MESSAGESECURITYMODE_NONE: return "None";
    case UA_MESSAGESECURITYMODE_SIGN: return "Sign";
    case UA_MESSAGESECURITYMODE_SIGNANDENCRYPT: return "SignAndEncrypt";
    case UA_MESSAGESECURITYMODE_INVALID:
    case __UA_MESSAGESECURITYMODE_FORCE32BIT:
    default: return "unknown";
    }
}

static void t_tru_channel(ga_ctx *ctx, void *profile) {
    const cli_cycle *c = cli_base_cycle(profile, ctx);
    if(!c)
        return;
    const fg_event *bad = NULL, *weak = NULL;
    size_t keyCalls = 0;
    for(size_t i = c->first; i < c->end && !bad; i++) {
        const fg_event *ev = fg_event_at(i);
        const fg_session *s = fg_session_at(ev->session);
        UA_MessageSecurityMode m = s ? s->mode : UA_MESSAGESECURITYMODE_INVALID;
        bool keyMaterial = ev->method == FG_M_SIGN || ev->method == FG_M_NEWKEYPAIR ||
                           ev->method == FG_M_FINISH;
        keyCalls += keyMaterial;
        if(m == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
            continue;
        if(keyMaterial || m != UA_MESSAGESECURITYMODE_SIGN)
            bad = ev;
        else if(!weak && (ev->method == FG_M_STATUS || ev->method == FG_M_TRUSTLIST))
            weak = ev;
    }
    if(bad) {
        const fg_session *s = fg_session_at(bad->session);
        ga_fail(ctx, "%s over %s (12 §7.9: SignAndEncrypt)", fg_method_name(bad->method),
                mode_name(s ? s->mode : UA_MESSAGESECURITYMODE_INVALID));
    } else if(weak) {
        ga_warn(ctx, "%s over Sign (allowed; 12 §7.6 uses SignAndEncrypt)", fg_method_name(weak->method));
    } else if(!keyCalls) {
        ga_not_tested(ctx, "the client made no signing request in its first cycle");
    } else {
        ga_pass(ctx, "all %zu calls over SignAndEncrypt", c->end - c->first);
    }
}

static bool deprecated_policy(const char *uri) {
    static const char *const old[] = {"http://opcfoundation.org/UA/SecurityPolicy#Basic256",
                                      "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"};
    for(size_t i = 0; i < GDS_ARRAY_SIZE(old); i++)
        if(!strcmp(uri, old[i]))
            return true;
    return false;
}

static void t_tru_policy(ga_ctx *ctx, void *profile) {
    const cli_cycle *c = cli_base_cycle(profile, ctx);
    if(!c)
        return;
    size_t first = 0, end = 0;
    cli_sessions(c, &first, &end);
    if(first == end) {
        ga_not_tested(ctx, "the client activated no session in its first cycle");
        return;
    }
    for(size_t i = first; i < end; i++) {
        const fg_session *s = fg_session_at(i);
        if(deprecated_policy(s->policy)) {
            ga_warn(ctx, "the client chose the deprecated %s although current policies were offered",
                    s->policy);
            return;
        }
    }
    ga_pass(ctx, "current policy %s", fg_session_at(first)->policy);
}

const ga_test cli_trust_tests[] = {
    {"CLI-TRU-01", "12 Annex G.1", "No password or secret to an untrusted GDS", false, true, t_tru_no_secret},
    {"CLI-TRU-02", "12 Annex G.1; 4 §6.1.3", "Nothing from an untrusted GDS is installed", false, true, t_tru_nothing_installed},
    {"CLI-TRU-03", "4 §6.1.3", "No calls to a GDS whose certificate is revoked", false, true, t_tru_revoked},
    {"CLI-TRU-04", "4 §6.1.3", "No silent use of a GDS whose certificate expired", false, true, t_tru_expired},
    {"CLI-TRU-05", "4 §6.1.3", "No calls to a GDS whose certificate names another URI", false, true, t_tru_wrong_uri},
    {"CLI-TRU-06", "12 §7.6, §7.9.3-§7.9.5", "Certificate methods over SignAndEncrypt", false, true, t_tru_channel},
    {"CLI-TRU-07", "OPC 10000-7", "A current security policy rather than a deprecated one", false, true, t_tru_policy},
};
const size_t cli_trust_count = GDS_ARRAY_SIZE(cli_trust_tests);
