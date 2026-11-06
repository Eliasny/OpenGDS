/* OpenGDS Auditor client profile - Faults (CLI-FLT-*): bad certificates
 * from FinishRequest must not be installed. Rows of
 * docs/auditor/client-profile.md, "Faults (cli_faults.c)". CLI-FLT-01, -02,
 * -07, -08 and -09 (session drops, garbage, hangs) follow.
 * SPDX-License-Identifier: MPL-2.0 */
#include "client_profile.h"
#include "common/banned.h"

static void not_installed(cli_profile *p, ga_ctx *ctx, fault_id fault, const char *what) {
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
    else if(cli_cert_is(&pr.cert, &bad->issued))
        ga_fail(ctx, "the client installed the %s certificate", what);
    else if(cli_cert_is(&pr.cert, &good->issued))
        ga_pass(ctx, "the %s certificate was refused; the previous one is still in use", what);
    else
        ga_fail(ctx, "the client lost its previous certificate (it presents another one)");
    cli_probe_clear(&pr);
}

static void t_flt_untrusted(ga_ctx *ctx, void *profile) {
    not_installed(profile, ctx, FAULT_ISSUE_UNTRUSTED, "untrusted");
}
static void t_flt_wrong_key(ga_ctx *ctx, void *profile) {
    not_installed(profile, ctx, FAULT_ISSUE_WRONG_KEY, "wrong-key");
}
static void t_flt_wrong_uri(ga_ctx *ctx, void *profile) {
    not_installed(profile, ctx, FAULT_ISSUE_WRONG_URI, "wrong-URI");
}
static void t_flt_expired(ga_ctx *ctx, void *profile) {
    not_installed(profile, ctx, FAULT_ISSUE_EXPIRED, "expired");
}

const ga_test cli_faults_tests[] = {
    {"CLI-FLT-03", "12 §7.9.5; 4 §6.1.3", "A certificate from an untrusted CA is not installed", false, true, t_flt_untrusted},
    {"CLI-FLT-04", "12 §7.9.5", "A certificate for another key is not installed", false, true, t_flt_wrong_key},
    {"CLI-FLT-05", "12 §7.9.5; 6 §6.2.2", "A certificate for another ApplicationUri is not installed", false, true, t_flt_wrong_uri},
    {"CLI-FLT-06", "12 §7.9.5; 4 §6.1.3", "An expired certificate is not installed", false, true, t_flt_expired},
};
const size_t cli_faults_count = GDS_ARRAY_SIZE(cli_faults_tests);
