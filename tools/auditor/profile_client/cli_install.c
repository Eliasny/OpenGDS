/* OpenGDS Auditor client profile - Installation (CLI-INS-*) and CLI-REN-04.
 * Rows of docs/auditor/client-profile.md, "Installation (cli_install.c)" and
 * "Renewal". The probe server shows what the client really presents.
 * CLI-INS-02 (intermediate CA) and CLI-INS-03 (restart hook) follow.
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>

#include "client_profile.h"
#include "test_ca.h"
#include "common/banned.h"

/* Probe with a GDS-CA identity; judge the certificate the client presents
 * against `want`. */
static void presents(cli_profile *p, ga_ctx *ctx, const fg_event *want, const char *what) {
    cli_probe_result pr;
    if(!cli_probe(p, FG_CA_MAIN, ctx, &pr))
        return;
    if(!pr.connected)
        ga_not_tested(ctx, "the client did not connect to the probe server (it trusts the GDS CA)");
    else if(cli_cert_is(&pr.cert, &want->issued))
        ga_pass(ctx, "the client presents the %s certificate, byte for byte", what);
    else
        ga_fail(ctx, "the client presents another certificate than the %s one (%zu bytes)", what,
                pr.cert.len);
    cli_probe_clear(&pr);
}

static void t_ins_presented(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    if(!cli_base_cycle(p, ctx))
        return;
    const fg_event *ev = cli_last_issued();
    if(!ev) {
        ga_not_tested(ctx, "no certificate was issued to the client");
        return;
    }
    presents(p, ctx, ev, "issued");
}

static void t_ren_presented(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    if(!cli_base_cycle(p, ctx))
        return;
    const fg_event *before = cli_last_issued();
    cli_cycle c;
    if(!cli_cycle_for(p, FAULT_RENEW, ctx, &c))
        return;
    const fg_event *ev = cli_last_issued();
    if(!ev || ev == before || (size_t)(ev - fg_event_at(0)) < c.first) {
        ga_not_tested(ctx, "the renewal cycle issued no certificate");
        return;
    }
    presents(p, ctx, ev, "renewed");
}

/* CLI-INS-02: a certificate from the intermediate ca-int; the client must
 * send ca-int after it so a peer that trusts only ca can build the chain */
static void t_ins_chain(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    if(!cli_base_cycle(p, ctx))
        return;
    cli_cycle c;
    if(!cli_cycle_for(p, FAULT_ISSUE_INTERMEDIATE, ctx, &c))
        return;
    const fg_event *iss = NULL;
    for(size_t i = c.first; i < c.end && !iss; i++)
        if(fg_event_at(i)->method == FG_M_FINISH && fg_event_at(i)->issued.len)
            iss = fg_event_at(i);
    if(!iss) {
        ga_not_tested(ctx, "the client fetched no certificate in the cycle");
        return;
    }
    gds_buf inter = {0};
    if(testca_cert_der(fg_ca_int(), &inter) != GDS_OK) {
        ga_not_tested(ctx, "no ca-int certificate");
        return;
    }
    cli_probe_result pr;
    if(cli_probe(p, FG_CA_MAIN, ctx, &pr)) {
        const gds_buf *sent = &pr.cert;
        if(!pr.connected)
            ga_fail(ctx, "the client does not connect with the certificate from ca-int");
        else if(!cli_cert_is(sent, &iss->issued))
            ga_fail(ctx, "the client does not present the certificate issued by ca-int");
        else if(sent->len >= iss->issued.len + inter.len &&
                memcmp(sent->data + iss->issued.len, inter.data, inter.len) == 0)
            ga_pass(ctx, "the client sends its certificate followed by ca-int");
        else
            ga_warn(ctx, "the client sends no chain: a peer must already know ca-int (%zu bytes "
                         "sent, the certificate is %zu)", sent->len, iss->issued.len);
        cli_probe_clear(&pr);
    }
    gds_buf_free(&inter);
}

const ga_test cli_install_tests[] = {
    {"CLI-INS-01", "12 Annex G.1, §7.6", "The issued certificate is the one presented", false, true, t_ins_presented},
    {"CLI-INS-02", "12 §7.9.5; 4 §6.1.3", "A certificate from an intermediate CA is sent with its chain", false, true, t_ins_chain},
    {"CLI-REN-04", "12 §7.6", "After a renewal the new certificate is presented", false, true, t_ren_presented},
};
const size_t cli_install_count = GDS_ARRAY_SIZE(cli_install_tests);
