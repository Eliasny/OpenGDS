/* OpenGDS Auditor client profile - Trust list download (CLI-TL-*).
 * Rows of docs/auditor/client-profile.md, "Trust list (cli_trustlist.c)".
 * CLI-TL-03, -05 and -06 use the probe server. CLI-TL-04 (a CRL that revokes)
 * and CLI-TL-08 (slow) follow.
 * SPDX-License-Identifier: MPL-2.0 */
#include "client_profile.h"
#include "test_ca.h"
#include "common/banned.h"

/* One cycle with a changed trust list served in Reads of 256 bytes */
static const cli_cycle *short_reads(cli_profile *p, ga_ctx *ctx) {
    static cli_cycle c;
    static gds_status st = GDS_OK;
    static bool done;
    if(!cli_base_cycle(p, ctx))
        return NULL;
    if(!done) {
        st = cli_run_cycle(p, FAULT_TL_SHORT_READS, &c);
        done = true;
    }
    if(st != GDS_OK) {
        ga_not_tested(ctx, "the trigger could not be started: %s", gds_status_name(st));
        return NULL;
    }
    ga_note(ctx, "cycle tl-short-reads: trigger exit %d, %zu calls", c.run.exitStatus, c.end - c.first);
    return &c;
}

/* Index of the last TrustList.Open in the cycle, or c->end */
static size_t last_open(const cli_cycle *c) {
    size_t at = c->end;
    for(size_t i = c->first; i < c->end; i++)
        if(fg_event_at(i)->method == FG_M_TL_OPEN && fg_event_at(i)->result == UA_STATUSCODE_GOOD)
            at = i;
    return at;
}

static void t_tl_read_all(ga_ctx *ctx, void *profile) {
    const cli_cycle *c = short_reads(profile, ctx);
    if(!c)
        return;
    size_t open = last_open(c);
    if(open == c->end) {
        ga_not_tested(ctx, "the client did not open the changed trust list");
        return;
    }
    size_t got = 0, reads = 0, size = fg_trustlist_size();
    for(size_t i = open + 1; i < c->end; i++) {
        const fg_event *ev = fg_event_at(i);
        if(ev->method == FG_M_TL_READ && ev->result == UA_STATUSCODE_GOOD) {
            got += ev->bytes;
            reads++;
        }
    }
    if(got < size)
        ga_fail(ctx, "read %zu of %zu bytes in %zu Read(s): it stopped at a short Read "
                     "(10000-20 §4.2.4: only an empty result is the end)", got, size, reads);
    else
        ga_pass(ctx, "read all %zu bytes in %zu Read(s) of at most 256 bytes", size, reads);
}

static void t_tl_close(ga_ctx *ctx, void *profile) {
    const cli_cycle *c = short_reads(profile, ctx);
    if(!c)
        return;
    size_t open = last_open(c);
    if(open == c->end) {
        ga_not_tested(ctx, "the client did not open the changed trust list");
        return;
    }
    for(size_t i = open + 1; i < c->end; i++) {
        const fg_event *ev = fg_event_at(i);
        if(ev->method == FG_M_TL_CLOSE && ev->result == UA_STATUSCODE_GOOD) {
            ga_pass(ctx, "Close after reading");
            return;
        }
    }
    ga_warn(ctx, "the file handle was left open");
}

static void t_tl_skip_unchanged(ga_ctx *ctx, void *profile) {
    const cli_cycle *c = cli_shared_cycle(profile, CLI_SHARED_SECOND, ctx);
    if(!c)
        return;
    size_t n = cli_count(c, FG_M_TL_OPEN);
    if(n)
        ga_warn(ctx, "the unchanged trust list was downloaded again (%zu Open)", n);
    else
        ga_pass(ctx, "LastUpdateTime unchanged: no download");
}

/* A cycle with a changed list (fault), then a probe from `issuer` */
static bool cycle_then_probe(cli_profile *p, fault_id fault, fg_ca_id issuer, ga_ctx *ctx,
                             cli_probe_result *pr) {
    cli_cycle c;
    if(!cli_base_cycle(p, ctx) || !cli_cycle_for(p, fault, ctx, &c))
        return false;
    if(cli_count(&c, FG_M_TL_OPEN) == 0) {
        ga_not_tested(ctx, "the client did not download the changed trust list");
        return false;
    }
    return cli_probe(p, issuer, ctx, pr);
}

/* CA X added, then removed: TL-03 and TL-05 share it */
static int with_x(cli_profile *p, ga_ctx *ctx) {
    static int state = -1; /* -1 not run, 0 failed to run, 1 refused, 2 connected */
    if(state < 0) {
        cli_probe_result pr;
        state = cycle_then_probe(p, FAULT_TL_WITH_X, FG_CA_X, ctx, &pr) ? 1 + pr.connected : 0;
        if(state)
            cli_probe_clear(&pr);
        return state;
    }
    if(state == 0)
        ga_not_tested(ctx, "the trust list with CA X could not be served or probed");
    return state;
}

static void t_tl_trusted(ga_ctx *ctx, void *profile) {
    int s = with_x(profile, ctx);
    if(s == 2)
        ga_pass(ctx, "the probe with a certificate from CA X (now in TrustedCertificates) was accepted");
    else if(s == 1)
        ga_fail(ctx, "the probe with a certificate from CA X was refused: the new trust list is not in use");
}

static void t_tl_replace(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    int s = with_x(p, ctx);
    if(s == 0)
        return;
    if(s == 1) {
        ga_not_tested(ctx, "CA X was never accepted, so its removal cannot be seen");
        return;
    }
    cli_probe_result pr;
    if(!cycle_then_probe(p, FAULT_TL_MAIN, FG_CA_X, ctx, &pr))
        return;
    if(pr.connected)
        ga_fail(ctx, "CA X is still trusted after the list without it was installed (merged, not replaced)");
    else
        ga_pass(ctx, "CA X is no longer trusted once the list without it is installed");
    cli_probe_clear(&pr);
}

static void t_tl_issuers(ga_ctx *ctx, void *profile) {
    cli_probe_result pr;
    if(!cycle_then_probe(profile, FAULT_TL_ISSUER_Y, FG_CA_Y, ctx, &pr))
        return;
    if(pr.connected)
        ga_fail(ctx, "a leaf from CA Y, which is only in IssuerCertificates, was accepted");
    else
        ga_pass(ctx, "a leaf from an issuer-only CA was refused");
    cli_probe_clear(&pr);
}

/* CLI-TL-04: a CRL in the trust list revokes the probe's certificate */
static void t_tl_crl(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    if(!cli_base_cycle(p, ctx))
        return;
    cli_probe_result pr;
    if(!cli_probe(p, FG_CA_MAIN, ctx, &pr))
        return;
    bool worked = pr.connected;
    cli_probe_clear(&pr);
    if(!worked) {
        ga_not_tested(ctx, "the client does not connect to a probe from the GDS CA at all");
        return;
    }
    gds_buf cert = {0}, key = {0};
    if(testca_issue(fg_ca(FG_CA_MAIN), "OpenGDS Auditor TEST revoked probe", "urn:opengds:auditor:probe",
                    "localhost", 1, &cert, &key) != GDS_OK ||
       fg_set_revoked_cert(&cert) != GDS_OK) {
        ga_not_tested(ctx, "cannot make the revoked probe identity");
        gds_buf_free(&cert);
        gds_buf_free_secret(&key);
        return;
    }
    cli_cycle c;
    if(cli_cycle_for(p, FAULT_TL_REVOKING, ctx, &c)) {
        if(!cli_count(&c, FG_M_TL_READ))
            ga_not_tested(ctx, "the client did not download the changed trust list");
        else if(cli_probe_identity(p, &cert, &key, "revoked by the list's CRL", ctx, &pr)) {
            if(pr.connected)
                ga_fail(ctx, "the client connected to a server whose certificate the trust "
                             "list's CRL revokes");
            else
                ga_pass(ctx, "the client refused the probe revoked by the CRL in the trust list");
            cli_probe_clear(&pr);
        }
    }
    gds_buf_free(&cert);
    gds_buf_free_secret(&key);
}

const ga_test cli_trustlist_tests[] = {
    {"CLI-TL-01", "12 §7.9.9, §7.8.2.4", "Reads the trust list to the end of the file", false, true, t_tl_read_all},
    {"CLI-TL-02", "12 §7.8.2.4", "Closes the file after reading", false, true, t_tl_close},
    {"CLI-TL-03", "12 §7.9.9; 4 §6.1.3", "A CA added to the trust list is trusted", false, true, t_tl_trusted},
    {"CLI-TL-04", "12 §7.9.9; 4 §6.1.3", "A certificate revoked by a CRL in the list is refused", false, true, t_tl_crl},
    {"CLI-TL-05", "12 §7.8.2.8; 4 §6.1.3", "A new trust list replaces the old one", false, true, t_tl_replace},
    {"CLI-TL-06", "12 §7.8.2.8; 4 §6.1.3", "Issuer-only CAs are not trusted", false, true, t_tl_issuers},
    {"CLI-TL-07", "12 §7.6", "Skips the download when the list is unchanged", false, true, t_tl_skip_unchanged},
};
const size_t cli_trustlist_count = GDS_ARRAY_SIZE(cli_trustlist_tests);
