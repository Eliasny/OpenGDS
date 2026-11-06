/* OpenGDS Auditor client profile - Trust list download (CLI-TL-*).
 * Rows of docs/auditor/client-profile.md, "Trust list (cli_trustlist.c)".
 * CLI-TL-03..06 need the probe server and follow with it; CLI-TL-08 is slow.
 * SPDX-License-Identifier: MPL-2.0 */
#include "client_profile.h"
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

const ga_test cli_trustlist_tests[] = {
    {"CLI-TL-01", "12 §7.9.9, §7.8.2.4", "Reads the trust list to the end of the file", false, true, t_tl_read_all},
    {"CLI-TL-02", "12 §7.8.2.4", "Closes the file after reading", false, true, t_tl_close},
    {"CLI-TL-07", "12 §7.6", "Skips the download when the list is unchanged", false, true, t_tl_skip_unchanged},
};
const size_t cli_trustlist_count = GDS_ARRAY_SIZE(cli_trustlist_tests);
