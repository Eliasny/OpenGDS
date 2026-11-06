/* OpenGDS Auditor client profile - `gdsaudit client` and the cycle helpers.
 *
 *   gdsaudit client [--listen PORT] [--listen-any] [--work DIR] [--user NAME]
 *                   [--only PREFIX] [--expect FILE.csv] [--cycle-timeout S]
 *                   [--list] -- TRIGGER [ARG...]
 *
 * Starts the fake GDS and, for every pull cycle a test needs, runs TRIGGER
 * (no shell) with GDSAUDIT_GDS_URL, GDSAUDIT_GDS_CA, GDSAUDIT_GDS_CRL,
 * GDSAUDIT_GDS_USER, GDSAUDIT_GDS_PASSWORD_FILE and GDSAUDIT_CLIENT_DIR set.
 * The trigger makes the client under test do one pull cycle against that
 * GDS and then returns. Without a trigger every test is Not tested.
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <openssl/rand.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "client_profile.h"
#include "probe.h"
#include "common/buf.h"
#include "common/limits.h"
#include "common/safeint.h"
#include "common/banned.h"

#define CLI_MAX_TESTS 128
#define CLI_DEFAULT_PORT 4850

static double cli_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

gds_status cli_run_cycle(cli_profile *p, fault_id fault, cli_cycle *out) {
    memset(out, 0, sizeof(*out));
    out->fault = fault;
    fg_behaviour b = fault_behaviour(fault);
    fg_set_behaviour(&b);
    out->first = fg_event_count();
    out->sessFirst = fg_session_count();
    out->tStart = cli_now_ms();
    printf("#   cycle %u: fault %s\n", ++p->cycles, fault_name(fault));
    fflush(stdout);
    gds_status r = trig_run(&p->trig, p->user, &out->run);
    out->end = fg_event_count();
    out->sessEnd = fg_session_count();
    out->tEnd = cli_now_ms();
    fg_behaviour good = fault_behaviour(FAULT_NONE);
    fg_set_behaviour(&good);
    out->ran = r == GDS_OK;
    return r;
}

/* Evidence of the cycle as TAP comments; Not tested if it did not run. */
static bool cycle_usable(const cli_cycle *c, gds_status r, ga_ctx *ctx) {
    if(r != GDS_OK) {
        ga_not_tested(ctx, "the trigger could not be started: %s", gds_status_name(r));
        return false;
    }
    if(!c->run.exited)
        ga_note(ctx, "cycle %s: the trigger was killed after the timeout", fault_name(c->fault));
    else
        ga_note(ctx, "cycle %s: trigger exit %d after %.0f ms, %zu calls", fault_name(c->fault),
                c->run.exitStatus, c->run.ms, c->end - c->first);
    return true;
}

static const cli_cycle *shared_once(cli_profile *p, cli_shared which, ga_ctx *ctx) {
    static const fault_id faults[CLI_SHARED_COUNT] = {FAULT_NONE, FAULT_NONE, FAULT_RENEW};
    cli_cycle *c = &p->shared[which];
    if(!c->ran && p->sharedStatus[which] == GDS_OK)
        p->sharedStatus[which] = cli_run_cycle(p, faults[which], c);
    if(!cycle_usable(c, p->sharedStatus[which], ctx))
        return NULL;
    return c;
}

const cli_cycle *cli_shared_cycle(cli_profile *p, cli_shared which, ga_ctx *ctx) {
    if(which != CLI_SHARED_BASE && !shared_once(p, CLI_SHARED_BASE, ctx))
        return NULL;
    return shared_once(p, which, ctx);
}

void cli_sessions(const cli_cycle *c, size_t *first, size_t *end) {
    *first = c->sessFirst;
    *end = c->sessEnd;
}

bool cli_cycle_for(cli_profile *p, fault_id fault, ga_ctx *ctx, cli_cycle *out) {
    gds_status r = cli_run_cycle(p, fault, out);
    return cycle_usable(out, r, ctx);
}

/* Have the client connect to the started probe server; record the result */
static bool probe_run(cli_profile *p, const char *label, ga_ctx *ctx, cli_probe_result *out) {
    p->trig.action = "probe";
    p->trig.probeUrl = probe_url();
    printf("#   probe connection (%s)\n", label);
    fflush(stdout);
    gds_status r = trig_run(&p->trig, p->user, &out->run);
    p->trig.action = NULL;
    p->trig.probeUrl = NULL;
    out->connected = probe_connected();
    const gds_buf *c = probe_client_cert();
    if(out->connected && c->len && gds_buf_dup(c->data, c->len, &out->cert) != GDS_OK)
        r = GDS_ENOMEM;
    probe_stop();
    if(r != GDS_OK) {
        ga_not_tested(ctx, "the trigger could not be started for the probe: %s", gds_status_name(r));
        cli_probe_clear(out);
        return false;
    }
    ga_note(ctx, "probe (%s): %s (trigger exit %d)", label,
            out->connected ? "connected" : "no session", out->run.exitStatus);
    return true;
}

bool cli_probe(cli_profile *p, fg_ca_id issuer, ga_ctx *ctx, cli_probe_result *out) {
    memset(out, 0, sizeof(*out));
    gds_status r = probe_start(p->probePort, issuer);
    if(r != GDS_OK) {
        ga_not_tested(ctx, "probe server on port %ld: %s", p->probePort, gds_status_name(r));
        return false;
    }
    return probe_run(p,
                     issuer == FG_CA_MAIN    ? "GDS CA"
                     : issuer == FG_CA_X     ? "CA X"
                     : issuer == FG_CA_ROGUE ? "ca-rogue"
                                             : "CA Y",
                     ctx, out);
}

bool cli_probe_identity(cli_profile *p, const gds_buf *cert, const gds_buf *key, const char *label,
                        ga_ctx *ctx, cli_probe_result *out) {
    memset(out, 0, sizeof(*out));
    gds_status r = probe_start_identity(p->probePort, cert, key);
    if(r != GDS_OK) {
        ga_not_tested(ctx, "probe server on port %ld: %s", p->probePort, gds_status_name(r));
        return false;
    }
    return probe_run(p, label, ctx, out);
}

/* Did the trigger end on its own, without a crash? */
bool cli_survived(const trig_result *r) {
    return r->exited && r->exitStatus >= 0 && r->exitStatus < 128;
}

void cli_probe_clear(cli_probe_result *r) {
    gds_buf_free(&r->cert);
    memset(r, 0, sizeof(*r));
}

bool cli_cert_is(const gds_buf *presented, const gds_buf *cert) {
    return cert->len && presented->len >= cert->len &&
           memcmp(presented->data, cert->data, cert->len) == 0;
}

const fg_event *cli_last_issued(void) {
    for(size_t i = fg_event_count(); i-- > 0;) {
        const fg_event *ev = fg_event_at(i);
        if(ev->method == FG_M_FINISH && ev->result == UA_STATUSCODE_GOOD && ev->issued.len &&
           ev->issueMode == FG_ISSUE_GOOD)
            return ev;
    }
    return NULL;
}

const fg_event *cli_find(const cli_cycle *c, fg_method m, size_t n) {
    for(size_t i = c->first; i < c->end; i++) {
        const fg_event *ev = fg_event_at(i);
        if(ev && ev->method == m && n-- == 0)
            return ev;
    }
    return NULL;
}

size_t cli_count(const cli_cycle *c, fg_method m) {
    size_t n = 0;
    for(size_t i = c->first; i < c->end; i++) {
        const fg_event *ev = fg_event_at(i);
        n += ev && ev->method == m;
    }
    return n;
}

static size_t collect(ga_test *all) {
    const struct {
        const ga_test *t;
        size_t n;
    } sets[] = {{cli_csr_tests, cli_csr_count},
                {cli_register_tests, cli_register_count},
                {cli_pending_tests, cli_pending_count},
                {cli_renew_tests, cli_renew_count},
                {cli_trustlist_tests, cli_trustlist_count},
                {cli_install_tests, cli_install_count},
                {cli_faults_tests, cli_faults_count},
                {cli_trust_tests, cli_trust_count}};
    size_t n = 0;
    for(size_t s = 0; s < GDS_ARRAY_SIZE(sets); s++)
        for(size_t i = 0; i < sets[s].n && n < CLI_MAX_TESTS; i++)
            all[n++] = sets[s].t[i];
    return n;
}

static int usage(void) {
    fprintf(stderr,
            "usage: gdsaudit client [--listen PORT (the probe server uses PORT+1)] [--listen-any] [--work DIR] [--user NAME]\n"
            "       [--only PREFIX] [--expect FILE.csv] [--cycle-timeout S] [--list]\n"
            "       -- TRIGGER [ARG...]\n"
            "TRIGGER runs one pull cycle of the client under test against the fake GDS;\n"
            "it gets GDSAUDIT_GDS_URL, _GDS_CA, _GDS_CRL, _GDS_USER, _GDS_PASSWORD_FILE\n"
            "and GDSAUDIT_CLIENT_DIR in its environment.\n");
    return 2;
}

typedef struct {
    long port;
    bool listenAny, list;
    const char *work, *user;
    unsigned timeout;
    ga_run_options opt;
    char **trigger;
} cli_args;

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat option parsing
static bool parse_args(int argc, char **argv, cli_args *a) {
    for(int i = 1; i < argc; i++) {
        const char *k = argv[i];
        if(!strcmp(k, "--")) {
            if(i + 1 < argc)
                a->trigger = argv + i + 1;
            return true;
        }
        if(!strcmp(k, "--listen-any")) { a->listenAny = true; continue; }
        if(!strcmp(k, "--list")) { a->list = true; continue; }
        if(i + 1 >= argc)
            return false;
        const char *v = argv[++i];
        long n = 0;
        if(!strcmp(k, "--listen") && gds_parse_long(v, 1, 65535, &n)) a->port = n;
        else if(!strcmp(k, "--work")) a->work = v;
        else if(!strcmp(k, "--user")) a->user = v;
        else if(!strcmp(k, "--only")) a->opt.only = v;
        else if(!strcmp(k, "--expect")) a->opt.expectCsv = v;
        else if(!strcmp(k, "--cycle-timeout") && gds_parse_long(v, 1, 3600, &n)) a->timeout = (unsigned)n;
        else return false;
    }
    return true;
}

int gdsaudit_client_main(int argc, char **argv) {
    static ga_test all[CLI_MAX_TESTS];
    size_t nTests = collect(all);
    cli_args a = {CLI_DEFAULT_PORT, false, false, "./gdsaudit-client-work", "registrar", 60,
                  {NULL, false, NULL, false}, NULL};
    if(!parse_args(argc, argv, &a))
        return usage();
    if(a.list) {
        for(size_t k = 0; k < nTests; k++)
            printf("%-14s %-28s %s\n", all[k].id, all[k].clause, all[k].title);
        return 0;
    }
    char clientDir[GDS_MAX_PATH], logPath[GDS_MAX_PATH], password[33];
    unsigned char rnd[16];
    if(gds_path(clientDir, sizeof(clientDir), "%s/client", a.work) != GDS_OK ||
       gds_path(logPath, sizeof(logPath), "%s/trigger.log", a.work) != GDS_OK ||
       gds_mkdirs(clientDir, 0700) != GDS_OK) {
        fprintf(stderr, "cannot create %s/client\n", a.work);
        return 2;
    }
    if(RAND_bytes(rnd, sizeof(rnd)) != 1 || gds_hex(rnd, sizeof(rnd), password, sizeof(password)) != GDS_OK) {
        fprintf(stderr, "no random registrar password\n");
        return 2;
    }
    fg_config fc = {a.work, a.port, a.listenAny, a.user, password};
    gds_status s = fg_start(&fc);
    if(s != GDS_OK) {
        fprintf(stderr, "fake GDS on port %ld: %s\n", a.port, gds_status_name(s));
        return 2;
    }
    static cli_profile p;
    p.trig.argv = a.trigger;
    p.trig.logPath = logPath;
    p.trig.clientDir = clientDir;
    p.trig.timeoutSeconds = a.timeout;
    p.user = a.user;
    p.probePort = a.port + 1;
    a.opt.operatorAvailable = a.trigger != NULL;
    printf("# fake GDS %s, CA %s, trigger log %s%s\n", fg_url(), fg_ca_path(), logPath,
           a.trigger ? "" : " (no trigger: every test is Not tested)");
    int rc = ga_run(all, nTests, &p, &a.opt);
    fg_stop();
    return rc;
}
