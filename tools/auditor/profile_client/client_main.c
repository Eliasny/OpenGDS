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
#include <openssl/rand.h>

#include <stdio.h>
#include <string.h>

#include "client_profile.h"
#include "common/buf.h"
#include "common/limits.h"
#include "common/safeint.h"
#include "common/banned.h"

#define CLI_MAX_TESTS 64
#define CLI_DEFAULT_PORT 4850

gds_status cli_run_cycle(cli_profile *p, fault_id fault, cli_cycle *out) {
    memset(out, 0, sizeof(*out));
    out->fault = fault;
    fg_behaviour b = fault_behaviour(fault);
    fg_set_behaviour(&b);
    out->first = fg_event_count();
    printf("#   cycle %u: fault %s\n", ++p->cycles, fault_name(fault));
    fflush(stdout);
    gds_status r = trig_run(&p->trig, p->user, &out->run);
    out->end = fg_event_count();
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

const cli_cycle *cli_base_cycle(cli_profile *p, ga_ctx *ctx) {
    static gds_status baseStatus = GDS_OK;
    if(!p->base.ran && baseStatus == GDS_OK)
        baseStatus = cli_run_cycle(p, FAULT_NONE, &p->base);
    if(!cycle_usable(&p->base, baseStatus, ctx))
        return NULL;
    return &p->base;
}

bool cli_cycle_for(cli_profile *p, fault_id fault, ga_ctx *ctx, cli_cycle *out) {
    gds_status r = cli_run_cycle(p, fault, out);
    return cycle_usable(out, r, ctx);
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
    } sets[] = {{cli_csr_tests, cli_csr_count}};
    size_t n = 0;
    for(size_t s = 0; s < GDS_ARRAY_SIZE(sets); s++)
        for(size_t i = 0; i < sets[s].n && n < CLI_MAX_TESTS; i++)
            all[n++] = sets[s].t[i];
    return n;
}

static int usage(void) {
    fprintf(stderr,
            "usage: gdsaudit client [--listen PORT] [--listen-any] [--work DIR] [--user NAME]\n"
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
    a.opt.operatorAvailable = a.trigger != NULL;
    printf("# fake GDS %s, CA %s, trigger log %s%s\n", fg_url(), fg_ca_path(), logPath,
           a.trigger ? "" : " (no trigger: every test is Not tested)");
    int rc = ga_run(all, nTests, &p, &a.opt);
    fg_stop();
    return rc;
}
