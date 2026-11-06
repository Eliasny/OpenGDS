/* OpenGDS Auditor client profile - shared state of a `gdsaudit client` run.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_CLIENT_PROFILE_H
#define GDSAUDIT_CLIENT_PROFILE_H

#include "harness.h"
#include "fake_gds.h"
#include "faults.h"
#include "trigger.h"

/* One pull cycle of the client: the events [first, end) of the fake GDS. */
typedef struct {
    size_t first, end;
    size_t sessFirst, sessEnd; /* sessions activated during the cycle */
    double tStart, tEnd; /* monotonic ms around the trigger */
    fault_id fault;
    trig_result run;
    bool ran;
} cli_cycle;

/* Cycles several tests look at; each runs once, on first use. */
typedef enum {
    CLI_SHARED_BASE = 0, /* the first cycle, correct GDS: register, sign, trust list */
    CLI_SHARED_SECOND,   /* the next cycle, nothing changed: a certificate held, same list */
    CLI_SHARED_RENEW,    /* after the base: UpdateRequired TRUE */
    CLI_SHARED_COUNT
} cli_shared;

typedef struct {
    trig_cfg trig;
    const char *user;
    cli_cycle shared[CLI_SHARED_COUNT];
    gds_status sharedStatus[CLI_SHARED_COUNT];
    unsigned cycles;
    long probePort;
} cli_profile;

/* One connection of the client to the probe server */
typedef struct {
    bool connected;      /* a session was activated */
    gds_buf cert;        /* the client certificate it presented (chain included) */
    trig_result run;
} cli_probe_result;

/* Start one cycle of the client with the fake GDS answering per `fault`. */
GDS_MUST_CHECK gds_status cli_run_cycle(cli_profile *p, fault_id fault, cli_cycle *out);
/* A shared cycle (run on first use; SECOND and RENEW run the base first).
 * NULL, with the test already decided as Not tested, if the client could
 * not be started. */
const cli_cycle *cli_shared_cycle(cli_profile *p, cli_shared which, ga_ctx *ctx);
#define cli_base_cycle(p, ctx) cli_shared_cycle((p), CLI_SHARED_BASE, (ctx))
/* Run a cycle for one test; NULL (Not tested decided) on failure. */
GDS_MUST_CHECK bool cli_cycle_for(cli_profile *p, fault_id fault, ga_ctx *ctx, cli_cycle *out);

/* Start the probe with an identity from `issuer`, have the client connect
 * to it, record what it presented. false (Not tested decided) on failure. */
GDS_MUST_CHECK bool cli_probe(cli_profile *p, fg_ca_id issuer, ga_ctx *ctx, cli_probe_result *out);
void cli_probe_clear(cli_probe_result *r);
/* true if `presented` (a chain as sent) begins with exactly `cert` */
bool cli_cert_is(const gds_buf *presented, const gds_buf *cert);
/* The last valid certificate the fake GDS issued (FinishRequest Good), or NULL */
const fg_event *cli_last_issued(void);

/* The n-th call of method m in the cycle, or NULL. */
const fg_event *cli_find(const cli_cycle *c, fg_method m, size_t n);
size_t cli_count(const cli_cycle *c, fg_method m);
/* Sessions activated during the cycle: [*first, *end) for fg_session_at */
void cli_sessions(const cli_cycle *c, size_t *first, size_t *end);

/* Test groups (one file each, docs/auditor/client-profile.md) */
extern const ga_test cli_trust_tests[];
extern const size_t cli_trust_count;
extern const ga_test cli_csr_tests[];
extern const size_t cli_csr_count;
extern const ga_test cli_register_tests[];
extern const size_t cli_register_count;
extern const ga_test cli_pending_tests[];
extern const size_t cli_pending_count;
extern const ga_test cli_renew_tests[];
extern const size_t cli_renew_count;
extern const ga_test cli_trustlist_tests[];
extern const size_t cli_trustlist_count;
extern const ga_test cli_install_tests[];
extern const size_t cli_install_count;
extern const ga_test cli_faults_tests[];
extern const size_t cli_faults_count;

/* `gdsaudit client ...` */
int gdsaudit_client_main(int argc, char **argv);

#endif
