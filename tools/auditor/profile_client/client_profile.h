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
    fault_id fault;
    trig_result run;
    bool ran;
} cli_cycle;

typedef struct {
    trig_cfg trig;
    const char *user;
    cli_cycle base;    /* the first cycle with a correct GDS, shared by tests */
    unsigned cycles;
} cli_profile;

/* Start one cycle of the client with the fake GDS answering per `fault`. */
GDS_MUST_CHECK gds_status cli_run_cycle(cli_profile *p, fault_id fault, cli_cycle *out);
/* The shared first cycle (run on first use). NULL, with the test already
 * decided as Not tested, if the client could not be started. */
const cli_cycle *cli_base_cycle(cli_profile *p, ga_ctx *ctx);
/* Run a cycle for one test; NULL (Not tested decided) on failure. */
GDS_MUST_CHECK bool cli_cycle_for(cli_profile *p, fault_id fault, ga_ctx *ctx, cli_cycle *out);

/* The n-th call of method m in the cycle, or NULL. */
const fg_event *cli_find(const cli_cycle *c, fg_method m, size_t n);
size_t cli_count(const cli_cycle *c, fg_method m);

/* Test groups (one file each, docs/auditor/client-profile.md) */
extern const ga_test cli_csr_tests[];
extern const size_t cli_csr_count;

/* `gdsaudit client ...` */
int gdsaudit_client_main(int argc, char **argv);

#endif
