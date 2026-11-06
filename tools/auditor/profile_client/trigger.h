/* OpenGDS Auditor client profile - the trigger hook that starts one pull
 * cycle of the client under test (--trigger-cmd). Belongs in core/hooks.c
 * once the restart hook of the server profile needs the same code.
 *
 * Rules (docs/architecture.md, "No shell-outs"): posix_spawn of an argv
 * array, never through /bin/sh unless the operator writes it so; a timeout;
 * a cleared environment plus an allow-list; output captured as evidence.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_TRIGGER_H
#define GDSAUDIT_TRIGGER_H

#include <stdbool.h>

#include "common/compiler.h"
#include "common/errors.h"

typedef struct {
    char *const *argv;   /* program and arguments, NULL-terminated */
    const char *logPath; /* stdout and stderr of the hook are appended here */
    const char *clientDir; /* GDSAUDIT_CLIENT_DIR: state the client keeps between cycles */
    unsigned timeoutSeconds;
    const char *action;   /* GDSAUDIT_ACTION: NULL (a pull cycle), "probe" or "restart" */
    const char *probeUrl; /* GDSAUDIT_PROBE_URL with action "probe" */
} trig_cfg;

typedef struct {
    bool exited;     /* false: killed after the timeout */
    int exitStatus;  /* exit code when exited */
    double ms;       /* wall time */
} trig_result;

/* Run the hook once while serving the fake GDS (fg_iterate) until it ends.
 * The hook sees GDSAUDIT_GDS_URL, GDSAUDIT_GDS_CA, GDSAUDIT_GDS_CRL,
 * GDSAUDIT_GDS_USER, GDSAUDIT_GDS_PASSWORD_FILE and GDSAUDIT_CLIENT_DIR, and
 * for a probe connection GDSAUDIT_ACTION=probe and GDSAUDIT_PROBE_URL.
 * GDSAUDIT_ACTION=restart asks for a restart of the client (12 §7.6: what
 * it persisted must survive); exit 0 when done, nonzero when unsupported. */
GDS_MUST_CHECK gds_status trig_run(const trig_cfg *cfg, const char *user, trig_result *res);
/* Is the hook of the running trig_run still alive? (does not reap it) */
bool trig_child_running(void);

#endif
