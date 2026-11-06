/* OpenGDS Auditor view-model - one live run (Auditor plan avm/avm_run.c).
 *
 * Runs the headless engine (gdsaudit) as a child process with
 * --events /dev/fd/3 and turns its event stream into the run's result list
 * on the GLib main loop. The engine holds every test; this file holds none,
 * so the UI shows exactly the verdicts the headless run gives.
 *
 * Each run gets its own folder: events.jsonl (the stream as received),
 * output.log (the engine's TAP and messages) and report/ (the engine's HTML
 * and JUnit reports).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_AVM_RUN_H
#define GDSAUDIT_AVM_RUN_H

#include <gio/gio.h>

#include "results.h"

typedef struct AvmRun AvmRun;

typedef struct {
    /* Every event, after it was applied to avm_run_results(). */
    void (*event)(AvmRun *run, const ga_event *ev, void *user);
    /* One line of the engine's own output (TAP and messages). */
    void (*log)(AvmRun *run, const char *line, void *user);
    /* The engine has exited and its stream is read to the end. exitCode is
     * the engine's exit code (engine.h), or -1 if it was killed. error is
     * set if the run could not start or its stream was broken. */
    void (*finished)(AvmRun *run, int exitCode, const char *error, void *user);
} AvmRunCallbacks;

/* argv[0] is the engine binary; argv must contain "--events /dev/fd/3"
 * (avm_plan_argv with events = AVM_EVENTS_FD). runDir is created. Returns
 * NULL and sets *error if the engine cannot be started. */
#define AVM_EVENTS_FD "/dev/fd/3"
AvmRun *avm_run_start(char **argv, const char *runDir, const AvmRunCallbacks *cb, void *user,
                      GError **error);

/* A finished run read back from a run folder (the UI's own or a headless
 * run's --events file): its events are replayed to cb from the main loop,
 * then finished is called with the run's exit code. NULL and *error if
 * DIR/events.jsonl cannot be read. */
AvmRun *avm_run_open(const char *runDir, const AvmRunCallbacks *cb, void *user, GError **error);

/* Abort: the engine finishes the test in progress, marks the rest Not
 * tested and restores the target, then exits (SIGINT, as Ctrl-C would). */
void avm_run_abort(AvmRun *run);
/* Pause before the next test (the one in progress finishes), or resume. */
void avm_run_pause(AvmRun *run, gboolean paused);
gboolean avm_run_is_running(const AvmRun *run);
const ga_results *avm_run_results(const AvmRun *run);
const char *avm_run_dir(const AvmRun *run);
/* Kills a run still going (no restore: the window is closing) and frees. */
void avm_run_free(AvmRun *run);

/* The engine next to this program (or $GDSAUDIT_ENGINE); g_free it. */
char *avm_engine_path(void);
/* A new run folder under the user data folder: .../gdsaudit/runs/<time>-<profile> */
char *avm_new_run_dir(const char *profile);

/* Export: report.html, junit.xml and events.jsonl into dir. */
gboolean avm_run_export(const AvmRun *run, const char *dir, GError **error);

#endif
