/* OpenGDS Auditor view-model - the real engine through avm_run, on every
 * platform the desktop UI runs on (Linux: fds 3 and 4 and signals;
 * Windows: named pipes and the engine's --control events).
 *
 * The GDS profile against a port where nothing listens gives a run of
 * many short Not tested tests without any target. On it: events and the
 * engine's output arrive; pause holds the run between two tests and resume
 * goes on; abort ends it as aborted; the exit code is the run's.
 * Usage: test_avm_engine ENGINE RUN_DIR
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>

#include "avm_run.h"

static int failures;

#define CHECK(c)                                                                                   \
    do {                                                                                           \
        if(!(c)) {                                                                                 \
            g_printerr("%s:%d: check failed: %s\n", __FILE__, __LINE__, #c);                       \
            failures++;                                                                            \
        }                                                                                          \
    } while(0)

typedef struct {
    GMainLoop *loop;
    AvmRun *run;
    size_t started, startedAtPause, logLines;
    gboolean paused, resumed, abortSent, finished, startedWhilePaused, idle;
    int exitCode;
    char *error;
} T;

static gboolean resume(gpointer data) {
    T *t = data;
    t->startedWhilePaused = t->started > t->startedAtPause;
    avm_run_pause(t->run, FALSE);
    return G_SOURCE_REMOVE;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void on_event(AvmRun *run, const ga_event *ev, void *user) {
    T *t = user;
    GError *e = NULL;
    switch(ev->kind) {
    case GA_EV_TEST_STARTED:
        t->started++;
        if(t->started == 1) {
            /* no prompt is pending: an answer is refused, not sent */
            CHECK(avm_run_pending_prompt(run) == 0);
            CHECK(!avm_run_answer(run, 1, GA_ANSWER_DONE, NULL, &e) && e);
            g_clear_error(&e);
            avm_run_pause(run, TRUE);
        }
        break;
    case GA_EV_PAUSED:
        t->paused = TRUE;
        t->startedAtPause = t->started;
        g_timeout_add(2000, resume, t);
        break;
    case GA_EV_RESUMED:
        t->resumed = TRUE;
        break;
    case GA_EV_VERDICT:
        if(t->resumed && !t->abortSent && t->started > t->startedAtPause) {
            t->abortSent = TRUE;
            avm_run_abort(run);
        }
        break;
    case GA_EV_RUN_STARTED:
    case GA_EV_NOTE:
    case GA_EV_RUN_FINISHED:
    case GA_EV_PROMPT:
    case GA_EV_PROMPT_ANSWERED:
        break;
    }
}

static void on_log(AvmRun *run, const char *line, void *user) {
    (void)run;
    (void)line;
    ((T *)user)->logLines++;
}

static void on_finished(AvmRun *run, int exitCode, const char *error, void *user) {
    (void)run;
    T *t = user;
    t->finished = TRUE;
    t->exitCode = exitCode;
    t->error = g_strdup(error);
    g_main_loop_quit(t->loop);
}

static gboolean on_timeout(gpointer data) {
    T *t = data;
    g_printerr("timed out: started %zu, paused %d, resumed %d, abort sent %d\n", t->started,
               t->paused, t->resumed, t->abortSent);
    failures++;
    g_main_loop_quit(t->loop);
    return G_SOURCE_REMOVE;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
int main(int argc, char **argv) {
    if(argc != 3) {
        g_printerr("usage: %s ENGINE RUN_DIR\n", argv[0]);
        return 2;
    }
    char *work = g_build_filename(argv[2], "auditor", NULL);
    char *cert = g_build_filename(work, "own", "cert.der", NULL);
    char *runDir = g_build_filename(argv[2], "run", NULL);
    char *init[] = {argv[1], "server", "--work", work, "--init-only", NULL};
    gint st = 0;
    GError *e = NULL;
    /* the engine's own identity: some DER to give --trust */
    if(!g_spawn_sync(NULL, init, NULL, G_SPAWN_STDOUT_TO_DEV_NULL, NULL, NULL, NULL, NULL, &st,
                     &e) ||
       !g_spawn_check_wait_status(st, &e)) {
        g_printerr("%s --init-only: %s\n", argv[1], e ? e->message : "failed");
        return 2;
    }
    char *run[] = {argv[1], "gds", "--url", "opc.tcp://127.0.0.1:9", "--trust", cert,
                   "--work", work, "--events", AVM_EVENTS_FD, NULL};
    T t = {.loop = g_main_loop_new(NULL, FALSE), .exitCode = -2};
    AvmRunCallbacks cb = {on_event, on_log, on_finished};
    t.run = avm_run_start(run, runDir, &cb, &t, &e);
    if(!t.run) {
        g_printerr("avm_run_start: %s\n", e->message);
        return 2;
    }
    guint timer = g_timeout_add_seconds(240, on_timeout, &t);
    g_main_loop_run(t.loop);
    g_source_remove(timer);

    CHECK(t.finished);
    CHECK(t.error == NULL);
    if(t.error)
        g_printerr("run error: %s\n", t.error);
    CHECK(t.logLines > 0);
    CHECK(t.paused && t.resumed);
    CHECK(!t.startedWhilePaused);
    CHECK(t.abortSent);
    const ga_results *r = avm_run_results(t.run);
    CHECK(r->finishedSeen);
    CHECK(r->aborted);
    CHECK(r->exitCode == t.exitCode);
    CHECK(r->n == r->planned && r->planned > 2); /* aborted: the rest Not tested */
    CHECK(t.exitCode == 3); /* Not tested, nothing failed */
    char *copy = g_build_filename(runDir, "events.jsonl", NULL);
    CHECK(g_file_test(copy, G_FILE_TEST_IS_REGULAR));
    g_free(copy);
    g_print("engine run through avm_run: %zu tests started, exit %d, %zu log lines\n", t.started,
            t.exitCode, t.logLines);

    avm_run_free(t.run);
    g_main_loop_unref(t.loop);
    g_free(t.error);
    g_free(runDir);
    g_free(cert);
    g_free(work);
    if(failures) {
        g_printerr("%d check(s) failed\n", failures);
        return 1;
    }
    g_print("ok\n");
    return 0;
}
