/* OpenGDS Auditor view-model - runs the engine the way the desktop UI does
 * (avm_run.c: child process, --events /dev/fd/3, GLib main loop) and checks
 * that the verdicts it receives are the pinned ones. With the headless run
 * of the same target checked against the same file, this proves the UI and
 * headless give identical verdicts (Auditor plan, "Shared rules").
 *
 *   avm_selftest EXPECT.csv RUNDIR -- ENGINE PROFILE [ARGS...]
 *
 * --events /dev/fd/3 is added after PROFILE. Exit 0 if every verdict
 * matches EXPECT.csv (id,verdict lines), the reports exist and the engine
 * exited with 0, or with 3 (some tests Not tested) when EXPECT.csv pins
 * those verdicts; 1 otherwise.
 * SPDX-License-Identifier: MPL-2.0 */
#include <stdbool.h>
#include <string.h>

#include "avm_run.h"

#include "common/banned.h"

typedef struct {
    GMainLoop *loop;
    int exitCode;
    gboolean broken;
    size_t events;
} state;

static void on_event(AvmRun *run, const ga_event *ev, void *user) {
    (void)run;
    (void)ev;
    ((state *)user)->events++;
}

static void on_finished(AvmRun *run, int exitCode, const char *error, void *user) {
    (void)run;
    state *s = user;
    s->exitCode = exitCode;
    if(error) {
        g_printerr("run error: %s\n", error);
        s->broken = TRUE;
    }
    g_main_loop_quit(s->loop);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static int compare(const ga_results *r, const char *expectPath) {
    char *text = NULL;
    if(!g_file_get_contents(expectPath, &text, NULL, NULL)) {
        g_printerr("cannot read %s\n", expectPath);
        return 1;
    }
    int bad = 0;
    size_t lines = 0;
    char **rows = g_strsplit(text, "\n", -1);
    for(char **l = rows; *l; l++) {
        char *hash = strchr(*l, '#');
        if(hash)
            *hash = '\0';
        char **kv = g_strsplit(*l, ",", 2);
        if(kv[0] && kv[1]) {
            char *id = g_strstrip(kv[0]), *v = g_strstrip(kv[1]);
            lines++;
            const ga_result *found = NULL;
            for(size_t i = 0; i < r->n; i++)
                if(r->items[i].id && !strcmp(r->items[i].id, id))
                    found = &r->items[i];
            if(!found || !found->done || strcmp(ga_verdict_name(found->verdict), v) != 0) {
                g_printerr("MISMATCH %s: expected %s, UI run got %s\n", id, v,
                           found && found->done ? ga_verdict_name(found->verdict) : "nothing");
                bad++;
            }
        }
        g_strfreev(kv);
    }
    g_strfreev(rows);
    g_free(text);
    if(lines != r->n) {
        g_printerr("MISMATCH: %zu expected lines, %zu tests in the UI run\n", lines, r->n);
        bad++;
    }
    return bad ? 1 : 0;
}

int main(int argc, char **argv) {
    if(argc < 6 || strcmp(argv[3], "--") != 0) {
        g_printerr("usage: avm_selftest EXPECT.csv RUNDIR -- ENGINE PROFILE [ARGS...]\n");
        return 2;
    }
    GPtrArray *a = g_ptr_array_new();
    g_ptr_array_add(a, argv[4]);
    g_ptr_array_add(a, argv[5]);
    g_ptr_array_add(a, (char *)"--events");
    g_ptr_array_add(a, (char *)AVM_EVENTS_FD);
    char *reportDir = g_build_filename(argv[2], "report", NULL);
    g_ptr_array_add(a, (char *)"--report");
    g_ptr_array_add(a, reportDir);
    for(int i = 6; i < argc; i++)
        g_ptr_array_add(a, argv[i]);
    g_ptr_array_add(a, NULL);
    state s = {g_main_loop_new(NULL, FALSE), -1, FALSE, 0};
    AvmRunCallbacks cb = {on_event, NULL, on_finished};
    GError *e = NULL;
    AvmRun *run = avm_run_start((char **)a->pdata, argv[2], &cb, &s, &e);
    if(!run) {
        g_printerr("cannot start the engine: %s\n", e ? e->message : "?");
        return 1;
    }
    g_main_loop_run(s.loop);
    const ga_results *r = avm_run_results(run);
    int rc = compare(r, argv[1]);
    char *html = g_build_filename(reportDir, "report.html", NULL);
    char *junit = g_build_filename(reportDir, "junit.xml", NULL);
    char *events = g_build_filename(argv[2], "events.jsonl", NULL);
    if(!g_file_test(html, G_FILE_TEST_EXISTS) || !g_file_test(junit, G_FILE_TEST_EXISTS) ||
       !g_file_test(events, G_FILE_TEST_EXISTS)) {
        g_printerr("missing report.html, junit.xml or events.jsonl\n");
        rc = 1;
    }
    /* 3: some tests Not tested, such as the push setup tests outside
     * --only SRV-SET; compare() has checked them against EXPECT.csv */
    bool exitOk = s.exitCode == 0 || (s.exitCode == 3 && rc == 0);
    if(s.broken || !exitOk || !r->finishedSeen) {
        g_printerr("engine exit %d, stream %s\n", s.exitCode,
                   r->finishedSeen ? "complete" : "without run_finished");
        rc = 1;
    }
    g_print("UI-path run: %zu events, %zu tests, %s, exit %d\n", s.events, r->n,
            ga_results_outcome(r), s.exitCode);
    g_free(html);
    g_free(junit);
    g_free(events);
    avm_run_free(run);
    g_main_loop_unref(s.loop);
    g_ptr_array_free(a, TRUE);
    g_free(reportDir);
    return rc;
}
