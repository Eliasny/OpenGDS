/* OpenGDS Auditor view-model - tests of the run history and run diff.
 * SPDX-License-Identifier: MPL-2.0 */
#include <glib/gstdio.h>
#include <string.h>

#include "avm_history.h"
#include "avm_run.h"

#include "common/banned.h"

static void eq_str(const char *got, const char *want) {
    if(g_strcmp0(got, want) != 0) {
        g_printerr("expected \"%s\"\n     got \"%s\"\n", want ? want : "(null)",
                   got ? got : "(null)");
        g_test_fail();
    }
}

/* A run folder with an events file: tests given as "ID=verdict" */
static void write_run(const char *root, const char *name, const char *started,
                      const char *const *tests) {
    char *dir = g_build_filename(root, name, NULL);
    g_assert_true(g_mkdir_with_parents(dir, 0700) == 0);
    GString *s = g_string_new(NULL);
    g_string_append_printf(s, "{\"v\":1,\"ev\":\"run_started\",\"profile\":\"server\","
                              "\"target\":\"opc.tcp://plc:4840\",\"planned\":3,"
                              "\"allow_changes\":false,\"time\":\"%s\"}\n",
                           started);
    size_t n = 0;
    for(const char *const *t = tests; *t; t++) {
        char **kv = g_strsplit(*t, "=", 2);
        n++;
        g_string_append_printf(s, "{\"v\":1,\"ev\":\"test_started\",\"n\":%zu,\"id\":\"%s\"}\n"
                                  "{\"v\":1,\"ev\":\"verdict\",\"n\":%zu,\"id\":\"%s\","
                                  "\"verdict\":\"%s\",\"ms\":1,\"evidence\":\"e\"}\n",
                               n, kv[0], n, kv[0], kv[1]);
        g_strfreev(kv);
    }
    g_string_append(s, "{\"v\":1,\"ev\":\"run_finished\",\"exit\":0,\"aborted\":false}\n");
    char *path = g_build_filename(dir, "events.jsonl", NULL);
    g_assert_true(g_file_set_contents(path, s->str, (gssize)s->len, NULL));
    g_free(path);
    g_string_free(s, TRUE);
    g_free(dir);
}

static void load(const char *root, const char *name, ga_results *r) {
    char *path = g_build_filename(root, name, "events.jsonl", NULL);
    char err[256];
    g_assert_true(ga_results_load(path, r, err, sizeof(err)));
    g_free(path);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void test_list_and_diff(void) {
    char *root = g_dir_make_tmp("avm-history-XXXXXX", NULL);
    g_assert_nonnull(root);
    const char *fw1[] = {"SRV-TL-02=pass", "SRV-UPD-01=pass", "SRV-SEC-06=not_supported", NULL};
    const char *fw2[] = {"SRV-TL-02=pass", "SRV-UPD-01=fail", "SRV-NEW-01=warn", NULL};
    write_run(root, "20261106-070000-server", "2026-11-06T07:00:00Z", fw1);
    write_run(root, "20261106-080000-server", "2026-11-06T08:00:00Z", fw2);
    char *junk = g_build_filename(root, "not-a-run", NULL);
    g_assert_true(g_mkdir_with_parents(junk, 0700) == 0);
    char *bad = g_build_filename(root, "broken", NULL);
    g_assert_true(g_mkdir_with_parents(bad, 0700) == 0);
    char *badFile = g_build_filename(bad, "events.jsonl", NULL);
    g_assert_true(g_file_set_contents(badFile, "not json\n", -1, NULL));

    GPtrArray *list = avm_history_list(root);
    g_assert_true(list->len == 2); /* folders without a readable run are skipped */
    const AvmHistoryEntry *newest = g_ptr_array_index(list, 0);
    eq_str(newest->started, "2026-11-06T08:00:00Z");
    eq_str(newest->outcome, "Failed");
    g_assert_true(newest->counts[GA_FAIL] == 1 && newest->counts[GA_WARN] == 1);
    const AvmHistoryEntry *older = g_ptr_array_index(list, 1);
    eq_str(older->outcome, "Passed");
    eq_str(older->target, "opc.tcp://plc:4840");
    g_ptr_array_unref(list);

    ga_results a = {0}, b = {0};
    load(root, "20261106-070000-server", &a);
    load(root, "20261106-080000-server", &b);
    GPtrArray *d = avm_history_diff(&a, &b);
    g_assert_true(d->len == 3);
    eq_str(g_ptr_array_index(d, 0), "SRV-UPD-01: Pass -> Fail");
    eq_str(g_ptr_array_index(d, 1), "SRV-SEC-06: Not supported -> not in the second run");
    eq_str(g_ptr_array_index(d, 2), "SRV-NEW-01: not in the first run -> Warn");
    g_ptr_array_unref(d);
    d = avm_history_diff(&a, &a);
    g_assert_true(d->len == 0);
    g_ptr_array_unref(d);
    ga_results_free(&a);
    ga_results_free(&b);

    list = avm_history_list("/nonexistent/avm-history");
    g_assert_true(list->len == 0);
    g_ptr_array_unref(list);
    g_free(badFile);
    g_free(bad);
    g_free(junk);
    g_free(root); /* the temporary folder is left for inspection */
}

typedef struct {
    GMainLoop *loop;
    size_t events, verdicts;
    int exitCode;
} replay_state;

static void on_event(AvmRun *run, const ga_event *ev, void *user) {
    (void)run;
    replay_state *s = user;
    s->events++;
    s->verdicts += ev->kind == GA_EV_VERDICT;
}

static void on_finished(AvmRun *run, int exitCode, const char *error, void *user) {
    (void)run;
    (void)error;
    replay_state *s = user;
    s->exitCode = exitCode;
    g_main_loop_quit(s->loop);
}

/* A stored run (the UI's own or a headless --events folder) replays into
 * the same callbacks as a live one. */
// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void test_open_replays(void) {
    char *root = g_dir_make_tmp("avm-open-XXXXXX", NULL);
    const char *tests[] = {"SRV-TL-02=pass", "SRV-UPD-01=fail", NULL};
    write_run(root, "r", "2026-11-06T09:00:00Z", tests);
    char *dir = g_build_filename(root, "r", NULL);
    replay_state s = {g_main_loop_new(NULL, FALSE), 0, 0, -1};
    AvmRunCallbacks cb = {on_event, NULL, on_finished};
    GError *e = NULL;
    AvmRun *run = avm_run_open(dir, &cb, &s, &e);
    g_assert_no_error(e);
    g_assert_nonnull(run);
    g_main_loop_run(s.loop);
    g_assert_true(s.events == 6); /* started, 2 x (test, verdict), finished */
    g_assert_true(s.verdicts == 2 && s.exitCode == 0);
    const ga_results *r = avm_run_results(run);
    g_assert_true(r->n == 2 && r->counts[GA_FAIL] == 1);
    eq_str(ga_results_outcome(r), "Failed");
    g_assert_false(avm_run_is_running(run));
    avm_run_free(run);
    /* freed before the replay ran: nothing is called */
    run = avm_run_open(dir, &cb, &s, &e);
    avm_run_free(run);
    char *none = g_build_filename(root, "missing", NULL);
    g_assert_null(avm_run_open(none, &cb, &s, &e));
    g_assert_nonnull(e);
    g_clear_error(&e);
    g_main_loop_unref(s.loop);
    g_free(none);
    g_free(dir);
    g_free(root);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/avm/history/list-and-diff", test_list_and_diff);
    g_test_add_func("/avm/history/open-replays", test_open_replays);
    return g_test_run();
}
