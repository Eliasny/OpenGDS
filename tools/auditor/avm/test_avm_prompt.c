/* OpenGDS Auditor view-model - operator prompts: avm_run passes the
 * engine "--prompts /dev/fd/4", tracks the prompt it waits on, and sends
 * the operator's answer as one clean line (fake_prompt_engine.sh checks it).
 * Usage: test_avm_prompt FAKE_ENGINE_SH RUN_DIR
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
    gboolean prompted, answered, sawNote, pendingCleared;
    int exitCode;
} T;

/* The note is cut to fit one line and loses its control characters. */
static const char note[] = "lamp\nstays\tred\x01 ";
static const char want[] = "1 fail lamp stays red";

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void on_event(AvmRun *run, const ga_event *ev, void *user) {
    T *t = user;
    GError *e = NULL;
    switch(ev->kind) {
    case GA_EV_PROMPT:
        t->prompted = TRUE;
        CHECK(ev->seq == 1 && avm_run_pending_prompt(run) == 1);
        CHECK(!avm_run_answer(run, 2, GA_ANSWER_DONE, NULL, &e) && e); /* not the pending one */
        g_clear_error(&e);
        CHECK(!avm_run_answer(run, 1, (ga_answer)9, NULL, &e) && e); // NOLINT(clang-analyzer-optin.core.EnumCastOutOfRange): out of range on purpose
        g_clear_error(&e);
        t->answered = avm_run_answer(run, 1, GA_ANSWER_FAIL, note, &e);
        if(e)
            g_printerr("answer: %s\n", e->message);
        g_clear_error(&e);
        break;
    case GA_EV_NOTE:
        t->sawNote = ev->text && g_str_has_suffix(ev->text, want);
        break;
    case GA_EV_PROMPT_ANSWERED:
        t->pendingCleared = avm_run_pending_prompt(run) == 0;
        break;
    case GA_EV_RUN_STARTED:
    case GA_EV_TEST_STARTED:
    case GA_EV_VERDICT:
    case GA_EV_RUN_FINISHED:
    case GA_EV_PAUSED:
    case GA_EV_RESUMED:
        break;
    }
}

static void on_log(AvmRun *run, const char *line, void *user) {
    (void)run;
    (void)user;
    g_print("engine: %s\n", line);
}

static void on_finished(AvmRun *run, int exitCode, const char *error, void *user) {
    T *t = user;
    if(error)
        g_printerr("run error: %s\n", error);
    t->exitCode = exitCode;
    GError *e = NULL;
    CHECK(!avm_run_answer(run, 1, GA_ANSWER_DONE, NULL, &e) && e); /* engine gone */
    g_clear_error(&e);
    g_main_loop_quit(t->loop);
}

int main(int argc, char **argv) {
    if(argc != 3) {
        g_printerr("usage: test_avm_prompt FAKE_ENGINE_SH RUN_DIR\n");
        return 2;
    }
    g_setenv("WANT", want, TRUE);
    char *args[] = {(char *)"/bin/sh", argv[1], (char *)"server", NULL};
    T t = {g_main_loop_new(NULL, FALSE), FALSE, FALSE, FALSE, FALSE, -2};
    AvmRunCallbacks cb = {on_event, on_log, on_finished};
    GError *e = NULL;
    AvmRun *run = avm_run_start(args, argv[2], &cb, &t, &e);
    CHECK(run != NULL);
    if(!run) {
        g_printerr("%s\n", e ? e->message : "?");
        return 1;
    }
    g_main_loop_run(t.loop);
    CHECK(t.prompted && t.answered && t.sawNote && t.pendingCleared);
    CHECK(t.exitCode == 0); /* the fake engine got exactly the expected line */
    CHECK(avm_run_results(run)->n == 1);
    avm_run_free(run);
    g_main_loop_unref(t.loop);
    if(failures) {
        g_printerr("%d check(s) failed\n", failures);
        return 1;
    }
    g_print("avm prompt tests passed\n");
    return 0;
}
