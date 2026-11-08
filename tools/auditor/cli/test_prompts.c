/* OpenGDS Auditor - operator prompts end to end in the engine: ga_prompt
 * through the --prompts reader (cli/prompts.c), the verdicts each answer
 * gives, the events, and the answer line parser.
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "harness.h"
#include "prompts.h"

#include "common/banned.h"

static int failures;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if(!(cond)) {                                                                              \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);               \
            failures++;                                                                            \
        }                                                                                          \
    } while(0)

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void parse(void) {
    size_t seq = 0;
    ga_answer a = GA_ANSWER_DONE;
    char note[16];
    CHECK(prompts_parse_line("3 fail the lamp stays red", &seq, &a, note, sizeof(note)));
    CHECK(seq == 3 && a == GA_ANSWER_FAIL && !strcmp(note, "the lamp stays ")); /* cut */
    CHECK(prompts_parse_line("12 done", &seq, &a, note, sizeof(note)));
    CHECK(seq == 12 && a == GA_ANSWER_DONE && note[0] == '\0');
    CHECK(prompts_parse_line("1 skip ", &seq, &a, note, sizeof(note)) && a == GA_ANSWER_SKIP);
    const char *bad[] = {"", "done", "0 done", "01 done", "1done", "1  done", "1 DONE",
                         "1 maybe", "-1 done", "1 donex", "99999999 done"};
    for(size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        bool ok = prompts_parse_line(bad[i], &seq, &a, note, sizeof(note));
        if(ok)
            fprintf(stderr, "accepted: \"%s\"\n", bad[i]);
        CHECK(!ok);
    }
}

/* What the run emitted */
typedef struct {
    ga_verdict verdict[8];
    size_t prompts, answered;
    ga_answer answers[8];
    char lastAnswerNote[128];
} seen;

static void sink(const ga_event *ev, void *user) {
    seen *s = user;
    if(ev->kind == GA_EV_VERDICT && ev->n >= 1 && ev->n <= 8)
        s->verdict[ev->n - 1] = ev->verdict;
    if(ev->kind == GA_EV_PROMPT)
        s->prompts++;
    if(ev->kind == GA_EV_PROMPT_ANSWERED && s->answered < 8) {
        s->answers[s->answered++] = ev->answer;
        snprintf(s->lastAnswerNote, sizeof(s->lastAnswerNote), "%s", ev->text ? ev->text : "");
    }
}

static void step(ga_ctx *ctx, void *p) {
    (void)p;
    char note[64];
    ga_answer a = ga_prompt(ctx, note, sizeof(note), "Press the reset button");
    if(a == GA_ANSWER_DONE)
        ga_pass(ctx, "the operator did it%s%s", note[0] ? ": " : "", note);
}

static const ga_test tests[] = {
    {"T-1", "x", "done", false, true, step},
    {"T-2", "x", "skip", false, true, step},
    {"T-3", "x", "fail", false, true, step},
    {"T-4", "x", "no answer (end of file)", false, true, step},
};

static int run_with(const char *answers, seen *s) {
    memset(s, 0, sizeof(*s));
    char path[] = "/tmp/gdsaudit-prompts-XXXXXX";
    int fd = mkstemp(path);
    if(fd < 0)
        return -1;
    size_t len = strlen(answers);
    bool wrote = write(fd, answers, len) == (ssize_t)len;
    close(fd);
    ga_clear_event_sinks();
    (void)ga_add_event_sink(sink, s);
    bool opened = wrote && prompts_open(path);
    unlink(path);
    if(!opened)
        return -1;
    ga_run_options opt = {.operatorAvailable = true};
    int rc = ga_run(tests, sizeof(tests) / sizeof(tests[0]), NULL, &opt);
    prompts_close();
    return rc;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void engine(void) {
    seen s;
    /* answers for other prompt numbers and junk lines are passed over */
    int rc = run_with("9 done\njunk\n1 done all good\n2 skip\n3 fail lamp stays red\n", &s);
    CHECK(rc == 1); /* T-3 failed */
    CHECK(s.prompts == 4 && s.answered == 4);
    CHECK(s.verdict[0] == GA_PASS && s.verdict[1] == GA_NOT_TESTED);
    CHECK(s.verdict[2] == GA_FAIL && s.verdict[3] == GA_NOT_TESTED);
    CHECK(s.answers[0] == GA_ANSWER_DONE && s.answers[2] == GA_ANSWER_FAIL);
    CHECK(s.answers[3] == GA_ANSWER_SKIP); /* end of file */
    CHECK(!strcmp(s.lastAnswerNote, "no answer from the operator"));

    /* no handler: every prompt is a Skip, the test Not tested */
    ga_clear_event_sinks();
    memset(&s, 0, sizeof(s));
    (void)ga_add_event_sink(sink, &s);
    ga_run_options opt = {.operatorAvailable = true};
    rc = ga_run(tests, 1, NULL, &opt);
    CHECK(rc == 3 && s.verdict[0] == GA_NOT_TESTED && s.answers[0] == GA_ANSWER_SKIP);
    CHECK(!strcmp(s.lastAnswerNote, "no operator to ask"));
    CHECK(!ga_prompt_available());
    ga_clear_event_sinks();
}

int main(void) {
    parse();
    engine();
    if(failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("operator prompt tests passed\n");
    return 0;
}
