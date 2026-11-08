/* OpenGDS Auditor - the engine API the front ends use (Auditor plan,
 * include/gdsaudit/engine.h).
 *
 * The engine runs a profile and emits one event stream: run started, test
 * started, note (evidence line), verdict, run finished. The headless front
 * end prints it as TAP and, with --events FILE, writes it as JSON Lines; the
 * desktop UI runs the headless binary with --events and renders the same
 * stream, so neither front end holds test logic and both give identical
 * verdicts.
 *
 * JSON Lines schema (one object per line, UTF-8, "v" is the schema version):
 *   {"v":1,"ev":"run_started","profile":"server","target":"opc.tcp://..",
 *    "planned":12,"allow_changes":true,"time":"2026-11-06T05:00:00Z"}
 *   {"v":1,"ev":"test_started","n":1,"id":"SRV-TL-02","clause":"12 §7.8.2.1",
 *    "title":"..","changes":true,"operator":false}
 *   {"v":1,"ev":"note","n":1,"text":".."}
 *   {"v":1,"ev":"verdict","n":1,"id":"SRV-TL-02","verdict":"pass","ms":41,
 *    "evidence":".."}
 *   {"v":1,"ev":"paused"}  {"v":1,"ev":"resumed"}   (between two tests)
 *   {"v":1,"ev":"prompt","n":3,"seq":1,"text":"Restart the device, then .."}
 *   {"v":1,"ev":"prompt_answered","n":3,"seq":1,"answer":"done","text":"note"}
 *   {"v":1,"ev":"run_finished","pass":10,"fail":1,"warn":0,"not_supported":1,
 *    "not_tested":0,"exit":1,"aborted":false,"time":".."}
 * Readers ignore unknown keys and unknown "ev" values.
 *
 * This header needs only libc, so a front end can include it without
 * open62541.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_ENGINE_H
#define GDSAUDIT_ENGINE_H

#include <stdbool.h>
#include <stddef.h>

#define GA_EVENTS_SCHEMA 1

typedef enum {
    GA_PASS = 0,
    GA_FAIL,
    GA_WARN,          /* allowed by the spec but risky or ambiguous */
    GA_NOT_SUPPORTED, /* optional feature the target does not advertise */
    GA_NOT_TESTED     /* a needed step did not happen */
} ga_verdict;

#define GA_VERDICT_COUNT 5

/* "pass", "fail", "warn", "not_supported", "not_tested" */
const char *ga_verdict_name(ga_verdict v);
bool ga_verdict_parse(const char *s, ga_verdict *out);
/* "Pass", "Fail", "Warn", "Not supported", "Not tested" */
const char *ga_verdict_label(ga_verdict v);

typedef enum {
    GA_EV_RUN_STARTED = 0,
    GA_EV_TEST_STARTED,
    GA_EV_NOTE,
    GA_EV_VERDICT,
    GA_EV_RUN_FINISHED,
    GA_EV_PAUSED, /* between two tests, until resumed or aborted */
    GA_EV_RESUMED,
    GA_EV_PROMPT,         /* a test asks the operator for a manual step */
    GA_EV_PROMPT_ANSWERED /* the operator's answer (text: their note) */
} ga_event_kind;

/* The operator's answer to a prompt: the step is done, skip it (the test is
 * Not tested), or it failed (the test fails, with the operator's note). */
typedef enum { GA_ANSWER_DONE = 0, GA_ANSWER_SKIP, GA_ANSWER_FAIL } ga_answer;
#define GA_ANSWER_COUNT 3
/* "done", "skip", "fail" */
const char *ga_answer_name(ga_answer a);
bool ga_answer_parse(const char *s, ga_answer *out);

/* One engine event. Strings are borrowed for the duration of the callback.
 * Fields not listed for a kind are zero or NULL. */
typedef struct {
    /* run_started */
    const char *profile; /* "gds", "server", "client" */
    const char *target;  /* endpoint URL or listen URL */
    size_t planned;
    /* test_started, note, verdict, prompt*: 1-based test number in this run */
    size_t n;
    /* prompt, prompt_answered: prompt number in this run (1-based) */
    size_t seq;
    /* test_started (id also in verdict) */
    const char *id, *clause, *title;
    /* note: the line; verdict: the evidence line; prompt: the instruction;
     * prompt_answered: the operator's note */
    const char *text;
    /* verdict */
    double ms;
    /* run_started, run_finished: UTC, ISO 8601 */
    const char *time;
    /* run_finished */
    size_t counts[GA_VERDICT_COUNT];
    ga_event_kind kind;
    ga_verdict verdict; /* verdict */
    ga_answer answer;   /* prompt_answered */
    int exitCode;       /* run_finished */
    bool allowChanges;  /* run_started */
    bool needsWrite, needsOperator; /* test_started */
    bool aborted;       /* run_finished */
} ga_event;

typedef void (*ga_event_fn)(const ga_event *ev, void *user);

/* Process-wide event sinks, called in order for every event of every run.
 * Returns false if the table (GA_MAX_SINKS) is full. */
#define GA_MAX_SINKS 4
bool ga_add_event_sink(ga_event_fn fn, void *user);
void ga_clear_event_sinks(void);

/* What the run_started event names; set by the front end before the run. */
void ga_set_run_info(const char *profile, const char *target);

/* Ask the running profile to stop: async-signal-safe. The test in progress
 * finishes, every later test is Not tested ("run aborted"), and the
 * profile's own clean-up (for the server profile, restoring the target's
 * trust list and certificates) runs as on a normal end. */
void ga_request_abort(void);
bool ga_abort_requested(void);

/* Ask the running profile to wait before its next test, or to go on:
 * async-signal-safe. The test in progress always finishes first, so no
 * target is left half-changed; an abort ends a pause. */
void ga_request_pause(bool paused);
bool ga_pause_requested(void);

/* Operator prompts. The front end that can ask a person installs a handler:
 * it shows text (prompt number seq) and blocks until the answer, writing
 * the person's note (may be empty) to note. It returns false if no answer
 * can come (stream closed, run aborted): the test is then Not tested.
 * Without a handler, prompts are answered Skip ("no operator"). */
typedef bool (*ga_prompt_fn)(size_t seq, const char *text, ga_answer *answer, char *note,
                             size_t noteLen, void *user);
void ga_set_prompt_handler(ga_prompt_fn fn, void *user);
bool ga_prompt_available(void);

#endif
