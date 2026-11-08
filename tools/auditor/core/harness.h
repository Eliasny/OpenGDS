/* OpenGDS Auditor - test registry, runner and verdicts (Auditor plan core/harness.c,
 * core/verdict.c). Every test cites its clause; verdicts follow the plan:
 * Pass, Fail, Warn, Not supported, Not tested.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_HARNESS_H
#define GDSAUDIT_HARNESS_H

#include <stdbool.h>
#include <stddef.h>

#include "common/compiler.h"

#include "gdsaudit/engine.h" /* ga_verdict, events, abort */

typedef struct ga_ctx ga_ctx;

typedef void (*ga_test_fn)(ga_ctx *ctx, void *profile);

typedef struct {
    const char *id;     /* stable id, e.g. "gds.dir.register_valid" */
    const char *clause; /* e.g. "12 §6.5.5" */
    const char *title;
    bool needsWrite;    /* changes the target (needs --allow-changes on live targets) */
    bool needsOperator; /* needs a person or a hook */
    ga_test_fn fn;
} ga_test;

/* Results: each test ends with exactly one verdict and one evidence line.
 * The first call wins; later calls in the same test are ignored. */
void ga_pass(ga_ctx *ctx, const char *fmt, ...) GDS_FORMAT(2, 3);
void ga_fail(ga_ctx *ctx, const char *fmt, ...) GDS_FORMAT(2, 3);
void ga_warn(ga_ctx *ctx, const char *fmt, ...) GDS_FORMAT(2, 3);
void ga_not_supported(ga_ctx *ctx, const char *fmt, ...) GDS_FORMAT(2, 3);
void ga_not_tested(ga_ctx *ctx, const char *fmt, ...) GDS_FORMAT(2, 3);
/* Extra evidence lines (status codes, thumbprints) printed as TAP comments. */
void ga_note(ga_ctx *ctx, const char *fmt, ...) GDS_FORMAT(2, 3);
bool ga_decided(const ga_ctx *ctx);

/* Ask the operator for a manual step (engine.h, operator prompts), e.g.
 * "Restart the device, then choose Done". Blocks until the answer. The
 * prompt and the answer are also notes of the test. On SKIP the test is
 * decided Not tested, on FAIL it is decided Fail with the operator's note;
 * on DONE nothing is decided and the test goes on. Without a prompt
 * handler the answer is SKIP ("no operator to ask"). note may be NULL. */
ga_answer ga_prompt(ga_ctx *ctx, char *note, size_t noteLen, const char *fmt, ...)
    GDS_FORMAT(4, 5);

typedef struct {
    const char *only;      /* run only ids with this prefix (NULL: all) */
    bool allowChanges;     /* else needsWrite tests are Not tested */
    const char *expectCsv; /* compare verdicts with "id,verdict" lines */
    bool operatorAvailable; /* a person or hook is there: run needsOperator tests */
} ga_run_options;
/* Every run also emits its events to the sinks of include/gdsaudit/engine.h;
 * after ga_request_abort() the remaining tests are Not tested. */

/* Runs the tests in the given (fixed) order and prints TAP to stdout.
 * Returns the exit code of the Auditor plan: 0 all passed, 1 at least one
 * Fail, 3 no Fail but some Not tested. With expectCsv: 0 if every verdict
 * matches its expected line, 1 otherwise (a test turning green early is a
 * mismatch too, so the conformance matrix never lies), 2 if the file is
 * unreadable or names an unknown test. */
int ga_run(const ga_test *tests, size_t n, void *profile, const ga_run_options *opt);

#endif
