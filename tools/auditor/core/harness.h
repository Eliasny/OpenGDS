/* OpenGDS Auditor - test registry, runner and verdicts (Auditor plan core/harness.c,
 * core/verdict.c). Every test cites its clause; verdicts follow the plan:
 * Pass, Fail, Warn, Not supported, Not tested.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_HARNESS_H
#define GDSAUDIT_HARNESS_H

#include <stdbool.h>
#include <stddef.h>

#include "common/compiler.h"

typedef enum {
    GA_PASS = 0,
    GA_FAIL,
    GA_WARN,          /* allowed by the spec but risky or ambiguous */
    GA_NOT_SUPPORTED, /* optional feature the target does not advertise */
    GA_NOT_TESTED     /* a needed step did not happen */
} ga_verdict;

const char *ga_verdict_name(ga_verdict v);
/* Parse "pass", "fail", "warn", "not_supported", "not_tested". */
bool ga_verdict_parse(const char *s, ga_verdict *out);

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

typedef struct {
    const char *only;      /* run only ids with this prefix (NULL: all) */
    bool allowChanges;     /* else needsWrite tests are Not tested */
    const char *expectCsv; /* compare verdicts with "id,verdict" lines */
} ga_run_options;

/* Runs the tests in the given (fixed) order and prints TAP to stdout.
 * Returns the exit code of the Auditor plan: 0 all passed, 1 at least one
 * Fail, 3 no Fail but some Not tested. With expectCsv: 0 if every verdict
 * matches its expected line, 1 otherwise (a test turning green early is a
 * mismatch too, so the conformance matrix never lies), 2 if the file is
 * unreadable or names an unknown test. */
int ga_run(const ga_test *tests, size_t n, void *profile, const ga_run_options *opt);

#endif
