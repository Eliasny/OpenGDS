/* OpenGDS Auditor - the result list of one run, built from the engine's
 * event stream, the JSON Lines form of that stream, and the report writers
 * (Auditor plan report/: one writer per format from the same result list).
 *
 * libc only: the headless binary and the desktop UI both link it.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_RESULTS_H
#define GDSAUDIT_RESULTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "gdsaudit/engine.h"

/* Limits for anything read back from an events file */
#define GA_MAX_RESULTS 4096
#define GA_MAX_LINE ((size_t)64 * 1024)
#define GA_MAX_NOTES ((size_t)16 * 1024) /* per test; longer notes are cut */

typedef struct {
    char *id, *clause, *title;
    bool needsWrite, needsOperator;
    bool done; /* a verdict arrived */
    ga_verdict verdict;
    double ms;
    char *evidence;
    char *notes; /* note lines, '\n'-separated; NULL if none */
    size_t notesLen;
} ga_result;

typedef struct {
    char *profile, *target, *started, *finished;
    bool allowChanges;
    bool finishedSeen, aborted;
    size_t planned;
    int exitCode;
    size_t counts[GA_VERDICT_COUNT]; /* from the verdicts seen */
    ga_result *items;
    size_t n, cap;
} ga_results;

/* Apply one event. Returns false on out of memory or a stream that breaks
 * the limits; the list stays consistent either way. */
bool ga_results_apply(ga_results *r, const ga_event *ev);
void ga_results_free(ga_results *r);
/* An event sink (engine.h) that applies to the ga_results in user. */
void ga_results_sink(const ga_event *ev, void *user);

/* JSON Lines (schema in engine.h) */
bool ga_jsonl_write(FILE *f, const ga_event *ev);
/* An event sink that writes to the FILE in user and flushes each line. */
void ga_jsonl_sink(const ga_event *ev, void *user);

/* Owns the strings an parsed event points into. */
typedef struct {
    char *s[8];
} ga_jsonl_strings;

/* Parse one line (without its newline). Returns 1 and fills *ev for a
 * known event, 0 for a valid line to ignore (unknown "ev", newer schema
 * with unknown keys is fine), -1 for a malformed line. *strs must be
 * released with ga_jsonl_strings_free after use of *ev. */
int ga_jsonl_parse(const char *line, size_t len, ga_event *ev, ga_jsonl_strings *strs);
void ga_jsonl_strings_free(ga_jsonl_strings *strs);

/* Read a whole events file into r. Returns false if the file cannot be read
 * or holds a malformed line (err names it). */
bool ga_results_load(const char *path, ga_results *r, char *err, size_t errLen);

/* Reports. Every report says "self-test, not OPC Foundation certification". */
bool ga_report_html(FILE *f, const ga_results *r);
bool ga_report_junit(FILE *f, const ga_results *r);
/* JSON for machines: one document, schema "gdsaudit-report" version 1
 * (docs/auditor/report-json.md). UASM can import it as compliance evidence. */
bool ga_report_json(FILE *f, const ga_results *r);
/* TAP version 13 for the shell, with a YAML block per test. Fail and a test
 * without a verdict are "not ok"; Not supported and Not tested are SKIP. */
bool ga_report_tap(FILE *f, const ga_results *r);
/* Write DIR/report.html, DIR/junit.xml, DIR/report.json and DIR/report.tap
 * (DIR is created if missing). */
bool ga_report_write_dir(const char *dir, const ga_results *r, char *err, size_t errLen);

/* Results per ConformanceUnit, from the test catalogue (cu.h), in order of
 * first appearance. unit is the catalogue's name, GA_CU_TBD (not named yet)
 * or NULL (not in the catalogue). Past GA_MAX_UNITS - 1 named units the
 * rest count in the NULL row. */
#define GA_MAX_UNITS 32
typedef struct {
    const char *unit;
    size_t counts[GA_VERDICT_COUNT];
    size_t noVerdict;
} ga_unit_row;
size_t ga_results_units(const ga_results *r, ga_unit_row rows[GA_MAX_UNITS]);
/* The run's rule per unit: any Fail fails it ("Failed"), any Not tested or
 * missing verdict leaves it "Incomplete", else "Passed". */
const char *ga_unit_outcome(const ga_unit_row *u);

/* JSON helpers shared by the writers: s as a JSON string (NULL as ""),
 * always valid UTF-8; and a check that [s, s+len) is one JSON value with
 * nothing after it (depth-limited). */
void ga_json_put_string(FILE *f, const char *s);
bool ga_json_valid(const char *s, size_t len);

/* The run's verdict summary for people: "Passed", "Failed", "Incomplete"
 * (no Fail but some Not tested), "Aborted", "Did not finish". */
const char *ga_results_outcome(const ga_results *r);

#endif
