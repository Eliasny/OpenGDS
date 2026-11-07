/* OpenGDS Auditor - the TAP report (Auditor plan report/report_tap.c):
 * TAP version 13 for the shell, from the same result list as the other
 * reports. Fail, and a test that never got a verdict, are "not ok"; Pass
 * and Warn are "ok"; Not supported and Not tested are "ok ... # SKIP".
 * Each test has a YAML block with its verdict, clause, ConformanceUnit,
 * evidence and notes. Strings in it are YAML double-quoted scalars, written
 * with the JSON string writer (JSON escapes are valid there).
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <string.h>

#include "cu.h"
#include "results.h"

#include "common/banned.h"

/* A description or directive reason on the test line: one line, and a
 * "#" is escaped so it cannot start a directive (TAP 13). Control
 * characters become spaces; trailing spaces are dropped. */
static void tap_text(FILE *f, const char *s) {
    if(!s)
        return;
    size_t len = strlen(s);
    while(len > 0 && ((unsigned char)s[len - 1] <= 0x20 || s[len - 1] == 0x7f))
        len--;
    for(size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if(c == '#' || c == '\\')
            fputc('\\', f);
        fputc(c < 0x20 || c == 0x7f ? ' ' : c, f);
    }
}

static void yaml_str(FILE *f, const char *key, const char *val) {
    fprintf(f, "  %s: ", key);
    ga_json_put_string(f, val);
    fputc('\n', f);
}

static void yaml_notes(FILE *f, const char *notes) {
    if(!notes || !*notes)
        return;
    fputs("  notes:\n", f);
    const char *p = notes;
    while(*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        char line[GA_MAX_NOTES + 1];
        if(len > GA_MAX_NOTES)
            len = GA_MAX_NOTES;
        memcpy(line, p, len);
        line[len] = '\0';
        fputs("    - ", f);
        ga_json_put_string(f, line);
        fputc('\n', f);
        p = nl ? nl + 1 : p + strlen(p);
    }
}

static void test_line(FILE *f, const ga_result *x, size_t n) {
    bool notOk = !x->done || x->verdict == GA_FAIL;
    fprintf(f, "%s %zu - ", notOk ? "not ok" : "ok", n);
    tap_text(f, x->id);
    fputc(' ', f);
    tap_text(f, x->title);
    if(!x->done) {
        fputs(" # no verdict\n", f);
    } else if(x->verdict == GA_NOT_SUPPORTED || x->verdict == GA_NOT_TESTED) {
        fprintf(f, " # SKIP %s", ga_verdict_label(x->verdict));
        if(x->evidence && *x->evidence) {
            fputs(": ", f);
            tap_text(f, x->evidence);
        }
        fputc('\n', f);
    } else {
        fputc('\n', f);
    }
}

static void yaml_block(FILE *f, const ga_result *x) {
    const char *unit = ga_conformance_unit(x->id);
    fputs("  ---\n", f);
    fprintf(f, "  verdict: %s\n", x->done ? ga_verdict_name(x->verdict) : "none");
    yaml_str(f, "clause", x->clause);
    if(unit && strcmp(unit, GA_CU_TBD) != 0)
        yaml_str(f, "conformance_unit", unit);
    if(x->needsWrite)
        fputs("  changes: true\n", f);
    if(x->needsOperator)
        fputs("  operator: true\n", f);
    if(x->done)
        fprintf(f, "  ms: %.0f\n", x->ms);
    if(x->evidence)
        yaml_str(f, "evidence", x->evidence);
    yaml_notes(f, x->notes);
    fputs("  ...\n", f);
}

bool ga_report_tap(FILE *f, const ga_results *r) {
    /* A run that stopped early plans more than it reports, so a TAP
     * consumer sees the missing tests. */
    size_t plan = r->planned > r->n ? r->planned : r->n;
    fprintf(f, "TAP version 13\n1..%zu\n", plan);
    fputs("# OpenGDS Auditor: self-test, not OPC Foundation certification\n# target ", f);
    tap_text(f, r->target);
    fputs(", profile ", f);
    tap_text(f, r->profile);
    fputs(r->allowChanges ? ", changes allowed\n" : ", read-only\n", f);
    for(size_t i = 0; i < r->n; i++) {
        test_line(f, &r->items[i], i + 1);
        yaml_block(f, &r->items[i]);
    }
    fprintf(f, "# pass %zu, fail %zu, warn %zu, not supported %zu, not tested %zu\n",
            r->counts[GA_PASS], r->counts[GA_FAIL], r->counts[GA_WARN],
            r->counts[GA_NOT_SUPPORTED], r->counts[GA_NOT_TESTED]);
    fprintf(f, "# outcome: %s\n", ga_results_outcome(r));
    return !ferror(f);
}
