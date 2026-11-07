/* OpenGDS Auditor - the JSON report (Auditor plan report/report_json.c):
 * one document per run for machines, schema "gdsaudit-report" version 1,
 * documented in docs/auditor/report-json.md. UASM can import it as
 * compliance evidence; it says "self-test, not OPC Foundation
 * certification" like every other report.
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <string.h>

#include "cu.h"
#include "results.h"

#include "common/banned.h"

#define GA_REPORT_JSON_VERSION 1

/* key: value, where value is a string or null */
static void str_or_null(FILE *f, const char *key, const char *val) {
    fprintf(f, "\"%s\":", key);
    if(val)
        ga_json_put_string(f, val);
    else
        fputs("null", f);
}

static void counts(FILE *f, const size_t c[GA_VERDICT_COUNT], size_t noVerdict) {
    fputs("\"counts\":{", f);
    for(size_t v = 0; v < GA_VERDICT_COUNT; v++)
        fprintf(f, "\"%s\":%zu,", ga_verdict_name((ga_verdict)v), c[v]);
    fprintf(f, "\"no_verdict\":%zu}", noVerdict);
}

/* "named", "not_named" (TBD in the catalogue) or "not_in_catalogue" */
static const char *unit_state(const char *unit) {
    if(!unit)
        return "not_in_catalogue";
    return strcmp(unit, GA_CU_TBD) == 0 ? "not_named" : "named";
}

static const char *unit_name(const char *unit) {
    return unit && strcmp(unit, GA_CU_TBD) != 0 ? unit : NULL;
}

static void units(FILE *f, const ga_results *r) {
    ga_unit_row rows[GA_MAX_UNITS];
    size_t n = ga_results_units(r, rows);
    fputs("\"conformance_units\":[", f);
    for(size_t k = 0; k < n; k++) {
        fputs(k ? ",{" : "{", f);
        str_or_null(f, "unit", unit_name(rows[k].unit));
        fprintf(f, ",\"state\":\"%s\",", unit_state(rows[k].unit));
        counts(f, rows[k].counts, rows[k].noVerdict);
        fprintf(f, ",\"outcome\":\"%s\"}", ga_unit_outcome(&rows[k]));
    }
    fputc(']', f);
}

/* Notes are kept '\n'-separated in the result: one array element each. */
static void notes(FILE *f, const ga_result *x) {
    fputs("\"notes\":[", f);
    const char *p = x->notes;
    bool first = true;
    while(p && *p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        char line[GA_MAX_NOTES + 1];
        if(len > GA_MAX_NOTES)
            len = GA_MAX_NOTES;
        memcpy(line, p, len);
        line[len] = '\0';
        if(!first)
            fputc(',', f);
        ga_json_put_string(f, line);
        first = false;
        p = nl ? nl + 1 : p + strlen(p);
    }
    fputc(']', f);
}

static void test(FILE *f, const ga_result *x, size_t n) {
    const char *unit = ga_conformance_unit(x->id);
    fprintf(f, "{\"n\":%zu,", n);
    str_or_null(f, "id", x->id);
    fputc(',', f);
    str_or_null(f, "clause", x->clause);
    fputc(',', f);
    str_or_null(f, "title", x->title);
    fputc(',', f);
    str_or_null(f, "conformance_unit", unit_name(unit));
    fprintf(f, ",\"conformance_unit_state\":\"%s\",\"changes\":%s,\"operator\":%s,",
            unit_state(unit), x->needsWrite ? "true" : "false",
            x->needsOperator ? "true" : "false");
    if(x->done)
        fprintf(f, "\"verdict\":\"%s\",\"ms\":%.0f,", ga_verdict_name(x->verdict), x->ms);
    else
        fputs("\"verdict\":null,\"ms\":null,", f);
    str_or_null(f, "evidence", x->evidence);
    fputc(',', f);
    notes(f, x);
    fputc('}', f);
}

bool ga_report_json(FILE *f, const ga_results *r) {
    size_t noVerdict = 0;
    for(size_t i = 0; i < r->n; i++)
        noVerdict += !r->items[i].done;
    fprintf(f, "{\"schema\":\"gdsaudit-report\",\"version\":%d,", GA_REPORT_JSON_VERSION);
    fputs("\"note\":\"Self-test, not OPC Foundation certification.\",\"tool\":\"gdsaudit\",", f);
    str_or_null(f, "profile", r->profile);
    fputc(',', f);
    str_or_null(f, "target", r->target);
    fputc(',', f);
    str_or_null(f, "started", r->started);
    fputc(',', f);
    str_or_null(f, "finished", r->finished);
    fprintf(f, ",\"allow_changes\":%s,\"planned\":%zu,\"outcome\":\"%s\",",
            r->allowChanges ? "true" : "false", r->planned, ga_results_outcome(r));
    if(r->finishedSeen)
        fprintf(f, "\"exit\":%d,\"aborted\":%s,", r->exitCode, r->aborted ? "true" : "false");
    else
        fputs("\"exit\":null,\"aborted\":false,", f);
    counts(f, r->counts, noVerdict);
    fputc(',', f);
    units(f, r);
    fputs(",\"tests\":[", f);
    for(size_t i = 0; i < r->n; i++) {
        if(i)
            fputc(',', f);
        test(f, &r->items[i], i + 1);
    }
    fputs("]}\n", f);
    return !ferror(f);
}
