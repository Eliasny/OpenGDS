/* OpenGDS Auditor - HTML and JUnit XML reports from one result list
 * (Auditor plan report/report_html.c, report_junit.c).
 * Every report says "self-test, not OPC Foundation certification" and never
 * "compliant" or "certified".
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cu.h"
#include "results.h"

#include "common/banned.h"

#define SELF_TEST_NOTE "Self-test, not OPC Foundation certification."

/* Escape for HTML text and attribute values, and for XML. Control
 * characters other than newline and tab are dropped (not allowed in XML
 * 1.0); invalid UTF-8 was already replaced by the event writer, and
 * results built in-process get the same treatment here. */
static void esc(FILE *f, const char *s) {
    if(!s)
        return;
    for(const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch(*p) {
        case '&': fputs("&amp;", f); break;
        case '<': fputs("&lt;", f); break;
        case '>': fputs("&gt;", f); break;
        case '"': fputs("&quot;", f); break;
        case '\'': fputs("&#39;", f); break;
        default:
            if(*p >= 0x20 || *p == '\n' || *p == '\t')
                fputc(*p, f);
        }
    }
}

static const char *const verdictClass[GA_VERDICT_COUNT] = {"pass", "fail", "warn", "ns", "nt"};

static void html_head(FILE *f, const ga_results *r) {
    fputs("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
          "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
          "<title>OpenGDS Auditor report: ",
          f);
    esc(f, r->target);
    fputs("</title>\n<style>\n"
          "body{font:15px/1.45 system-ui,sans-serif;margin:2rem auto;max-width:72rem;"
          "padding:0 1rem;color:#1b1b1f;background:#fff}\n"
          "h1{font-size:1.4rem;margin:0 0 .25rem}\n"
          "h2{font-size:1.1rem;margin:1.5rem 0 .5rem}\n"
          "table.units{margin-bottom:1rem}\n"
          ".note{color:#5a5a66;margin:0 0 1rem}\n"
          ".banner{background:#fff4d6;border:1px solid #d9a400;padding:.5rem .75rem;"
          "border-radius:6px;margin:1rem 0}\n"
          "dl{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem;margin:1rem 0}\n"
          "dt{color:#5a5a66}dd{margin:0}\n"
          "table{border-collapse:collapse;width:100%}\n"
          "th,td{text-align:left;vertical-align:top;padding:.4rem .5rem;"
          "border-bottom:1px solid #e3e3e8}\n"
          "th{font-weight:600;background:#f6f6f8}\n"
          "td.id,td.clause,td:last-child{white-space:nowrap}\n"
          ".v{font-weight:600;white-space:nowrap}\n"
          ".pass{color:#11703a}.fail{color:#b3261e}.warn{color:#8a5a00}"
          ".ns,.nt{color:#5a5a66}\n"
          "pre{white-space:pre-wrap;margin:.3rem 0 0;font:12px/1.4 ui-monospace,monospace;"
          "color:#3d3d48}\n"
          ".counts span{margin-right:1rem}\n"
          "@media (prefers-color-scheme:dark){body{background:#151518;color:#e8e8ee}"
          "th{background:#222228}th,td{border-color:#333}.banner{background:#3a3000;"
          "border-color:#8a6d00}.note,dt,.ns,.nt{color:#a0a0ab}pre{color:#c4c4cf}"
          ".pass{color:#5fd38d}.fail{color:#ff8a80}.warn{color:#f0c050}}\n"
          "</style></head><body>\n",
          f);
}

static void html_summary(FILE *f, const ga_results *r) {
    fputs("<h1>OpenGDS Auditor report</h1>\n<p class=\"note\">" SELF_TEST_NOTE "</p>\n", f);
    if(r->allowChanges)
        fputs("<p class=\"banner\">Changes to the target were allowed in this run. The Auditor "
              "saved the target's trust list and certificates first and restores them at the "
              "end.</p>\n",
              f);
    fputs("<dl>\n<dt>Target</dt><dd>", f);
    esc(f, r->target);
    fputs("</dd>\n<dt>Profile</dt><dd>", f);
    esc(f, r->profile);
    fputs("</dd>\n<dt>Started</dt><dd>", f);
    esc(f, r->started);
    fputs("</dd>\n<dt>Finished</dt><dd>", f);
    esc(f, r->finished ? r->finished : "(did not finish)");
    fprintf(f, "</dd>\n<dt>Outcome</dt><dd>%s</dd>\n<dt>Tests</dt><dd class=\"counts\">",
            ga_results_outcome(r));
    for(size_t i = 0; i < GA_VERDICT_COUNT; i++)
        fprintf(f, "<span class=\"%s\">%s %zu</span>", verdictClass[i],
                ga_verdict_label((ga_verdict)i), r->counts[i]);
    fputs("</dd>\n</dl>\n", f);
}

/* One row of the ConformanceUnit table. unit is the catalogue's name,
 * GA_CU_TBD or NULL (not in the catalogue). */
typedef struct {
    const char *unit;
    size_t counts[GA_VERDICT_COUNT];
    size_t noVerdict;
} unit_row;

#define MAX_UNITS 32

static bool same_unit(const char *a, const char *b) {
    return a == b || (a && b && strcmp(a, b) == 0);
}

static size_t find_unit(const unit_row *rows, size_t n, const char *unit) {
    size_t k = 0;
    while(k < n && !same_unit(rows[k].unit, unit))
        k++;
    return k;
}

/* Units in order of first appearance. The last row is kept for tests not in
 * the catalogue, so past MAX_UNITS - 1 named units the rest count there. */
static size_t collect_units(const ga_results *r, unit_row *rows) {
    size_t n = 0;
    for(size_t i = 0; i < r->n; i++) {
        const ga_result *x = &r->items[i];
        const char *unit = ga_conformance_unit(x->id);
        size_t k = find_unit(rows, n, unit);
        if(k == n && n >= MAX_UNITS - 1) {
            unit = NULL;
            k = find_unit(rows, n, NULL);
        }
        if(k == n) {
            memset(&rows[n++], 0, sizeof(rows[0]));
            rows[k].unit = unit;
        }
        if(x->done && (size_t)x->verdict < GA_VERDICT_COUNT)
            rows[k].counts[x->verdict]++;
        else
            rows[k].noVerdict++;
    }
    return n;
}

static const char *unit_outcome(const unit_row *u) {
    if(u->counts[GA_FAIL])
        return "Failed";
    if(u->counts[GA_NOT_TESTED] || u->noVerdict)
        return "Incomplete";
    return "Passed";
}

/* Results per ConformanceUnit, from the test catalogue. The same rule as
 * the run outcome: any Fail fails the unit, any Not tested leaves it
 * Incomplete. */
static void html_units(FILE *f, const ga_results *r) {
    unit_row rows[MAX_UNITS];
    size_t n = collect_units(r, rows);
    if(n == 0)
        return;
    fputs("<h2>ConformanceUnits</h2>\n<p class=\"note\">Grouped by the ConformanceUnit each "
          "test names in the Auditor's test catalogue. " SELF_TEST_NOTE "</p>\n"
          "<table class=\"units\">\n<thead><tr><th>ConformanceUnit</th>",
          f);
    for(size_t v = 0; v < GA_VERDICT_COUNT; v++)
        fprintf(f, "<th>%s</th>", ga_verdict_label((ga_verdict)v));
    fputs("<th>Result</th></tr></thead>\n<tbody>\n", f);
    for(size_t k = 0; k < n; k++) {
        const unit_row *u = &rows[k];
        fputs("<tr><td>", f);
        if(!u->unit)
            fputs("<em>Not in the test catalogue</em>", f);
        else if(strcmp(u->unit, GA_CU_TBD) == 0)
            fputs("<em>Not named yet in the test catalogue</em>", f);
        else
            esc(f, u->unit);
        fputs("</td>", f);
        for(size_t v = 0; v < GA_VERDICT_COUNT; v++)
            fprintf(f, "<td>%zu</td>", u->counts[v]);
        const char *o = unit_outcome(u);
        fprintf(f, "<td class=\"v %s\">%s</td></tr>\n",
                o[0] == 'F' ? "fail" : o[0] == 'P' ? "pass" : "nt", o);
    }
    fputs("</tbody></table>\n<h2>Tests</h2>\n", f);
}

bool ga_report_html(FILE *f, const ga_results *r) {
    html_head(f, r);
    html_summary(f, r);
    html_units(f, r);
    fputs("<table>\n<thead><tr><th>Test</th><th>Clause</th><th>Title and evidence</th>"
          "<th>Verdict</th><th>Time</th></tr></thead>\n<tbody>\n",
          f);
    for(size_t i = 0; i < r->n; i++) {
        const ga_result *x = &r->items[i];
        fputs("<tr><td class=\"id\">", f);
        esc(f, x->id);
        fputs("</td><td class=\"clause\">", f);
        esc(f, x->clause);
        fputs("</td><td>", f);
        esc(f, x->title);
        if(x->needsWrite)
            fputs(" <small>(changes the target)</small>", f);
        if(x->evidence || x->notes) {
            fputs("<pre>", f);
            esc(f, x->evidence);
            if(x->notes) {
                if(x->evidence)
                    fputc('\n', f);
                esc(f, x->notes);
            }
            fputs("</pre>", f);
        }
        if(x->done)
            fprintf(f, "</td><td class=\"v %s\">%s</td><td>%.0f ms</td></tr>\n",
                    verdictClass[x->verdict], ga_verdict_label(x->verdict), x->ms);
        else
            fputs("</td><td class=\"v nt\">No verdict</td><td></td></tr>\n", f);
    }
    fputs("</tbody></table>\n<p class=\"note\">" SELF_TEST_NOTE
          " Generated by the OpenGDS Auditor (gdsaudit).</p>\n</body></html>\n",
          f);
    return !ferror(f);
}

bool ga_report_junit(FILE *f, const ga_results *r) {
    double total = 0;
    size_t skipped = r->counts[GA_NOT_SUPPORTED] + r->counts[GA_NOT_TESTED], missing = 0;
    for(size_t i = 0; i < r->n; i++) {
        total += r->items[i].ms;
        missing += !r->items[i].done;
    }
    fputs("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", f);
    fputs("<!-- OpenGDS Auditor: " SELF_TEST_NOTE " -->\n", f);
    fprintf(f, "<testsuites tests=\"%zu\" failures=\"%zu\" errors=\"%zu\" skipped=\"%zu\""
               " time=\"%.3f\">\n",
            r->n, r->counts[GA_FAIL], missing, skipped, total / 1000.0);
    fputs("<testsuite name=\"gdsaudit.", f);
    esc(f, r->profile);
    fprintf(f, "\" tests=\"%zu\" failures=\"%zu\" errors=\"%zu\" skipped=\"%zu\" time=\"%.3f\"",
            r->n, r->counts[GA_FAIL], missing, skipped, total / 1000.0);
    if(r->started) {
        fputs(" timestamp=\"", f);
        esc(f, r->started);
        fputc('"', f);
    }
    fputs(">\n<properties><property name=\"target\" value=\"", f);
    esc(f, r->target);
    fprintf(f, "\"/><property name=\"allow_changes\" value=\"%s\"/>"
               "<property name=\"outcome\" value=\"%s\"/></properties>\n",
            r->allowChanges ? "true" : "false", ga_results_outcome(r));
    for(size_t i = 0; i < r->n; i++) {
        const ga_result *x = &r->items[i];
        fputs("<testcase classname=\"gdsaudit.", f);
        esc(f, r->profile);
        fputs("\" name=\"", f);
        esc(f, x->id);
        fputs(" ", f);
        esc(f, x->title);
        fprintf(f, "\" time=\"%.3f\">", x->ms / 1000.0);
        if(!x->done) {
            fputs("<error message=\"no verdict\"/>", f);
        } else if(x->verdict == GA_FAIL) {
            fputs("<failure message=\"", f);
            esc(f, x->evidence);
            fputs("\"/>", f);
        } else if(x->verdict == GA_NOT_SUPPORTED || x->verdict == GA_NOT_TESTED) {
            fprintf(f, "<skipped message=\"%s: ", ga_verdict_label(x->verdict));
            esc(f, x->evidence);
            fputs("\"/>", f);
        }
        fputs("<system-out>", f);
        if(x->done)
            fprintf(f, "verdict: %s\n", ga_verdict_name(x->verdict));
        fputs("clause: ", f);
        esc(f, x->clause);
        fputc('\n', f);
        esc(f, x->evidence);
        if(x->notes) {
            fputc('\n', f);
            esc(f, x->notes);
        }
        fputs("</system-out></testcase>\n", f);
    }
    fputs("</testsuite>\n</testsuites>\n", f);
    return !ferror(f);
}

typedef bool (*writer_fn)(FILE *f, const ga_results *r);

/* Write DIR/NAME through DIR/NAME.tmp and a rename, so a reader never sees
 * half a report. */
static bool write_one(const char *dir, const char *name, writer_fn fn, const ga_results *r,
                      char *err, size_t errLen) {
    char path[4096], tmp[4200];
    int n1 = snprintf(path, sizeof(path), "%s/%s", dir, name);
    int n2 = snprintf(tmp, sizeof(tmp), "%s/%s.tmp", dir, name);
    if(n1 < 0 || (size_t)n1 >= sizeof(path) || n2 < 0 || (size_t)n2 >= sizeof(tmp)) {
        snprintf(err, errLen, "report path too long");
        return false;
    }
    FILE *f = fopen(tmp, "w");
    if(!f) {
        snprintf(err, errLen, "%s: %s", tmp, strerror(errno));
        return false;
    }
    bool ok = fn(f, r);
    ok = (fclose(f) == 0) && ok;
    if(!ok || rename(tmp, path) != 0) {
        snprintf(err, errLen, "%s: %s", path, ok ? strerror(errno) : "write failed");
        unlink(tmp);
        return false;
    }
    return true;
}

bool ga_report_write_dir(const char *dir, const ga_results *r, char *err, size_t errLen) {
    if(mkdir(dir, 0755) != 0 && errno != EEXIST) {
        snprintf(err, errLen, "%s: %s", dir, strerror(errno));
        return false;
    }
    return write_one(dir, "report.html", ga_report_html, r, err, errLen) &&
           write_one(dir, "junit.xml", ga_report_junit, r, err, errLen);
}
