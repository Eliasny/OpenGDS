/* OpenGDS Auditor - tests of the event stream round trip, the parser's
 * refusals and the report writers.
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cu.h"
#include "results.h"

#include "common/banned.h"

static int failures;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if(!(cond)) {                                                          \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__,   \
                    #cond);                                                    \
            failures++;                                                        \
        }                                                                      \
    } while(0)

/* Write ev to a memory stream and return the line (without '\n'). */
static char *to_line(const ga_event *ev) {
    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    if(!f)
        return NULL;
    bool ok = ga_jsonl_write(f, ev);
    fclose(f);
    if(!ok || len == 0 || buf[len - 1] != '\n') {
        free(buf);
        return NULL;
    }
    buf[len - 1] = '\0';
    return buf;
}

static bool parse_apply(ga_results *r, const char *line) {
    ga_event ev;
    ga_jsonl_strings s;
    int p = ga_jsonl_parse(line, strlen(line), &ev, &s);
    bool ok = p == 1 && ga_results_apply(r, &ev);
    ga_jsonl_strings_free(&s);
    return ok;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void roundtrip(void) {
    ga_results direct = {0}, viaText = {0};
    ga_event evs[] = {
        {.kind = GA_EV_RUN_STARTED, .profile = "server", .target = "opc.tcp://h:4840",
         .allowChanges = true, .planned = 2, .time = "2026-11-06T05:00:00Z"},
        {.kind = GA_EV_TEST_STARTED, .n = 1, .id = "SRV-TL-02", .clause = "12 \xc2\xa7" "7.8.2.1",
         .title = "quote \" backslash \\ <tag> & tab\t", .needsWrite = true},
        {.kind = GA_EV_NOTE, .n = 1, .text = "Open -> Good"},
        {.kind = GA_EV_NOTE, .n = 1, .text = "bad utf8 \xff\xfe end"},
        {.kind = GA_EV_VERDICT, .n = 1, .id = "SRV-TL-02", .verdict = GA_FAIL, .ms = 41,
         .text = "list differs"},
        {.kind = GA_EV_PAUSED},
        {.kind = GA_EV_RESUMED},
        {.kind = GA_EV_TEST_STARTED, .n = 2, .id = "SRV-UPD-01", .clause = "12 x",
         .title = "t2", .needsOperator = true},
        {.kind = GA_EV_VERDICT, .n = 2, .id = "SRV-UPD-01", .verdict = GA_NOT_TESTED,
         .ms = 0, .text = "run aborted"},
        {.kind = GA_EV_RUN_FINISHED, .counts = {0, 1, 0, 0, 1}, .exitCode = 1, .aborted = true,
         .time = "2026-11-06T05:00:02Z"},
    };
    for(size_t i = 0; i < sizeof(evs) / sizeof(evs[0]); i++) {
        CHECK(ga_results_apply(&direct, &evs[i]));
        char *line = to_line(&evs[i]);
        CHECK(line != NULL);
        if(line) {
            CHECK(strchr(line, '\n') == NULL);
            if(evs[i].kind == GA_EV_PAUSED)
                CHECK(!strcmp(line, "{\"v\":1,\"ev\":\"paused\"}"));
            CHECK(parse_apply(&viaText, line));
        }
        free(line);
    }
    CHECK(viaText.n == 2 && direct.n == 2);
    CHECK(viaText.allowChanges && viaText.planned == 2 && viaText.finishedSeen);
    CHECK(viaText.aborted && viaText.exitCode == 1);
    CHECK(viaText.counts[GA_FAIL] == 1 && viaText.counts[GA_NOT_TESTED] == 1);
    CHECK(!strcmp(viaText.profile, "server") && !strcmp(viaText.target, "opc.tcp://h:4840"));
    CHECK(!strcmp(viaText.items[0].title, evs[1].title));
    CHECK(!strcmp(viaText.items[0].clause, evs[1].clause)); /* UTF-8 kept */
    CHECK(viaText.items[0].needsWrite && !viaText.items[0].needsOperator);
    CHECK(viaText.items[1].needsOperator);
    CHECK(viaText.items[0].verdict == GA_FAIL && viaText.items[0].ms == 41);
    CHECK(!strcmp(viaText.items[0].evidence, "list differs"));
    /* invalid UTF-8 became U+FFFD, one per bad byte */
    CHECK(viaText.items[0].notes &&
          !strcmp(viaText.items[0].notes, "Open -> Good\nbad utf8 \xef\xbf\xbd\xef\xbf\xbd end"));
    CHECK(!strcmp(ga_results_outcome(&viaText), "Aborted"));

    /* reports */
    char *html = NULL, *xml = NULL;
    size_t hl = 0, xl = 0;
    FILE *f = open_memstream(&html, &hl);
    CHECK(f && ga_report_html(f, &viaText));
    if(f)
        fclose(f);
    f = open_memstream(&xml, &xl);
    CHECK(f && ga_report_junit(f, &viaText));
    if(f)
        fclose(f);
    CHECK(html && strstr(html, "Self-test, not OPC Foundation certification"));
    CHECK(html && strstr(html, "quote &quot; backslash \\ &lt;tag&gt; &amp; tab"));
    CHECK(html && !strstr(html, "<tag>"));
    CHECK(html && strstr(html, "Changes to the target were allowed"));
    CHECK(html && !strstr(html, "compliant") && !strstr(html, "certified"));
    CHECK(xml && strstr(xml, "failures=\"1\"") && strstr(xml, "skipped=\"1\""));
    CHECK(xml && strstr(xml, "<failure message=\"list differs\"/>"));
    /* both tests are in one ConformanceUnit of the catalogue: Failed */
    CHECK(html && strstr(html, "<h2>ConformanceUnits</h2>"));
    CHECK(html && strstr(html, "<tr><td>Push Model for Global Certificate and TrustList "
                               "Management</td><td>0</td><td>1</td><td>0</td><td>0</td>"
                               "<td>1</td><td class=\"v fail\">Failed</td></tr>"));
    CHECK(xml && strstr(xml, "<skipped message=\"Not tested: run aborted\"/>"));
    free(html);
    free(xml);
    ga_results_free(&direct);
    ga_results_free(&viaText);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void refusals(void) {
    const char *bad[] = {
        "",
        "{",
        "[]",
        "{\"v\":1}",                                         /* no ev */
        "{\"ev\":\"note\",\"n\":1,\"text\":\"x\"}",           /* no schema */
        "{\"v\":1,\"ev\":\"note\",\"text\":\"x\"}",           /* no test number */
        "{\"v\":1,\"ev\":\"note\",\"n\":0,\"text\":\"x\"}",
        "{\"v\":1,\"ev\":\"note\",\"n\":-1,\"text\":\"x\"}",
        "{\"v\":1,\"ev\":\"note\",\"n\":1.5,\"text\":\"x\"}",
        "{\"v\":1,\"ev\":\"verdict\",\"n\":1,\"id\":\"a\"}",  /* no verdict */
        "{\"v\":1,\"ev\":\"verdict\",\"n\":1,\"verdict\":\"great\"}",
        "{\"v\":1,\"ev\":\"note\",\"n\":1,\"text\":\"a\\q\"}", /* bad escape */
        "{\"v\":1,\"ev\":\"note\",\"n\":1,\"text\":\"\\ud800\"}", /* lone surrogate */
        "{\"v\":1,\"ev\":\"note\",\"n\":1,\"text\":\"unterminated}",
        "{\"v\":1,\"ev\":\"note\",\"n\":1,\"text\":\"x\"} trailing",
        "{\"v\":1,\"ev\":\"note\",\"n\":1,\"text\":\"x\",}",
        "{\"v\":1,\"ev\":\"note\",\"n\":1,\"x\":[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]}",
        "{\"v\":1,\"ev\":\"note\",\"n\":99999999,\"text\":\"x\"}",
    };
    for(size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        ga_event ev;
        ga_jsonl_strings s;
        int p = ga_jsonl_parse(bad[i], strlen(bad[i]), &ev, &s);
        ga_results r = {0};
        bool applied = p == 1 && ga_results_apply(&r, &ev);
        if(applied)
            fprintf(stderr, "accepted: %s\n", bad[i]);
        CHECK(!applied);
        ga_jsonl_strings_free(&s);
        ga_results_free(&r);
    }
    /* forward compatible: unknown keys of any type and unknown events */
    const char *ok = "{\"v\":2,\"ev\":\"note\",\"n\":1,\"new\":{\"a\":[1,true,null,\"s\"]},"
                     "\"text\":\"t\\u00e4\\ud83d\\ude00\"}";
    ga_event ev;
    ga_jsonl_strings s;
    CHECK(ga_jsonl_parse(ok, strlen(ok), &ev, &s) == 1);
    CHECK(ev.kind == GA_EV_NOTE && ev.text && !strcmp(ev.text, "t\xc3\xa4\xf0\x9f\x98\x80"));
    ga_jsonl_strings_free(&s);
    const char *unknown = "{\"v\":1,\"ev\":\"prompt\",\"n\":1}";
    CHECK(ga_jsonl_parse(unknown, strlen(unknown), &ev, &s) == 0);
    ga_jsonl_strings_free(&s);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void units(void) {
    const char *u = ga_conformance_unit("SRV-TL-02");
    CHECK(u && !strcmp(u, "Push Model for Global Certificate and TrustList Management"));
    u = ga_conformance_unit("SRV-TXN-01");
    CHECK(u && !strcmp(u, "Server PushManagement Transactions"));
    u = ga_conformance_unit("CLI-TRU-02"); /* unit not named yet */
    CHECK(u && !strcmp(u, GA_CU_TBD));
    CHECK(ga_conformance_unit("gds.dir.register_valid") == NULL);
    CHECK(ga_conformance_unit(NULL) == NULL);
    CHECK(ga_cu_table_len >= 100);

    /* a test outside the catalogue and one not yet named get rows of their own */
    ga_results r = {0};
    ga_event evs[] = {
        {.kind = GA_EV_RUN_STARTED, .profile = "client", .target = "x", .planned = 2},
        {.kind = GA_EV_TEST_STARTED, .n = 1, .id = "CLI-TRU-02", .clause = "c", .title = "t"},
        {.kind = GA_EV_VERDICT, .n = 1, .id = "CLI-TRU-02", .verdict = GA_PASS},
        {.kind = GA_EV_TEST_STARTED, .n = 2, .id = "gds.x", .clause = "c", .title = "t"},
    };
    for(size_t i = 0; i < sizeof(evs) / sizeof(evs[0]); i++)
        CHECK(ga_results_apply(&r, &evs[i]));
    char *html = NULL;
    size_t hl = 0;
    FILE *f = open_memstream(&html, &hl);
    CHECK(f && ga_report_html(f, &r));
    if(f)
        fclose(f);
    CHECK(html && strstr(html, "<em>Not named yet in the test catalogue</em></td><td>1</td>"));
    /* no verdict: Incomplete */
    CHECK(html && strstr(html, "<em>Not in the test catalogue</em></td><td>0</td><td>0</td>"
                               "<td>0</td><td>0</td><td>0</td><td class=\"v nt\">Incomplete"));
    free(html);
    ga_results_free(&r);
}

int main(void) {
    roundtrip();
    refusals();
    units();
    if(failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("report and event stream tests passed\n");
    return 0;
}
