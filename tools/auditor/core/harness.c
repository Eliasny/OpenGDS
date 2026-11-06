/* OpenGDS Auditor - test registry, runner and verdicts.
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "harness.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/buf.h"
#include "common/banned.h"

#define GA_EVIDENCE 512
#define GA_MAX_EXPECT 512

struct ga_ctx {
    bool decided;
    ga_verdict verdict;
    char evidence[GA_EVIDENCE];
};

static const char *const verdictNames[] = {"pass", "fail", "warn", "not_supported",
                                           "not_tested"};

const char *ga_verdict_name(ga_verdict v) {
    if((size_t)v < GDS_ARRAY_SIZE(verdictNames))
        return verdictNames[v];
    return "invalid";
}

bool ga_verdict_parse(const char *s, ga_verdict *out) {
    for(size_t i = 0; i < GDS_ARRAY_SIZE(verdictNames); i++) {
        if(strcmp(s, verdictNames[i]) == 0) {
            *out = (ga_verdict)i;
            return true;
        }
    }
    return false;
}

/* Evidence must stay on one TAP line: replace control characters. */
static void sanitize(char *s) {
    for(; *s; s++)
        if((unsigned char)*s < 0x20 || *s == 0x7f)
            *s = ' ';
}

GDS_FORMAT(3, 0)
static void decide(ga_ctx *ctx, ga_verdict v, const char *fmt, va_list ap) {
    if(ctx->decided)
        return;
    ctx->decided = true;
    ctx->verdict = v;
    /* truncation ok: display. NOLINTNEXTLINE(clang-analyzer-valist.Uninitialized): caller ran va_start */
    vsnprintf(ctx->evidence, sizeof(ctx->evidence), fmt, ap);
    sanitize(ctx->evidence);
}

#define DECIDER(name, v)                                                       \
    void name(ga_ctx *ctx, const char *fmt, ...) {                             \
        va_list ap;                                                            \
        va_start(ap, fmt);                                                     \
        decide(ctx, v, fmt, ap);                                               \
        va_end(ap);                                                            \
    }
DECIDER(ga_pass, GA_PASS)
DECIDER(ga_fail, GA_FAIL)
DECIDER(ga_warn, GA_WARN)
DECIDER(ga_not_supported, GA_NOT_SUPPORTED)
DECIDER(ga_not_tested, GA_NOT_TESTED)

void ga_note(ga_ctx *ctx, const char *fmt, ...) {
    (void)ctx;
    char line[GA_EVIDENCE];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap); /* NOLINT(clang-analyzer-valist.Uninitialized): va_start above */
    va_end(ap);
    sanitize(line);
    printf("#   %s\n", line);
}

bool ga_decided(const ga_ctx *ctx) {
    return ctx->decided;
}

typedef struct {
    char id[128];
    ga_verdict v;
    bool seen;
} expect_line;

/* Load "id,verdict" lines; '#' starts a comment. Returns count or -1. */
static long load_expect(const char *path, expect_line *lines, size_t max) {
    gds_buf b = {0};
    if(gds_file_read(path, (size_t)256 * 1024, &b) != GDS_OK)
        return -1;
    long n = 0;
    size_t pos = 0;
    while(pos < b.len) {
        size_t end = pos;
        while(end < b.len && b.data[end] != '\n')
            end++;
        char line[256];
        size_t len = end - pos;
        if(len >= sizeof(line)) {
            n = -1;
            break;
        }
        memcpy(line, b.data + pos, len);
        line[len] = '\0';
        pos = end + 1;
        char *hash = strchr(line, '#');
        if(hash)
            *hash = '\0';
        char *comma = strchr(line, ',');
        if(!comma)
            continue; /* blank or comment line */
        *comma = '\0';
        char *vs = comma + 1;
        char *e = vs + strlen(vs);
        while(e > vs && (e[-1] == ' ' || e[-1] == '\r' || e[-1] == '\t'))
            *--e = '\0';
        while(*vs == ' ')
            vs++;
        if((size_t)n >= max || gds_path(lines[n].id, sizeof(lines[n].id), "%s", line) != GDS_OK ||
           !ga_verdict_parse(vs, &lines[n].v)) {
            fprintf(stderr, "expect file %s: bad line for '%s'\n", path, line);
            n = -1;
            break;
        }
        lines[n].seen = false;
        n++;
    }
    gds_buf_free(&b);
    return n;
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static bool selected(const ga_test *t, const ga_run_options *opt) {
    return !opt->only || strncmp(t->id, opt->only, strlen(opt->only)) == 0;
}

/* Run one test and print its TAP lines; returns its verdict. */
static ga_verdict run_one(const ga_test *t, size_t k, void *profile, const ga_run_options *opt) {
    ga_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    double t0 = now_ms();
    if(t->needsWrite && !opt->allowChanges)
        ga_not_tested(&ctx, "changes the target; run with --allow-changes");
    else if(t->needsOperator)
        ga_not_tested(&ctx, "needs an operator or hook (not available in this run)");
    else
        t->fn(&ctx, profile);
    if(!ctx.decided)
        ga_fail(&ctx, "test ended without a verdict (harness bug)");
    double ms = now_ms() - t0;
    const char *directive = "";
    if(ctx.verdict == GA_NOT_SUPPORTED || ctx.verdict == GA_NOT_TESTED)
        directive = " # SKIP";
    printf("%s %zu - %s [%s] %s%s\n", ctx.verdict == GA_FAIL ? "not ok" : "ok", k, t->id,
           t->clause, t->title, directive);
    printf("#   verdict: %s (%.0f ms) %s\n", ga_verdict_name(ctx.verdict), ms, ctx.evidence);
    return ctx.verdict;
}

/* Compare with the expected line; returns true on a mismatch. */
static bool check_expect(const ga_test *t, ga_verdict v, expect_line *expect, long nExpect,
                         const char *file) {
    for(long j = 0; j < nExpect; j++) {
        if(strcmp(expect[j].id, t->id) != 0)
            continue;
        expect[j].seen = true;
        if(expect[j].v == v)
            return false;
        printf("#   EXPECT MISMATCH: %s expected %s, got %s\n", t->id,
               ga_verdict_name(expect[j].v), ga_verdict_name(v));
        return true;
    }
    printf("#   EXPECT: %s has no line in %s\n", t->id, file);
    return true;
}

int ga_run(const ga_test *tests, size_t n, void *profile, const ga_run_options *opt) {
    static expect_line expect[GA_MAX_EXPECT];
    long nExpect = 0;
    if(opt->expectCsv) {
        nExpect = load_expect(opt->expectCsv, expect, GA_MAX_EXPECT);
        if(nExpect < 0) {
            fprintf(stderr, "cannot load %s\n", opt->expectCsv);
            return 2;
        }
    }
    size_t counts[5] = {0};
    size_t mismatches = 0, planned = 0, k = 0;
    for(size_t i = 0; i < n; i++)
        planned += selected(&tests[i], opt);
    printf("TAP version 13\n1..%zu\n", planned);
    printf("# OpenGDS Auditor: self-test, not OPC Foundation certification\n");
    for(size_t i = 0; i < n; i++) {
        if(!selected(&tests[i], opt))
            continue;
        ga_verdict v = run_one(&tests[i], ++k, profile, opt);
        counts[v]++;
        if(opt->expectCsv && check_expect(&tests[i], v, expect, nExpect, opt->expectCsv))
            mismatches++;
        fflush(stdout);
    }
    printf("# pass %zu, fail %zu, warn %zu, not supported %zu, not tested %zu\n",
           counts[GA_PASS], counts[GA_FAIL], counts[GA_WARN], counts[GA_NOT_SUPPORTED],
           counts[GA_NOT_TESTED]);
    if(opt->expectCsv) {
        for(long j = 0; j < nExpect && !opt->only; j++) {
            if(!expect[j].seen) {
                printf("# EXPECT: %s names an unknown test %s\n", opt->expectCsv, expect[j].id);
                return 2;
            }
        }
        printf("# expectations: %zu mismatch(es) against %s\n", mismatches, opt->expectCsv);
        return mismatches ? 1 : 0;
    }
    if(counts[GA_FAIL])
        return 1;
    if(counts[GA_NOT_TESTED])
        return 3;
    return 0;
}
