/* OpenGDS Auditor - verdict names and the result list of one run.
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "results.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "common/banned.h"

static const char *const verdictNames[GA_VERDICT_COUNT] = {"pass", "fail", "warn",
                                                           "not_supported", "not_tested"};
static const char *const verdictLabels[GA_VERDICT_COUNT] = {"Pass", "Fail", "Warn",
                                                            "Not supported", "Not tested"};

const char *ga_verdict_name(ga_verdict v) {
    if((size_t)v < GA_VERDICT_COUNT)
        return verdictNames[v];
    return "invalid";
}

const char *ga_verdict_label(ga_verdict v) {
    if((size_t)v < GA_VERDICT_COUNT)
        return verdictLabels[v];
    return "Invalid";
}

bool ga_verdict_parse(const char *s, ga_verdict *out) {
    for(size_t i = 0; i < GA_VERDICT_COUNT; i++) {
        if(strcmp(s, verdictNames[i]) == 0) {
            *out = (ga_verdict)i;
            return true;
        }
    }
    return false;
}

static const char *const answerNames[GA_ANSWER_COUNT] = {"done", "skip", "fail"};

const char *ga_answer_name(ga_answer a) {
    return (size_t)a < GA_ANSWER_COUNT ? answerNames[a] : "invalid";
}

bool ga_answer_parse(const char *s, ga_answer *out) {
    for(size_t i = 0; i < GA_ANSWER_COUNT; i++) {
        if(strcmp(s, answerNames[i]) == 0) {
            *out = (ga_answer)i;
            return true;
        }
    }
    return false;
}

/* strdup that keeps NULL and reports out of memory */
static bool dup_into(char **dst, const char *src) {
    char *c = NULL;
    if(src) {
        c = strdup(src);
        if(!c)
            return false;
    }
    free(*dst);
    *dst = c;
    return true;
}

static void result_free(ga_result *x) {
    free(x->id);
    free(x->clause);
    free(x->title);
    free(x->evidence);
    free(x->notes);
    memset(x, 0, sizeof(*x));
}

void ga_results_free(ga_results *r) {
    for(size_t i = 0; i < r->n; i++)
        result_free(&r->items[i]);
    free(r->items);
    free(r->profile);
    free(r->target);
    free(r->started);
    free(r->finished);
    memset(r, 0, sizeof(*r));
}

/* The item for test number n (1-based), growing the list up to n. */
static ga_result *item(ga_results *r, size_t n) {
    if(n == 0 || n > GA_MAX_RESULTS)
        return NULL;
    if(n > r->cap) {
        size_t cap = r->cap ? r->cap : 16;
        while(cap < n)
            cap *= 2;
        ga_result *grown = realloc(r->items, cap * sizeof(*grown));
        if(!grown)
            return NULL;
        memset(grown + r->cap, 0, (cap - r->cap) * sizeof(*grown));
        r->items = grown;
        r->cap = cap;
    }
    if(n > r->n)
        r->n = n;
    return &r->items[n - 1];
}

static bool add_note(ga_result *x, const char *text) {
    size_t len = strlen(text);
    if(x->notesLen >= GA_MAX_NOTES)
        return true; /* cut: the evidence line and verdict still count */
    if(len > GA_MAX_NOTES - x->notesLen)
        len = GA_MAX_NOTES - x->notesLen;
    size_t need = x->notesLen + len + 2;
    char *grown = realloc(x->notes, need);
    if(!grown)
        return false;
    x->notes = grown;
    if(x->notesLen)
        x->notes[x->notesLen++] = '\n';
    memcpy(x->notes + x->notesLen, text, len);
    x->notesLen += len;
    x->notes[x->notesLen] = '\0';
    return true;
}

static bool apply_run_started(ga_results *r, const ga_event *ev) {
    for(size_t i = 0; i < r->n; i++)
        result_free(&r->items[i]);
    r->n = 0;
    memset(r->counts, 0, sizeof(r->counts));
    r->finishedSeen = r->aborted = false;
    r->exitCode = 0;
    r->allowChanges = ev->allowChanges;
    r->planned = ev->planned;
    return dup_into(&r->profile, ev->profile) && dup_into(&r->target, ev->target) &&
           dup_into(&r->started, ev->time) && dup_into(&r->finished, NULL);
}

bool ga_results_apply(ga_results *r, const ga_event *ev) {
    ga_result *x;
    switch(ev->kind) {
    case GA_EV_RUN_STARTED:
        return apply_run_started(r, ev);
    case GA_EV_TEST_STARTED:
        if(!(x = item(r, ev->n)))
            return false;
        x->needsWrite = ev->needsWrite;
        x->needsOperator = ev->needsOperator;
        return dup_into(&x->id, ev->id) && dup_into(&x->clause, ev->clause) &&
               dup_into(&x->title, ev->title);
    case GA_EV_NOTE:
        if(!(x = item(r, ev->n)))
            return false;
        return !ev->text || add_note(x, ev->text);
    case GA_EV_VERDICT:
        if(!(x = item(r, ev->n)) || (size_t)ev->verdict >= GA_VERDICT_COUNT)
            return false;
        if(x->done && (size_t)x->verdict < GA_VERDICT_COUNT && r->counts[x->verdict])
            r->counts[x->verdict]--;
        x->done = true;
        x->verdict = ev->verdict;
        x->ms = ev->ms;
        r->counts[ev->verdict]++;
        if(!x->id && !dup_into(&x->id, ev->id))
            return false;
        return dup_into(&x->evidence, ev->text);
    case GA_EV_PAUSED:
    case GA_EV_RESUMED:
    case GA_EV_PROMPT:
    case GA_EV_PROMPT_ANSWERED:
        return true; /* no result of their own (prompts are notes too) */
    case GA_EV_RUN_FINISHED:
        r->finishedSeen = true;
        r->aborted = ev->aborted;
        r->exitCode = ev->exitCode;
        return dup_into(&r->finished, ev->time);
    }
    return false;
}

void ga_results_sink(const ga_event *ev, void *user) {
    if(!ga_results_apply((ga_results *)user, ev))
        fprintf(stderr, "gdsaudit: result list: out of memory\n");
}

const char *ga_results_outcome(const ga_results *r) {
    if(r->aborted)
        return "Aborted";
    if(!r->finishedSeen)
        return "Did not finish";
    if(r->counts[GA_FAIL])
        return "Failed";
    if(r->counts[GA_NOT_TESTED])
        return "Incomplete";
    return "Passed";
}

bool ga_results_load(const char *path, ga_results *r, char *err, size_t errLen) {
    FILE *f = fopen(path, "r");
    if(!f) {
        snprintf(err, errLen, "%s: %s", path, strerror(errno));
        return false;
    }
    const int bufLen = (int)GA_MAX_LINE + 2;
    char *line = malloc((size_t)bufLen);
    bool ok = line != NULL;
    size_t lineNo = 0;
    while(ok && fgets(line, bufLen, f)) {
        lineNo++;
        size_t len = strlen(line);
        if(len > 0 && line[len - 1] == '\n')
            line[--len] = '\0';
        else if(!feof(f)) {
            snprintf(err, errLen, "%s:%zu: line longer than %zu bytes", path, lineNo, GA_MAX_LINE);
            ok = false;
            break;
        }
        if(len == 0)
            continue;
        ga_event ev;
        ga_jsonl_strings strs;
        int p = ga_jsonl_parse(line, len, &ev, &strs);
        if(p < 0) {
            snprintf(err, errLen, "%s:%zu: not an Auditor event line", path, lineNo);
            ok = false;
        } else if(p > 0 && !ga_results_apply(r, &ev)) {
            snprintf(err, errLen, "%s:%zu: event out of range or out of memory", path, lineNo);
            ok = false;
        }
        ga_jsonl_strings_free(&strs);
    }
    if(ok && ferror(f)) {
        snprintf(err, errLen, "%s: read error", path);
        ok = false;
    }
    if(!line)
        snprintf(err, errLen, "out of memory");
    free(line);
    fclose(f);
    return ok;
}
