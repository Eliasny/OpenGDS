/* OpenGDS Auditor view-model - past runs and the difference of two runs.
 * SPDX-License-Identifier: MPL-2.0 */
#include "avm_history.h"

#include <string.h>

#include "common/banned.h"

#define AVM_MAX_RUNS 1000

char *avm_history_dir(void) {
    return g_build_filename(g_get_user_data_dir(), "gdsaudit", "runs", NULL);
}

static void entry_free(gpointer p) {
    AvmHistoryEntry *e = p;
    g_free(e->dir);
    g_free(e->profile);
    g_free(e->target);
    g_free(e->started);
    g_free(e);
}

static AvmHistoryEntry *load_entry(const char *dir) {
    char *events = g_build_filename(dir, "events.jsonl", NULL);
    ga_results r = {0};
    char err[256];
    gboolean ok = g_file_test(events, G_FILE_TEST_IS_REGULAR) &&
                  ga_results_load(events, &r, err, sizeof(err)) && r.profile;
    g_free(events);
    AvmHistoryEntry *e = NULL;
    if(ok) {
        e = g_new0(AvmHistoryEntry, 1);
        e->dir = g_strdup(dir);
        e->profile = g_strdup(r.profile);
        e->target = g_strdup(r.target ? r.target : "");
        e->started = g_strdup(r.started ? r.started : "");
        e->outcome = ga_results_outcome(&r);
        memcpy(e->counts, r.counts, sizeof(e->counts));
    }
    ga_results_free(&r);
    return e;
}

static gint newest_first(gconstpointer a, gconstpointer b) {
    const AvmHistoryEntry *x = *(const AvmHistoryEntry *const *)a;
    const AvmHistoryEntry *y = *(const AvmHistoryEntry *const *)b;
    int c = strcmp(y->started, x->started);
    return c ? c : strcmp(y->dir, x->dir);
}

GPtrArray *avm_history_list(const char *root) {
    GPtrArray *out = g_ptr_array_new_with_free_func(entry_free);
    GDir *d = g_dir_open(root, 0, NULL);
    if(!d)
        return out;
    const char *name;
    while((name = g_dir_read_name(d)) && out->len < AVM_MAX_RUNS) {
        char *dir = g_build_filename(root, name, NULL);
        AvmHistoryEntry *e = g_file_test(dir, G_FILE_TEST_IS_DIR) ? load_entry(dir) : NULL;
        if(e)
            g_ptr_array_add(out, e);
        g_free(dir);
    }
    g_dir_close(d);
    g_ptr_array_sort(out, newest_first);
    return out;
}

static const ga_result *find(const ga_results *r, const char *id) {
    for(size_t i = 0; i < r->n; i++)
        if(r->items[i].id && !strcmp(r->items[i].id, id))
            return &r->items[i];
    return NULL;
}

static const char *label(const ga_result *x) {
    return x && x->done ? ga_verdict_label(x->verdict) : "no verdict";
}

GPtrArray *avm_history_diff(const ga_results *a, const ga_results *b) {
    GPtrArray *out = g_ptr_array_new_with_free_func(g_free);
    for(size_t i = 0; i < a->n; i++) {
        const ga_result *x = &a->items[i];
        if(!x->id)
            continue;
        const ga_result *y = find(b, x->id);
        if(!y)
            g_ptr_array_add(out, g_strdup_printf("%s: %s -> not in the second run", x->id,
                                                 label(x)));
        else if(x->done != y->done || (x->done && x->verdict != y->verdict))
            g_ptr_array_add(out, g_strdup_printf("%s: %s -> %s", x->id, label(x), label(y)));
    }
    for(size_t i = 0; i < b->n; i++) {
        const ga_result *y = &b->items[i];
        if(y->id && !find(a, y->id))
            g_ptr_array_add(out, g_strdup_printf("%s: not in the first run -> %s", y->id,
                                                 label(y)));
    }
    return out;
}
