/* OpenGDS Auditor view-model - past runs (Auditor plan avm/avm_history.c):
 * the run folders under the user data folder, and the difference between
 * two runs (for example two firmware versions of one device).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_AVM_HISTORY_H
#define GDSAUDIT_AVM_HISTORY_H

#include <glib.h>

#include "results.h"

typedef struct {
    char *dir;     /* the run folder */
    char *profile, *target, *started;
    const char *outcome; /* static string, ga_results_outcome() */
    size_t counts[GA_VERDICT_COUNT];
} AvmHistoryEntry;

/* The folder runs are kept in: <user data>/gdsaudit/runs */
char *avm_history_dir(void);

/* Every readable run folder under root (a folder with events.jsonl),
 * newest first. Unreadable folders are skipped. g_ptr_array_unref frees. */
GPtrArray *avm_history_list(const char *root);

/* What changed from run a to run b, one line per test whose verdict
 * differs or that is in only one of them ("SRV-TL-02: Pass -> Fail").
 * Empty array if both runs gave the same verdicts. */
GPtrArray *avm_history_diff(const ga_results *a, const ga_results *b);

#endif
