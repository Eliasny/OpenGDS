/* OpenGDS Auditor desktop UI - main window (Auditor plan ui/win_main.c).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_UI_WIN_MAIN_H
#define GDSAUDIT_UI_WIN_MAIN_H

#include <gtk/gtk.h>

#include "avm_plan.h"
#include "results.h"

GtkWindow *win_main_new(GtkApplication *app);

/* Show a stored run (a run folder with events.jsonl) in the main window.
 * Returns FALSE and sets *error if it cannot be read or a run is going. */
gboolean win_main_show_run(GtkWindow *win, const char *dir, GError **error);
/* The run shown in the main window, or NULL. */
const ga_results *win_main_results(GtkWindow *win);

/* History (ui/page_history.c): past runs, open one, compare one with the
 * run shown in the main window. */
void page_history_present(GtkWindow *main);

/* The form as a plan (read from the widgets first), for the Targets
 * window to change; NULL while a run is going. After a change, call
 * win_main_plan_changed to show it in the form. */
AvmPlan *win_main_plan(GtkWindow *win);
void win_main_plan_changed(GtkWindow *win);

/* Targets (ui/page_targets.c): discovery, use an endpoint in the form,
 * saved targets. */
void page_targets_present(GtkWindow *main);

/* For the smoke test: TRUE if every part of the window was built. */
gboolean win_main_check(GtkWindow *win);

/* Confirmation before a run that changes the target (ui/dlg_allow_changes.c):
 * names the endpoint and the pinned certificate's thumbprint. Calls done
 * with TRUE only if the user chose to allow changes. */
typedef void (*dlg_allow_changes_done)(gboolean allowed, gpointer user);
void dlg_allow_changes_run(GtkWindow *parent, const char *endpoint, const char *thumbprint,
                           gboolean tofu, dlg_allow_changes_done done, gpointer user);

#endif
