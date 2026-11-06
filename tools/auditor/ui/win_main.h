/* OpenGDS Auditor desktop UI - main window (Auditor plan ui/win_main.c).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_UI_WIN_MAIN_H
#define GDSAUDIT_UI_WIN_MAIN_H

#include <gtk/gtk.h>

GtkWindow *win_main_new(GtkApplication *app);

/* For the smoke test: TRUE if every part of the window was built. */
gboolean win_main_check(GtkWindow *win);

/* Confirmation before a run that changes the target (ui/dlg_allow_changes.c):
 * names the endpoint and the pinned certificate's thumbprint. Calls done
 * with TRUE only if the user chose to allow changes. */
typedef void (*dlg_allow_changes_done)(gboolean allowed, gpointer user);
void dlg_allow_changes_run(GtkWindow *parent, const char *endpoint, const char *thumbprint,
                           gboolean tofu, dlg_allow_changes_done done, gpointer user);

#endif
