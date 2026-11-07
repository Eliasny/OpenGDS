/* OpenGDS Auditor desktop UI - gdsaudit-gui (Auditor plan ui/app.c).
 *
 *   gdsaudit-gui            the desktop app
 *   gdsaudit-gui --smoke    build the window, check it and quit (CI)
 *
 * The engine is the gdsaudit binary next to this one ($GDSAUDIT_ENGINE
 * overrides it).
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>

#include "win_main.h"

#include "common/banned.h"

static gboolean smoke;
static int smokeResult = 1;

static void smoke_answer(ga_answer a, const char *note, gpointer user) {
    (void)a;
    (void)note;
    (void)user; /* never pressed in the smoke run */
}

/* The main window, then History, Targets and an operator step over it:
 * every window is built and has its title; closing them all ends the app. */
static gboolean smoke_check(gpointer data) {
    GtkWindow *win = data;
    gboolean ok = win_main_check(win);
    page_history_present(win);
    page_targets_present(win);
    (void)dlg_prompt_present(win, 1, "SRV-X-01", "smoke", "Press the reset button", smoke_answer,
                             NULL);
    GListModel *tops = gtk_window_get_toplevels();
    guint n = g_list_model_get_n_items(tops);
    gboolean history = FALSE, targets = FALSE, prompt = FALSE;
    GPtrArray *close = g_ptr_array_new();
    for(guint i = 0; i < n; i++) {
        GtkWindow *t = g_list_model_get_item(tops, i);
        const char *title = gtk_window_get_title(t);
        history = history || g_strcmp0(title, "Auditor history") == 0;
        targets = targets || g_strcmp0(title, "Auditor targets") == 0;
        prompt = prompt || g_strcmp0(title, "Operator step") == 0;
        if(t != win)
            g_ptr_array_add(close, t);
        g_object_unref(t);
    }
    for(guint i = 0; i < close->len; i++)
        gtk_window_destroy(g_ptr_array_index(close, i));
    g_ptr_array_unref(close);
    if(!history || !targets || !prompt)
        g_printerr("smoke: history %d, targets %d, operator step %d\n", history, targets, prompt);
    smokeResult = ok && history && targets && prompt ? 0 : 1;
    gtk_window_destroy(win);
    return G_SOURCE_REMOVE;
}

static void on_activate(GtkApplication *app, gpointer data) {
    (void)data;
    GtkWindow *win = win_main_new(app);
    gtk_window_present(win);
    if(smoke)
        g_timeout_add(500, smoke_check, win);
}

int main(int argc, char **argv) {
    if(argc == 2 && strcmp(argv[1], "--smoke") == 0) {
        smoke = TRUE;
        argc = 1;
    }
    GtkApplication *app =
        gtk_application_new("org.opengds.Auditor", G_APPLICATION_NON_UNIQUE);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);
    int rc = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    if(smoke)
        return rc != 0 ? rc : smokeResult;
    return rc;
}
