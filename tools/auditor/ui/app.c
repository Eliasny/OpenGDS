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

static gboolean smoke_check(gpointer data) {
    GtkWindow *win = data;
    smokeResult = win_main_check(win) ? 0 : 1;
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
