/* OpenGDS Auditor desktop UI - the confirmation before a run may change the
 * target (Auditor plan ui/dlg_allow_changes.c, "Safety in the UI"):
 * read-only is the default, and allowing changes names the endpoint and the
 * certificate thumbprint of the target.
 * SPDX-License-Identifier: MPL-2.0 */
#include "win_main.h"

#include "common/banned.h"

typedef struct {
    dlg_allow_changes_done done;
    gpointer user;
} pending;

enum { BTN_CANCEL = 0, BTN_ALLOW = 1 };

static void on_choice(GObject *src, GAsyncResult *res, gpointer data) {
    pending *p = data;
    GError *e = NULL;
    int b = gtk_alert_dialog_choose_finish(GTK_ALERT_DIALOG(src), res, &e);
    g_clear_error(&e); /* dismissed: same as Cancel */
    p->done(b == BTN_ALLOW, p->user);
    g_free(p);
}

void dlg_allow_changes_run(GtkWindow *parent, const char *endpoint, const char *thumbprint,
                           gboolean tofu, dlg_allow_changes_done done, gpointer user) {
    const char *pin = thumbprint ? thumbprint
                      : tofu     ? "not pinned: trusted on first use (test setups only)"
                                 : "not pinned: the target is trusted through the chosen CA";
    char *detail = g_strdup_printf(
        "Endpoint: %s\nCertificate thumbprint (SHA-1): %s\n\n"
        "The Auditor will write trust lists and certificates to this target. It saves the "
        "target's trust list and certificates first and restores them at the end, on error "
        "and on abort. Allow this only on a target you are responsible for.",
        endpoint, pin);
    GtkAlertDialog *d = gtk_alert_dialog_new("Allow changes to this target?");
    gtk_alert_dialog_set_detail(d, detail);
    const char *buttons[] = {"Cancel", "Allow changes and run", NULL};
    gtk_alert_dialog_set_buttons(d, buttons);
    gtk_alert_dialog_set_cancel_button(d, BTN_CANCEL);
    gtk_alert_dialog_set_default_button(d, BTN_CANCEL);
    gtk_alert_dialog_set_modal(d, TRUE);
    pending *p = g_new0(pending, 1);
    p->done = done;
    p->user = user;
    gtk_alert_dialog_choose(d, parent, NULL, on_choice, p);
    g_object_unref(d);
    g_free(detail);
}
