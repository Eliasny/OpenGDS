/* OpenGDS Auditor desktop UI - an operator step (engine.h operator prompts):
 * a test asks the person at the UI to do something by hand, such as
 * restarting the device. The answer is Done, Skip (the test is Not tested)
 * or Report failure (the test fails; a note saying what went wrong is
 * required).
 *
 * The window is not modal, so Pause and Abort in the main window still
 * work, and it has no close button: the run waits for an answer. The main
 * window destroys it when the engine stops waiting (answered, aborted or
 * exited); done is called only for a button the person pressed.
 * SPDX-License-Identifier: MPL-2.0 */
#include "win_main.h"

#include "common/banned.h"

typedef struct {
    GtkWindow *win;
    GtkEntry *note;
    GtkWidget *failBtn;
    dlg_prompt_done done;
    gpointer user;
} prompt;

static void answer(prompt *p, ga_answer a) {
    const char *note = gtk_editable_get_text(GTK_EDITABLE(p->note));
    p->done(a, note, p->user);
    gtk_window_destroy(p->win); /* frees p */
}

static void on_done(GtkButton *b, gpointer data) {
    (void)b;
    answer(data, GA_ANSWER_DONE);
}

static void on_skip(GtkButton *b, gpointer data) {
    (void)b;
    answer(data, GA_ANSWER_SKIP);
}

static void on_fail(GtkButton *b, gpointer data) {
    (void)b;
    answer(data, GA_ANSWER_FAIL);
}

/* A failure needs a note: the report says what the operator saw. */
static void on_note_changed(GtkEditable *e, gpointer data) {
    prompt *p = data;
    char *t = g_strdup(gtk_editable_get_text(e));
    gtk_widget_set_sensitive(p->failBtn, *g_strstrip(t) != '\0');
    g_free(t);
}

static gboolean on_close_request(GtkWindow *w, gpointer data) {
    (void)w;
    (void)data;
    return TRUE; /* only an answer closes it (or the main window) */
}

static GtkWidget *button(const char *mnemonic, GCallback cb, prompt *p) {
    GtkWidget *b = gtk_button_new_with_mnemonic(mnemonic);
    g_signal_connect(b, "clicked", cb, p);
    return b;
}

GtkWindow *dlg_prompt_present(GtkWindow *parent, size_t seq, const char *testId,
                              const char *testTitle, const char *text, dlg_prompt_done done,
                              gpointer user) {
    prompt *p = g_new0(prompt, 1);
    p->done = done;
    p->user = user;
    p->win = GTK_WINDOW(gtk_window_new());
    g_object_set_data_full(G_OBJECT(p->win), "gdsaudit-prompt", p, g_free);
    gtk_window_set_title(p->win, "Operator step");
    gtk_window_set_transient_for(p->win, parent);
    gtk_window_set_deletable(p->win, FALSE);
    gtk_window_set_default_size(p->win, 520, -1);
    g_signal_connect(p->win, "close-request", G_CALLBACK(on_close_request), NULL);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_top(box, 16);
    gtk_widget_set_margin_bottom(box, 16);
    gtk_widget_set_margin_start(box, 16);
    gtk_widget_set_margin_end(box, 16);

    char *head = g_strdup_printf("Step %zu for test %s%s%s", seq, testId ? testId : "?",
                                 testTitle && *testTitle ? ": " : "",
                                 testTitle ? testTitle : "");
    GtkWidget *h = gtk_label_new(head);
    g_free(head);
    gtk_label_set_wrap(GTK_LABEL(h), TRUE);
    gtk_label_set_xalign(GTK_LABEL(h), 0);
    gtk_widget_add_css_class(h, "heading");
    gtk_box_append(GTK_BOX(box), h);

    GtkWidget *t = gtk_label_new(text ? text : "");
    gtk_label_set_wrap(GTK_LABEL(t), TRUE);
    gtk_label_set_selectable(GTK_LABEL(t), TRUE);
    gtk_label_set_xalign(GTK_LABEL(t), 0);
    gtk_box_append(GTK_BOX(box), t);

    GtkWidget *hint = gtk_label_new("The run waits here. Done when the step is carried out; Skip "
                                    "leaves this test Not tested; Report failure fails it with "
                                    "your note.");
    gtk_label_set_wrap(GTK_LABEL(hint), TRUE);
    gtk_label_set_xalign(GTK_LABEL(hint), 0);
    gtk_widget_add_css_class(hint, "dim-label");
    gtk_box_append(GTK_BOX(box), hint);

    p->note = GTK_ENTRY(gtk_entry_new());
    gtk_entry_set_placeholder_text(p->note, "What you saw (needed to report a failure)");
    gtk_entry_set_max_length(p->note, 900);
    GtkWidget *nl = gtk_label_new_with_mnemonic("_Note");
    gtk_label_set_xalign(GTK_LABEL(nl), 0);
    gtk_label_set_mnemonic_widget(GTK_LABEL(nl), GTK_WIDGET(p->note));
    gtk_box_append(GTK_BOX(box), nl);
    gtk_box_append(GTK_BOX(box), GTK_WIDGET(p->note));

    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(row, GTK_ALIGN_END);
    gtk_widget_set_margin_top(row, 6);
    GtkWidget *skip = button("_Skip this step", G_CALLBACK(on_skip), p);
    p->failBtn = button("Report _failure", G_CALLBACK(on_fail), p);
    gtk_widget_set_sensitive(p->failBtn, FALSE);
    gtk_widget_set_tooltip_text(p->failBtn, "Write in the note what went wrong first.");
    gtk_widget_add_css_class(p->failBtn, "destructive-action");
    GtkWidget *ok = button("_Done", G_CALLBACK(on_done), p);
    gtk_widget_add_css_class(ok, "suggested-action");
    gtk_box_append(GTK_BOX(row), skip);
    gtk_box_append(GTK_BOX(row), p->failBtn);
    gtk_box_append(GTK_BOX(row), ok);
    gtk_box_append(GTK_BOX(box), row);
    g_signal_connect(p->note, "changed", G_CALLBACK(on_note_changed), p);

    gtk_window_set_child(p->win, box);
    gtk_window_set_default_widget(p->win, ok);
    gtk_window_present(p->win);
    return p->win;
}
