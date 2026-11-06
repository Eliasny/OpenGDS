/* OpenGDS Auditor desktop UI - History (Auditor plan ui/page_history.c):
 * the runs kept under the user data folder; open one in the main window,
 * or compare one with the run shown there (for example two firmware
 * versions of one device).
 * SPDX-License-Identifier: MPL-2.0 */
#include "win_main.h"

#include "avm_history.h"

#include "common/banned.h"

typedef struct {
    GtkWindow *main, *win;
    GtkListBox *list;
    GtkLabel *status;
    GPtrArray *entries; /* AvmHistoryEntry*, in list order */
} History;

static void history_free(gpointer p) {
    History *h = p;
    g_ptr_array_unref(h->entries);
    g_free(h);
}

static const AvmHistoryEntry *selected(History *h) {
    GtkListBoxRow *row = gtk_list_box_get_selected_row(h->list);
    if(!row) {
        gtk_label_set_text(h->status, "Choose a run first.");
        return NULL;
    }
    int i = gtk_list_box_row_get_index(row);
    return i >= 0 && (guint)i < h->entries->len ? g_ptr_array_index(h->entries, (guint)i) : NULL;
}

static GtkWidget *entry_row(const AvmHistoryEntry *e) {
    char *top = g_strdup_printf("%s · %s · %s", e->started, e->profile, e->outcome);
    char *bottom = g_strdup_printf("%s · Pass %zu · Fail %zu · Warn %zu · Not supported %zu · "
                                   "Not tested %zu",
                                   e->target, e->counts[GA_PASS], e->counts[GA_FAIL],
                                   e->counts[GA_WARN], e->counts[GA_NOT_SUPPORTED],
                                   e->counts[GA_NOT_TESTED]);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *l1 = gtk_label_new(top), *l2 = gtk_label_new(bottom);
    gtk_label_set_xalign(GTK_LABEL(l1), 0);
    gtk_label_set_xalign(GTK_LABEL(l2), 0);
    gtk_widget_add_css_class(l1, "heading");
    gtk_widget_add_css_class(l2, "dim-label");
    gtk_box_append(GTK_BOX(box), l1);
    gtk_box_append(GTK_BOX(box), l2);
    g_free(top);
    g_free(bottom);
    return box;
}

static void fill(History *h) {
    GtkWidget *child;
    while((child = gtk_widget_get_first_child(GTK_WIDGET(h->list))))
        gtk_list_box_remove(h->list, child);
    char *root = avm_history_dir();
    g_ptr_array_unref(h->entries);
    h->entries = avm_history_list(root);
    for(guint i = 0; i < h->entries->len; i++)
        gtk_list_box_append(h->list, entry_row(g_ptr_array_index(h->entries, i)));
    char *m = g_strdup_printf("%u run(s) in %s", h->entries->len, root);
    gtk_label_set_text(h->status, m);
    g_free(m);
    g_free(root);
}

static void on_refresh(GtkButton *b, gpointer data) {
    (void)b;
    fill(data);
}

static void on_open(GtkButton *b, gpointer data) {
    (void)b;
    History *h = data;
    const AvmHistoryEntry *e = selected(h);
    if(!e)
        return;
    GError *err = NULL;
    if(win_main_show_run(h->main, e->dir, &err)) {
        gtk_window_destroy(h->win);
        return;
    }
    gtk_label_set_text(h->status, err ? err->message : "cannot open the run");
    g_clear_error(&err);
}

static void show_diff(History *h, const AvmHistoryEntry *e, GPtrArray *d) {
    GString *s = g_string_new(NULL);
    for(guint i = 0; i < d->len; i++)
        g_string_append_printf(s, "%s\n", (const char *)g_ptr_array_index(d, i));
    char *msg = g_strdup_printf("From the run of %s to the run in the main window", e->started);
    GtkAlertDialog *dlg = gtk_alert_dialog_new("%s", msg);
    gtk_alert_dialog_set_detail(dlg, d->len ? s->str : "Every test gave the same verdict.");
    gtk_alert_dialog_set_modal(dlg, TRUE);
    gtk_alert_dialog_show(dlg, h->win);
    g_object_unref(dlg);
    g_free(msg);
    g_string_free(s, TRUE);
}

static void on_compare(GtkButton *b, gpointer data) {
    (void)b;
    History *h = data;
    const AvmHistoryEntry *e = selected(h);
    if(!e)
        return;
    const ga_results *current = win_main_results(h->main);
    if(!current) {
        gtk_label_set_text(h->status, "Open or run the run to compare with in the main window "
                                      "first.");
        return;
    }
    char *path = g_build_filename(e->dir, "events.jsonl", NULL);
    ga_results old = {0};
    char err[512];
    if(ga_results_load(path, &old, err, sizeof(err))) {
        GPtrArray *d = avm_history_diff(&old, current);
        show_diff(h, e, d);
        g_ptr_array_unref(d);
    } else {
        gtk_label_set_text(h->status, err);
    }
    ga_results_free(&old);
    g_free(path);
}

static GtkWidget *button(const char *label, GCallback cb, History *h) {
    GtkWidget *b = gtk_button_new_with_mnemonic(label);
    g_signal_connect(b, "clicked", cb, h);
    return b;
}

void page_history_present(GtkWindow *main) {
    History *h = g_new0(History, 1);
    h->main = main;
    h->entries = g_ptr_array_new();
    h->win = GTK_WINDOW(gtk_window_new());
    gtk_window_set_title(h->win, "Auditor history");
    gtk_window_set_transient_for(h->win, main);
    gtk_window_set_modal(h->win, TRUE);
    gtk_window_set_default_size(h->win, 760, 520);
    g_object_set_data_full(G_OBJECT(h->win), "gdsaudit-history", h, history_free);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_add_css_class(box, "results");
    h->list = GTK_LIST_BOX(gtk_list_box_new());
    gtk_list_box_set_selection_mode(h->list, GTK_SELECTION_SINGLE);
    GtkWidget *placeholder = gtk_label_new("No runs yet.");
    gtk_widget_add_css_class(placeholder, "dim-label");
    gtk_list_box_set_placeholder(h->list, placeholder);
    GtkWidget *sc = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(sc), GTK_WIDGET(h->list));
    gtk_widget_set_vexpand(sc, TRUE);
    gtk_box_append(GTK_BOX(box), sc);
    h->status = GTK_LABEL(gtk_label_new(NULL));
    gtk_label_set_xalign(h->status, 0);
    gtk_label_set_wrap(h->status, TRUE);
    gtk_box_append(GTK_BOX(box), GTK_WIDGET(h->status));
    GtkWidget *buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_set_halign(buttons, GTK_ALIGN_END);
    gtk_box_append(GTK_BOX(buttons), button("_Refresh", G_CALLBACK(on_refresh), h));
    gtk_box_append(GTK_BOX(buttons),
                   button("_Compare with the main window", G_CALLBACK(on_compare), h));
    GtkWidget *open = button("_Open", G_CALLBACK(on_open), h);
    gtk_widget_add_css_class(open, "suggested-action");
    gtk_box_append(GTK_BOX(buttons), open);
    gtk_box_append(GTK_BOX(box), buttons);
    gtk_window_set_child(h->win, box);
    fill(h);
    gtk_window_present(h->win);
}
