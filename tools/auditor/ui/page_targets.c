/* OpenGDS Auditor desktop UI - Targets (Auditor plan ui/page_targets.c):
 * find a device's endpoints and use one in the form (its URL, with its
 * certificate pinned), and keep the form as a named saved target.
 * SPDX-License-Identifier: MPL-2.0 */
#include "win_main.h"

#include "avm_run.h"
#include "avm_target.h"

#include "common/banned.h"

typedef struct {
    GtkWindow *main, *win; /* win is NULL once closed */
    GtkEntry *url, *name;
    GtkButton *findBtn;
    GtkSpinner *spinner;
    GtkListBox *endpoints, *saved;
    GtkLabel *status, *servers;
    GPtrArray *found; /* AvmEndpoint*, borrowed from discovery */
    AvmDiscovery *discovery;
    GCancellable *cancel;
    char *targetsPath;
} Targets;

/* Shared by the window and a discovery in flight. */
static void targets_clear(gpointer p) {
    Targets *t = p;
    avm_discovery_free(t->discovery);
    g_clear_object(&t->cancel);
    g_free(t->targetsPath);
}

static void targets_unref(gpointer p) {
    g_rc_box_release_full(p, targets_clear);
}

static void set_status(Targets *t, const char *text) {
    gtk_label_set_text(t->status, text);
}

static void clear_list(GtkListBox *l) {
    GtkWidget *child;
    while((child = gtk_widget_get_first_child(GTK_WIDGET(l))))
        gtk_list_box_remove(l, child);
}

static GtkWidget *two_lines(const char *top, const char *bottom, const char *third) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    const char *texts[] = {top, bottom, third};
    for(size_t i = 0; i < G_N_ELEMENTS(texts); i++) {
        if(!texts[i] || !*texts[i])
            continue;
        GtkWidget *l = gtk_label_new(texts[i]);
        gtk_label_set_xalign(GTK_LABEL(l), 0);
        gtk_label_set_wrap(GTK_LABEL(l), TRUE);
        gtk_label_set_selectable(GTK_LABEL(l), i > 0);
        gtk_widget_add_css_class(l, i == 0 ? "heading" : "dim-label");
        gtk_box_append(GTK_BOX(box), l);
    }
    return box;
}

static const char *mode_label(const char *mode) {
    if(!g_strcmp0(mode, "signandencrypt"))
        return "Sign and encrypt";
    if(!g_strcmp0(mode, "sign"))
        return "Sign";
    return !g_strcmp0(mode, "none") ? "No security" : mode;
}

static GtkWidget *endpoint_row(const AvmEndpoint *e) {
    char *top = g_strdup_printf("%s · %s · security level %u", avm_policy_name(e->policyUri),
                                mode_label(e->mode), e->level);
    char *mid = g_strdup_printf("%s · user tokens: %s", e->url,
                                *e->userTokens ? e->userTokens : "none listed");
    char *low = *e->thumbprint ? g_strdup_printf("Certificate %s · %s", e->thumbprint,
                                                 e->certText)
                               : g_strdup("No server certificate");
    GtkWidget *w = two_lines(top, mid, low);
    g_free(top);
    g_free(mid);
    g_free(low);
    return w;
}

static void show_discovery(Targets *t, AvmDiscovery *d) {
    clear_list(t->endpoints);
    g_ptr_array_set_size(t->found, 0);
    avm_discovery_free(t->discovery);
    t->discovery = d;
    GString *s = g_string_new(NULL);
    for(guint i = 0; i < d->servers->len; i++)
        g_string_append_printf(s, "%sServer: %s", s->len ? "\n" : "",
                               (const char *)g_ptr_array_index(d->servers, i));
    for(guint i = 0; i < d->errors->len; i++)
        g_string_append_printf(s, "%s%s", s->len ? "\n" : "",
                               (const char *)g_ptr_array_index(d->errors, i));
    gtk_label_set_text(t->servers, s->str);
    g_string_free(s, TRUE);
    for(guint i = 0; i < d->endpoints->len; i++) {
        const AvmEndpoint *e = g_ptr_array_index(d->endpoints, i);
        g_ptr_array_add(t->found, (gpointer)(uintptr_t)e);
        gtk_list_box_append(t->endpoints, endpoint_row(e));
    }
    if(d->endpoints->len) {
        gtk_list_box_select_row(t->endpoints, gtk_list_box_get_row_at_index(t->endpoints, 0));
        set_status(t, "Choose an endpoint. Check its certificate thumbprint with the device "
                      "before you pin it.");
    } else {
        set_status(t, "No endpoints found.");
    }
}

static void on_discovered(AvmDiscovery *d, const char *error, gpointer user) {
    Targets *t = user;
    if(t->win) {
        gtk_spinner_set_spinning(t->spinner, FALSE);
        gtk_widget_set_sensitive(GTK_WIDGET(t->findBtn), TRUE);
        if(d) {
            /* d is freed after this call: keep its arrays */
            AvmDiscovery *mine = g_new0(AvmDiscovery, 1);
            mine->endpoints = g_ptr_array_ref(d->endpoints);
            mine->servers = g_ptr_array_ref(d->servers);
            mine->errors = g_ptr_array_ref(d->errors);
            show_discovery(t, mine);
        } else {
            char *m = g_strdup_printf("Discovery failed: %s", error ? error : "unknown error");
            set_status(t, m);
            g_free(m);
        }
    }
    targets_unref(t);
}

static void on_find(GtkButton *b, gpointer data) {
    (void)b;
    Targets *t = data;
    char *url = g_strstrip(g_strdup(gtk_editable_get_text(GTK_EDITABLE(t->url))));
    if(!g_str_has_prefix(url, "opc.tcp://")) {
        set_status(t, "Enter a discovery URL that starts with opc.tcp://");
        g_free(url);
        return;
    }
    char *engine = avm_engine_path();
    char *certs = avm_discover_certs_dir();
    gtk_spinner_set_spinning(t->spinner, TRUE);
    gtk_widget_set_sensitive(GTK_WIDGET(t->findBtn), FALSE);
    set_status(t, "Asking the server for its endpoints…");
    avm_discover(engine, url, certs, t->cancel, on_discovered, g_rc_box_acquire(t));
    g_free(certs);
    g_free(engine);
    g_free(url);
}

static void on_use(GtkButton *b, gpointer data) {
    (void)b;
    Targets *t = data;
    GtkListBoxRow *row = gtk_list_box_get_selected_row(t->endpoints);
    int i = row ? gtk_list_box_row_get_index(row) : -1;
    if(i < 0 || (guint)i >= t->found->len) {
        set_status(t, "Find the endpoints and choose one first.");
        return;
    }
    const AvmEndpoint *e = g_ptr_array_index(t->found, (guint)i);
    AvmPlan *p = win_main_plan(t->main);
    if(!p) {
        set_status(t, "A run is going: wait for it or abort it.");
        return;
    }
    avm_plan_use_endpoint(p, e);
    win_main_plan_changed(t->main);
    char *m = *e->certFile ? g_strdup_printf("The form now uses %s with certificate %s pinned.",
                                             e->url, e->thumbprint)
                           : g_strdup_printf("The form now uses %s. This endpoint showed no "
                                             "certificate, so none is pinned.",
                                             e->url);
    set_status(t, m);
    g_free(m);
}

/* ---- saved targets ---- */

static void fill_saved(Targets *t) {
    clear_list(t->saved);
    char **names = avm_targets_list(t->targetsPath);
    for(size_t i = 0; names[i]; i++) {
        GtkWidget *l = gtk_label_new(names[i]);
        gtk_label_set_xalign(GTK_LABEL(l), 0);
        gtk_list_box_append(t->saved, l);
    }
    g_strfreev(names);
}

/* The selected saved target's name (g_free it), or NULL. */
static char *saved_name(Targets *t) {
    GtkListBoxRow *row = gtk_list_box_get_selected_row(t->saved);
    GtkWidget *l = row ? gtk_list_box_row_get_child(row) : NULL;
    if(!l) {
        set_status(t, "Choose a saved target first.");
        return NULL;
    }
    return g_strdup(gtk_label_get_text(GTK_LABEL(l)));
}

static void report(Targets *t, gboolean ok, GError *e, const char *done) {
    if(ok) {
        set_status(t, done);
    } else {
        char *m = g_strdup_printf("%s", e ? e->message : "failed");
        set_status(t, m);
        g_free(m);
    }
    g_clear_error(&e);
}

static void on_save(GtkButton *b, gpointer data) {
    (void)b;
    Targets *t = data;
    char *name = g_strstrip(g_strdup(gtk_editable_get_text(GTK_EDITABLE(t->name))));
    AvmPlan *p = win_main_plan(t->main);
    GError *e = NULL;
    gboolean ok = p && avm_target_save(t->targetsPath, name, p, &e);
    if(!p)
        g_set_error(&e, G_IO_ERROR, G_IO_ERROR_BUSY, "A run is going: wait for it or abort it.");
    char *m = g_strdup_printf("Saved the form as “%s” (paths only, never passwords).", name);
    report(t, ok, e, m);
    g_free(m);
    if(ok)
        fill_saved(t);
    g_free(name);
}

static void on_load(GtkButton *b, gpointer data) {
    (void)b;
    Targets *t = data;
    char *name = saved_name(t);
    if(!name)
        return;
    AvmPlan *p = win_main_plan(t->main);
    GError *e = NULL;
    gboolean ok = p && avm_target_load(t->targetsPath, name, p, &e);
    if(!p)
        g_set_error(&e, G_IO_ERROR, G_IO_ERROR_BUSY, "A run is going: wait for it or abort it.");
    if(ok)
        win_main_plan_changed(t->main);
    char *m = g_strdup_printf("Loaded “%s” into the form.", name);
    report(t, ok, e, m);
    g_free(m);
    gtk_editable_set_text(GTK_EDITABLE(t->name), name);
    g_free(name);
}

typedef struct {
    Targets *t;
    char *name;
} DeleteAsk;

static void on_delete_answer(GObject *src, GAsyncResult *res, gpointer data) {
    DeleteAsk *a = data;
    int choice = gtk_alert_dialog_choose_finish(GTK_ALERT_DIALOG(src), res, NULL);
    if(choice == 1 && a->t->win) {
        GError *e = NULL;
        gboolean ok = avm_target_delete(a->t->targetsPath, a->name, &e);
        char *m = g_strdup_printf("Deleted “%s”.", a->name);
        report(a->t, ok, e, m);
        g_free(m);
        fill_saved(a->t);
    }
    targets_unref(a->t);
    g_free(a->name);
    g_free(a);
}

static void on_delete(GtkButton *b, gpointer data) {
    (void)b;
    Targets *t = data;
    char *name = saved_name(t);
    if(!name)
        return;
    GtkAlertDialog *d = gtk_alert_dialog_new("Delete the saved target “%s”?", name);
    gtk_alert_dialog_set_detail(d, "Only the saved entry is deleted, not the files it names.");
    const char *buttons[] = {"_Cancel", "_Delete", NULL};
    gtk_alert_dialog_set_buttons(d, buttons);
    gtk_alert_dialog_set_cancel_button(d, 0);
    gtk_alert_dialog_set_default_button(d, 0);
    DeleteAsk *a = g_new0(DeleteAsk, 1);
    a->t = g_rc_box_acquire(t);
    a->name = name;
    gtk_alert_dialog_choose(d, t->win, NULL, on_delete_answer, a);
    g_object_unref(d);
}

/* ---- window ---- */

static void on_destroy(GtkWidget *win, gpointer data) {
    (void)win;
    Targets *t = data;
    t->win = NULL;
    g_cancellable_cancel(t->cancel);
    g_ptr_array_unref(t->found);
    t->found = NULL;
    targets_unref(t);
}

static GtkWidget *button(const char *label, GCallback cb, Targets *t) {
    GtkWidget *b = gtk_button_new_with_mnemonic(label);
    g_signal_connect(b, "clicked", cb, t);
    return b;
}

static GtkWidget *heading(const char *text) {
    GtkWidget *l = gtk_label_new(text);
    gtk_label_set_xalign(GTK_LABEL(l), 0);
    gtk_widget_add_css_class(l, "title-4");
    return l;
}

static GtkWidget *scrolled_list(GtkListBox *list, const char *empty, int height) {
    gtk_list_box_set_selection_mode(list, GTK_SELECTION_SINGLE);
    GtkWidget *placeholder = gtk_label_new(empty);
    gtk_widget_add_css_class(placeholder, "dim-label");
    gtk_list_box_set_placeholder(list, placeholder);
    GtkWidget *sc = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(sc), GTK_WIDGET(list));
    gtk_widget_set_size_request(sc, -1, height);
    return sc;
}

static GtkWidget *build_discovery(Targets *t, const AvmPlan *p) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_append(GTK_BOX(box), heading("Find a device"));
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    t->url = GTK_ENTRY(gtk_entry_new());
    gtk_entry_set_placeholder_text(t->url, "opc.tcp://host:4840 (a server or a discovery server)");
    gtk_editable_set_text(GTK_EDITABLE(t->url), p && p->url ? p->url : "");
    gtk_widget_set_hexpand(GTK_WIDGET(t->url), TRUE);
    gtk_accessible_update_property(GTK_ACCESSIBLE(t->url), GTK_ACCESSIBLE_PROPERTY_LABEL,
                                   "Discovery URL", -1);
    g_signal_connect_swapped(t->url, "activate", G_CALLBACK(on_find), t);
    gtk_box_append(GTK_BOX(row), GTK_WIDGET(t->url));
    t->spinner = GTK_SPINNER(gtk_spinner_new());
    gtk_box_append(GTK_BOX(row), GTK_WIDGET(t->spinner));
    t->findBtn = GTK_BUTTON(button("_Find endpoints", G_CALLBACK(on_find), t));
    gtk_box_append(GTK_BOX(row), GTK_WIDGET(t->findBtn));
    gtk_box_append(GTK_BOX(box), row);
    t->servers = GTK_LABEL(gtk_label_new(NULL));
    gtk_label_set_xalign(t->servers, 0);
    gtk_label_set_wrap(t->servers, TRUE);
    gtk_label_set_selectable(t->servers, TRUE);
    gtk_widget_add_css_class(GTK_WIDGET(t->servers), "dim-label");
    gtk_box_append(GTK_BOX(box), GTK_WIDGET(t->servers));
    t->endpoints = GTK_LIST_BOX(gtk_list_box_new());
    GtkWidget *sc = scrolled_list(t->endpoints, "No endpoints yet.", 220);
    gtk_widget_set_vexpand(sc, TRUE);
    gtk_box_append(GTK_BOX(box), sc);
    GtkWidget *use = button("_Use this endpoint", G_CALLBACK(on_use), t);
    gtk_widget_set_tooltip_text(use, "Put its URL in the form and pin its certificate");
    gtk_widget_set_halign(use, GTK_ALIGN_END);
    gtk_widget_add_css_class(use, "suggested-action");
    gtk_box_append(GTK_BOX(box), use);
    return box;
}

static GtkWidget *build_saved(Targets *t) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_append(GTK_BOX(box), heading("Saved targets"));
    t->saved = GTK_LIST_BOX(gtk_list_box_new());
    gtk_box_append(GTK_BOX(box), scrolled_list(t->saved, "No saved targets.", 120));
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    t->name = GTK_ENTRY(gtk_entry_new());
    gtk_entry_set_placeholder_text(t->name, "Name, for example Line 3 PLC");
    gtk_widget_set_hexpand(GTK_WIDGET(t->name), TRUE);
    gtk_accessible_update_property(GTK_ACCESSIBLE(t->name), GTK_ACCESSIBLE_PROPERTY_LABEL,
                                   "Saved target name", -1);
    gtk_box_append(GTK_BOX(row), GTK_WIDGET(t->name));
    gtk_box_append(GTK_BOX(row), button("_Save the form", G_CALLBACK(on_save), t));
    gtk_box_append(GTK_BOX(row), button("_Load", G_CALLBACK(on_load), t));
    gtk_box_append(GTK_BOX(row), button("_Delete…", G_CALLBACK(on_delete), t));
    gtk_box_append(GTK_BOX(box), row);
    return box;
}

void page_targets_present(GtkWindow *main) {
    Targets *t = g_rc_box_new0(Targets);
    t->main = main;
    t->found = g_ptr_array_new();
    t->cancel = g_cancellable_new();
    t->targetsPath = avm_targets_default_path();
    t->win = GTK_WINDOW(gtk_window_new());
    gtk_window_set_title(t->win, "Auditor targets");
    gtk_window_set_transient_for(t->win, main);
    gtk_window_set_modal(t->win, TRUE);
    gtk_window_set_default_size(t->win, 760, 640);
    g_signal_connect(t->win, "destroy", G_CALLBACK(on_destroy), t);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_add_css_class(box, "results");
    gtk_box_append(GTK_BOX(box), build_discovery(t, win_main_plan(main)));
    gtk_box_append(GTK_BOX(box), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL));
    gtk_box_append(GTK_BOX(box), build_saved(t));
    t->status = GTK_LABEL(gtk_label_new(NULL));
    gtk_label_set_xalign(t->status, 0);
    gtk_label_set_wrap(t->status, TRUE);
    gtk_accessible_update_property(GTK_ACCESSIBLE(t->status), GTK_ACCESSIBLE_PROPERTY_LABEL,
                                   "Status", -1);
    gtk_box_append(GTK_BOX(box), GTK_WIDGET(t->status));
    gtk_window_set_child(t->win, box);
    fill_saved(t);
    gtk_window_present(t->win);
}
