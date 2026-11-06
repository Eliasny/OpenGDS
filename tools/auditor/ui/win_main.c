/* OpenGDS Auditor desktop UI - the main window (Auditor plan AT1 thin path:
 * one window with target, profile, preset and Run; live verdict list;
 * abort that restores the target; open and export the report).
 *
 * The window holds no test logic: it builds the headless command line from
 * the plan (avm/avm_plan.c), runs it (avm/avm_run.c) and shows the events.
 * SPDX-License-Identifier: MPL-2.0 */
#include "win_main.h"

#include <string.h>

#include "avm_plan.h"
#include "avm_run.h"

#include "common/banned.h"

typedef struct {
    GtkWidget *row;
    GtkLabel *verdict, *details;
    GtkExpander *expander;
    GString *text; /* evidence, then notes */
} vrow;

typedef struct {
    GtkWindow *win;
    AvmPlan plan;
    AvmRun *run;
    gboolean closeWhenDone;
    /* form */
    GtkDropDown *profile, *preset;
    GtkLabel *presetDesc;
    GtkWidget *targetBox, *serverBox, *gdsBox, *clientBox;
    GtkEntry *url, *user, *passwordFile, *serverCert, *trust, *crl, *trigger, *clientUser, *work;
    GtkEntry *adminCert, *adminKey, *adminUser, *adminPasswordFile;
    GtkCheckButton *tofu, *allowChanges;
    GtkSpinButton *port;
    /* run */
    GtkWidget *runBtn, *abortBtn, *exportBtn, *openBtn;
    GtkLabel *banner, *status;
    GtkProgressBar *progress;
    GtkListBox *list;
    GPtrArray *rows; /* vrow*, by test number - 1 */
    GtkTextBuffer *log;
    GtkExpander *logExpander;
} Win;

static const char *const verdictCss[GA_VERDICT_COUNT] = {"verdict-pass", "verdict-fail",
                                                         "verdict-warn", "verdict-ns",
                                                         "verdict-nt"};

static void vrow_free(gpointer p) {
    vrow *r = p;
    g_string_free(r->text, TRUE);
    g_free(r);
}

static void win_free(gpointer p) {
    Win *w = p;
    avm_run_free(w->run);
    avm_plan_clear(&w->plan);
    g_ptr_array_unref(w->rows);
    g_free(w);
}

/* ---- form ---- */

static GtkWidget *field_label(const char *text, GtkWidget *mnemonicFor) {
    GtkWidget *l = gtk_label_new_with_mnemonic(text);
    gtk_label_set_xalign(GTK_LABEL(l), 0);
    gtk_widget_add_css_class(l, "field-label");
    if(mnemonicFor)
        gtk_label_set_mnemonic_widget(GTK_LABEL(l), mnemonicFor);
    return l;
}

static GtkEntry *add_entry(GtkWidget *box, const char *label, const char *placeholder) {
    GtkWidget *e = gtk_entry_new();
    if(placeholder)
        gtk_entry_set_placeholder_text(GTK_ENTRY(e), placeholder);
    gtk_box_append(GTK_BOX(box), field_label(label, e));
    gtk_box_append(GTK_BOX(box), e);
    return GTK_ENTRY(e);
}

typedef enum { PICK_FILE, PICK_FILES, PICK_FOLDER } pick_kind;

typedef struct {
    GtkEntry *entry;
    pick_kind kind;
} picker;

static void set_entry(GtkEntry *e, const char *s) {
    gtk_editable_set_text(GTK_EDITABLE(e), s ? s : "");
}

static const char *entry_text(GtkEntry *e) {
    return gtk_editable_get_text(GTK_EDITABLE(e));
}

static void set_entry_from_files(GtkEntry *entry, GListModel *files) {
    GString *s = g_string_new(NULL);
    for(guint i = 0; i < g_list_model_get_n_items(files); i++) {
        GFile *f = g_list_model_get_item(files, i);
        char *path = g_file_get_path(f);
        if(path)
            g_string_append_printf(s, "%s%s", s->len ? ";" : "", path);
        g_free(path);
        g_object_unref(f);
    }
    set_entry(entry, s->str);
    g_string_free(s, TRUE);
}

static void on_picked(GObject *src, GAsyncResult *res, gpointer data) {
    picker *p = data;
    GtkFileDialog *d = GTK_FILE_DIALOG(src);
    GError *e = NULL;
    if(p->kind == PICK_FILES) {
        GListModel *files = gtk_file_dialog_open_multiple_finish(d, res, &e);
        if(files) {
            set_entry_from_files(p->entry, files);
            g_object_unref(files);
        }
    } else {
        GFile *f = p->kind == PICK_FOLDER ? gtk_file_dialog_select_folder_finish(d, res, &e)
                                          : gtk_file_dialog_open_finish(d, res, &e);
        if(f) {
            char *path = g_file_get_path(f);
            set_entry(p->entry, path);
            g_free(path);
            g_object_unref(f);
        }
    }
    g_clear_error(&e); /* dismissed */
}

static void on_browse(GtkButton *b, gpointer data) {
    picker *p = data;
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_modal(d, TRUE);
    GtkWindow *parent = GTK_WINDOW(gtk_widget_get_root(GTK_WIDGET(b)));
    if(p->kind == PICK_FOLDER)
        gtk_file_dialog_select_folder(d, parent, NULL, on_picked, p);
    else if(p->kind == PICK_FILES)
        gtk_file_dialog_open_multiple(d, parent, NULL, on_picked, p);
    else
        gtk_file_dialog_open(d, parent, NULL, on_picked, p);
    g_object_unref(d);
}

/* A labelled entry with a Browse button for a file or folder path. */
static GtkEntry *add_path(GtkWidget *box, const char *label, const char *placeholder,
                          pick_kind kind) {
    GtkWidget *e = gtk_entry_new();
    gtk_widget_set_hexpand(e, TRUE);
    if(placeholder)
        gtk_entry_set_placeholder_text(GTK_ENTRY(e), placeholder);
    GtkWidget *b = gtk_button_new_with_label("Browse…");
    gtk_widget_set_tooltip_text(b, label);
    picker *p = g_new0(picker, 1);
    p->entry = GTK_ENTRY(e);
    p->kind = kind;
    g_object_set_data_full(G_OBJECT(b), "picker", p, g_free);
    g_signal_connect(b, "clicked", G_CALLBACK(on_browse), p);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(row), e);
    gtk_box_append(GTK_BOX(row), b);
    gtk_box_append(GTK_BOX(box), field_label(label, e));
    gtk_box_append(GTK_BOX(box), row);
    return GTK_ENTRY(e);
}

static GtkWidget *section(void) {
    GtkWidget *b = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    return b;
}

static void sync_visibility(Win *w) {
    AvmProfile p = (AvmProfile)gtk_drop_down_get_selected(w->profile);
    gtk_widget_set_visible(w->targetBox, p != AVM_PROFILE_CLIENT);
    gtk_widget_set_visible(w->serverBox, p == AVM_PROFILE_SERVER);
    gtk_widget_set_visible(w->gdsBox, p == AVM_PROFILE_GDS);
    gtk_widget_set_visible(w->clientBox, p == AVM_PROFILE_CLIENT);
    /* the client profile never writes to a target: it is the GDS */
    gtk_widget_set_visible(GTK_WIDGET(w->allowChanges), p != AVM_PROFILE_CLIENT);
}

static void on_profile(GObject *o, GParamSpec *ps, gpointer data) {
    (void)o;
    (void)ps;
    sync_visibility(data);
}

static void on_preset(GObject *o, GParamSpec *ps, gpointer data) {
    (void)o;
    (void)ps;
    Win *w = data;
    AvmPreset p = (AvmPreset)gtk_drop_down_get_selected(w->preset);
    avm_plan_apply_preset(&w->plan, p);
    gtk_check_button_set_active(w->allowChanges, w->plan.allowChanges);
    gtk_label_set_text(w->presetDesc, avm_preset_description(p));
}

/* Read the form into the plan. */
static void sync_plan(Win *w) {
    AvmPlan *p = &w->plan;
    p->profile = (AvmProfile)gtk_drop_down_get_selected(w->profile);
    p->preset = (AvmPreset)gtk_drop_down_get_selected(w->preset);
    p->allowChanges = gtk_check_button_get_active(w->allowChanges);
    p->tofu = gtk_check_button_get_active(w->tofu);
    p->listenPort = (guint)gtk_spin_button_get_value_as_int(w->port);
    const struct {
        char **field;
        GtkEntry *entry;
    } map[] = {{&p->url, w->url},
               {&p->user, w->user},
               {&p->passwordFile, w->passwordFile},
               {&p->serverCert, w->serverCert},
               {&p->trustFiles, w->trust},
               {&p->crlFile, w->crl},
               {&p->triggerCmd, w->trigger},
               {&p->clientUser, w->clientUser},
               {&p->workDir, w->work},
               {&p->adminCert, w->adminCert},
               {&p->adminKey, w->adminKey},
               {&p->adminUser, w->adminUser},
               {&p->adminPasswordFile, w->adminPasswordFile}};
    for(size_t i = 0; i < G_N_ELEMENTS(map); i++) {
        char *v = g_strstrip(g_strdup(entry_text(map[i].entry)));
        avm_plan_set(map[i].field, v);
        g_free(v);
    }
}

static GtkDropDown *drop_down(GtkWidget *box, const char *label, const char *const *items) {
    GtkWidget *d = gtk_drop_down_new_from_strings(items);
    gtk_box_append(GTK_BOX(box), field_label(label, d));
    gtk_box_append(GTK_BOX(box), d);
    return GTK_DROP_DOWN(d);
}

static void build_target_sections(Win *w, GtkWidget *form) {
    w->targetBox = section();
    w->url = add_entry(w->targetBox, "_Endpoint URL", "opc.tcp://host:4840");
    w->user = add_entry(w->targetBox, "_User (optional)",
                        "server: a user without SecurityAdmin");
    w->passwordFile = add_path(w->targetBox, "_Password file", "file holding the password",
                               PICK_FILE);
    gtk_box_append(GTK_BOX(form), w->targetBox);

    w->serverBox = section();
    w->serverCert = add_path(w->serverBox, "Target _certificate (DER)", "pinned certificate",
                             PICK_FILE);
    w->tofu = GTK_CHECK_BUTTON(
        gtk_check_button_new_with_mnemonic("_Trust on first use (test setups only)"));
    gtk_box_append(GTK_BOX(w->serverBox), GTK_WIDGET(w->tofu));
    w->adminCert = add_path(w->serverBox, "Admin certificate (optional)",
                            "default: the Auditor's own admin identity", PICK_FILE);
    w->adminKey = add_path(w->serverBox, "Admin key", "key of the admin certificate", PICK_FILE);
    w->adminUser = add_entry(w->serverBox, "Admin user (instead of a certificate)", NULL);
    w->adminPasswordFile = add_path(w->serverBox, "Admin password file", NULL, PICK_FILE);
    gtk_box_append(GTK_BOX(form), w->serverBox);

    w->gdsBox = section();
    w->trust = add_path(w->gdsBox, "Trusted _CA certificates", "ca.der; separate several with ;",
                        PICK_FILES);
    w->crl = add_path(w->gdsBox, "CA _revocation list (optional)", "ca.crl", PICK_FILE);
    gtk_box_append(GTK_BOX(form), w->gdsBox);

    w->clientBox = section();
    GtkWidget *port = gtk_spin_button_new_with_range(1, 65535, 1);
    w->port = GTK_SPIN_BUTTON(port);
    gtk_box_append(GTK_BOX(w->clientBox), field_label("Fake GDS _port", port));
    gtk_box_append(GTK_BOX(w->clientBox), port);
    w->trigger = add_entry(w->clientBox, "_Trigger command",
                           "runs one pull cycle of the client (no shell)");
    w->clientUser = add_entry(w->clientBox, "Registrar _user", "registrar");
    gtk_box_append(GTK_BOX(form), w->clientBox);
}

static void on_run(GtkButton *b, gpointer data);
static void on_abort(GtkButton *b, gpointer data);
static void on_export(GtkButton *b, gpointer data);
static void on_open(GtkButton *b, gpointer data);

static GtkWidget *build_form(Win *w) {
    GtkWidget *form = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_add_css_class(form, "form");
    const char *profiles[] = {avm_profile_label(AVM_PROFILE_SERVER),
                              avm_profile_label(AVM_PROFILE_CLIENT),
                              avm_profile_label(AVM_PROFILE_GDS), NULL};
    const char *presets[] = {avm_preset_label(AVM_PRESET_QUICK), avm_preset_label(AVM_PRESET_FULL),
                             avm_preset_label(AVM_PRESET_CERT), NULL};
    GtkWidget *top = section();
    w->profile = drop_down(top, "P_rofile", profiles);
    w->preset = drop_down(top, "Pre_set", presets);
    w->presetDesc = GTK_LABEL(gtk_label_new(NULL));
    gtk_label_set_wrap(w->presetDesc, TRUE);
    gtk_label_set_xalign(w->presetDesc, 0);
    gtk_widget_add_css_class(GTK_WIDGET(w->presetDesc), "dim-label");
    gtk_box_append(GTK_BOX(top), GTK_WIDGET(w->presetDesc));
    gtk_box_append(GTK_BOX(form), top);

    build_target_sections(w, form);

    GtkWidget *bottom = section();
    w->work = add_path(bottom, "_Work folder", "identity and test CA", PICK_FOLDER);
    w->allowChanges = GTK_CHECK_BUTTON(
        gtk_check_button_new_with_mnemonic("_Allow changes to the target"));
    gtk_box_append(GTK_BOX(bottom), GTK_WIDGET(w->allowChanges));
    gtk_box_append(GTK_BOX(form), bottom);

    g_signal_connect(w->profile, "notify::selected", G_CALLBACK(on_profile), w);
    g_signal_connect(w->preset, "notify::selected", G_CALLBACK(on_preset), w);

    GtkWidget *sc = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sc), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(sc), form);
    gtk_widget_set_size_request(sc, 340, -1);
    return sc;
}

static void load_plan_into_form(Win *w) {
    const AvmPlan *p = &w->plan;
    gtk_drop_down_set_selected(w->profile, (guint)p->profile);
    gtk_drop_down_set_selected(w->preset, (guint)p->preset);
    set_entry(w->url, p->url);
    set_entry(w->user, p->user);
    set_entry(w->passwordFile, p->passwordFile);
    set_entry(w->serverCert, p->serverCert);
    set_entry(w->trust, p->trustFiles);
    set_entry(w->crl, p->crlFile);
    set_entry(w->trigger, p->triggerCmd);
    set_entry(w->clientUser, p->clientUser);
    set_entry(w->work, p->workDir);
    set_entry(w->adminCert, p->adminCert);
    set_entry(w->adminKey, p->adminKey);
    set_entry(w->adminUser, p->adminUser);
    set_entry(w->adminPasswordFile, p->adminPasswordFile);
    gtk_spin_button_set_value(w->port, p->listenPort);
    gtk_check_button_set_active(w->tofu, p->tofu);
    gtk_check_button_set_active(w->allowChanges, p->allowChanges);
    gtk_label_set_text(w->presetDesc, avm_preset_description(p->preset));
    sync_visibility(w);
}

/* ---- results ---- */

static void set_status(Win *w, const char *text) {
    gtk_label_set_text(w->status, text);
}

static void set_running(Win *w, gboolean running) {
    gtk_widget_set_sensitive(w->runBtn, !running);
    gtk_widget_set_sensitive(w->abortBtn, running);
    gtk_widget_set_sensitive(w->exportBtn, !running && w->run != NULL);
    gtk_widget_set_sensitive(GTK_WIDGET(w->profile), !running);
}

static void set_verdict_label(GtkLabel *l, int v) {
    for(size_t i = 0; i < GA_VERDICT_COUNT; i++)
        gtk_widget_remove_css_class(GTK_WIDGET(l), verdictCss[i]);
    gtk_widget_remove_css_class(GTK_WIDGET(l), "verdict-running");
    if(v < 0) {
        gtk_label_set_text(l, "Running…");
        gtk_widget_add_css_class(GTK_WIDGET(l), "verdict-running");
        return;
    }
    gtk_label_set_text(l, ga_verdict_label((ga_verdict)v));
    gtk_widget_add_css_class(GTK_WIDGET(l), verdictCss[v]);
}

static GtkWidget *cell(const char *text, const char *css, gboolean expand) {
    GtkWidget *l = gtk_label_new(text ? text : "");
    gtk_label_set_xalign(GTK_LABEL(l), 0);
    gtk_label_set_wrap(GTK_LABEL(l), expand);
    gtk_widget_set_hexpand(l, expand);
    if(css)
        gtk_widget_add_css_class(l, css);
    return l;
}

static void add_row(Win *w, const ga_event *ev) {
    vrow *r = g_new0(vrow, 1);
    r->text = g_string_new(NULL);
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *line = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *verdict = cell(NULL, "verdict", FALSE);
    gtk_label_set_width_chars(GTK_LABEL(verdict), 13);
    r->verdict = GTK_LABEL(verdict);
    set_verdict_label(r->verdict, -1);
    gtk_box_append(GTK_BOX(line), verdict);
    gtk_box_append(GTK_BOX(line), cell(ev->id, "test-id", FALSE));
    char *title = g_strdup_printf("%s%s%s", ev->title ? ev->title : "",
                                  ev->needsWrite ? "  · changes the target" : "",
                                  ev->needsOperator ? "  · operator step" : "");
    gtk_box_append(GTK_BOX(line), cell(title, NULL, TRUE));
    g_free(title);
    gtk_box_append(GTK_BOX(line), cell(ev->clause, "clause", FALSE));
    gtk_box_append(GTK_BOX(outer), line);

    r->expander = GTK_EXPANDER(gtk_expander_new("Evidence"));
    r->details = GTK_LABEL(gtk_label_new(NULL));
    gtk_label_set_selectable(r->details, TRUE);
    gtk_label_set_wrap(r->details, TRUE);
    gtk_label_set_wrap_mode(r->details, PANGO_WRAP_WORD_CHAR);
    gtk_label_set_xalign(r->details, 0);
    gtk_widget_add_css_class(GTK_WIDGET(r->details), "evidence");
    gtk_expander_set_child(r->expander, GTK_WIDGET(r->details));
    gtk_widget_set_visible(GTK_WIDGET(r->expander), FALSE);
    gtk_box_append(GTK_BOX(outer), GTK_WIDGET(r->expander));

    r->row = gtk_list_box_row_new();
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(r->row), outer);
    gtk_list_box_append(w->list, r->row);
    while(w->rows->len + 1 < ev->n)
        g_ptr_array_add(w->rows, NULL);
    if(w->rows->len < ev->n)
        g_ptr_array_add(w->rows, r);
    else
        vrow_free(r);
}

static vrow *row_for(Win *w, size_t n) {
    return n >= 1 && n <= w->rows->len ? g_ptr_array_index(w->rows, n - 1) : NULL;
}

static void row_append_text(vrow *r, const char *text, gboolean first) {
    if(!text || !*text)
        return;
    if(first) { /* the verdict's evidence line goes above the notes */
        if(r->text->len)
            g_string_prepend(r->text, "\n");
        g_string_prepend(r->text, text);
    } else
        g_string_append_printf(r->text, "%s%s", r->text->len ? "\n" : "", text);
    gtk_label_set_text(r->details, r->text->str);
    gtk_widget_set_visible(GTK_WIDGET(r->expander), TRUE);
}

static void update_counts(Win *w) {
    const ga_results *res = avm_run_results(w->run);
    size_t done = 0;
    for(size_t i = 0; i < GA_VERDICT_COUNT; i++)
        done += res->counts[i];
    char *s = g_strdup_printf("%zu of %zu tests · Pass %zu · Fail %zu · Warn %zu · "
                              "Not supported %zu · Not tested %zu",
                              done, res->planned, res->counts[GA_PASS], res->counts[GA_FAIL],
                              res->counts[GA_WARN], res->counts[GA_NOT_SUPPORTED],
                              res->counts[GA_NOT_TESTED]);
    set_status(w, s);
    g_free(s);
    if(res->planned)
        gtk_progress_bar_set_fraction(w->progress, (double)done / (double)res->planned);
}

static void on_run_event(AvmRun *run, const ga_event *ev, void *user) {
    (void)run;
    Win *w = user;
    vrow *r;
    switch(ev->kind) {
    case GA_EV_RUN_STARTED:
        update_counts(w);
        break;
    case GA_EV_TEST_STARTED:
        add_row(w, ev);
        break;
    case GA_EV_NOTE:
        if((r = row_for(w, ev->n)))
            row_append_text(r, ev->text, FALSE);
        break;
    case GA_EV_VERDICT:
        if((r = row_for(w, ev->n))) {
            set_verdict_label(r->verdict, (int)ev->verdict);
            row_append_text(r, ev->text, TRUE);
            if(ev->verdict == GA_FAIL)
                gtk_expander_set_expanded(r->expander, TRUE);
        }
        update_counts(w);
        break;
    case GA_EV_RUN_FINISHED:
        break;
    }
}

static void on_run_log(AvmRun *run, const char *line, void *user) {
    (void)run;
    Win *w = user;
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(w->log, &end);
    gtk_text_buffer_insert(w->log, &end, line, -1);
    gtk_text_buffer_insert(w->log, &end, "\n", 1);
}

static char *report_path(const Win *w) {
    return g_build_filename(avm_run_dir(w->run), "report", "report.html", NULL);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): GLib string macros add branches
static char *outcome_text(const Win *w, int exitCode, const char *error) {
    const ga_results *res = avm_run_results(w->run);
    if(!res->profile)
        return g_strdup_printf("The run could not be done (exit %d%s%s). See the log below.",
                               exitCode, error ? ": " : "", error ? error : "");
    GString *s = g_string_new(ga_results_outcome(res));
    g_string_append_printf(s, " · Pass %zu · Fail %zu · Warn %zu · Not supported %zu · "
                              "Not tested %zu",
                           res->counts[GA_PASS], res->counts[GA_FAIL], res->counts[GA_WARN],
                           res->counts[GA_NOT_SUPPORTED], res->counts[GA_NOT_TESTED]);
    gboolean gaps = w->plan.preset == AVM_PRESET_CERT && res->counts[GA_NOT_TESTED];
    if(gaps)
        g_string_append(s, ". Preparation for certification needs every test to run: "
                           "set the hooks or allow changes for the Not tested ones.");
    if(error)
        g_string_append_printf(s, ". %s", error);
    g_string_append(s, ". Self-test, not OPC Foundation certification.");
    return g_string_free(s, FALSE);
}

static void on_run_finished(AvmRun *run, int exitCode, const char *error, void *user) {
    (void)run;
    Win *w = user;
    char *text = outcome_text(w, exitCode, error);
    set_status(w, text);
    g_free(text);
    gtk_progress_bar_set_fraction(w->progress, 1.0);
    set_running(w, FALSE);
    char *rp = report_path(w);
    gtk_widget_set_sensitive(w->openBtn, g_file_test(rp, G_FILE_TEST_EXISTS));
    g_free(rp);
    if(!avm_run_results(w->run)->profile)
        gtk_expander_set_expanded(w->logExpander, TRUE);
    gtk_widget_set_visible(GTK_WIDGET(w->banner), FALSE);
    if(w->closeWhenDone)
        gtk_window_destroy(w->win);
}

static void clear_results(Win *w) {
    GtkWidget *child;
    while((child = gtk_widget_get_first_child(GTK_WIDGET(w->list))))
        gtk_list_box_remove(w->list, child);
    g_ptr_array_set_size(w->rows, 0);
    gtk_text_buffer_set_text(w->log, "", 0);
    gtk_progress_bar_set_fraction(w->progress, 0);
}

static void start_run(Win *w) {
    char *engine = avm_engine_path();
    char *dir = avm_new_run_dir(avm_profile_name(w->plan.profile));
    char *reportDir = g_build_filename(dir, "report", NULL);
    GError *e = NULL;
    char **argv = avm_plan_argv(&w->plan, engine, AVM_EVENTS_FD, reportDir, &e);
    AvmRun *run = NULL;
    if(argv) {
        AvmRunCallbacks cb = {on_run_event, on_run_log, on_run_finished};
        run = avm_run_start(argv, dir, &cb, w, &e);
    }
    if(run) {
        avm_run_free(w->run);
        w->run = run;
        clear_results(w);
        gboolean writes = w->plan.allowChanges && w->plan.profile != AVM_PROFILE_CLIENT;
        if(writes) {
            char *b = g_strdup_printf("Changes to %s are allowed in this run. The target's trust "
                                      "list and certificates are saved first and restored at "
                                      "the end.",
                                      w->plan.url);
            gtk_label_set_text(w->banner, b);
            g_free(b);
        }
        gtk_widget_set_visible(GTK_WIDGET(w->banner), writes);
        gtk_widget_set_sensitive(w->openBtn, FALSE);
        set_status(w, "Starting the engine…");
        set_running(w, TRUE);
    } else {
        char *m = g_strdup_printf("Cannot start %s: %s", engine, e ? e->message : "unknown error");
        set_status(w, m);
        g_free(m);
    }
    g_clear_error(&e);
    g_strfreev(argv);
    g_free(reportDir);
    g_free(dir);
    g_free(engine);
}

static void on_allowed(gboolean allowed, gpointer user) {
    Win *w = user;
    if(allowed)
        start_run(w);
    else
        set_status(w, "Not started: changes were not allowed. Clear “Allow changes” for a "
                      "read-only run.");
}

static void on_run(GtkButton *b, gpointer data) {
    (void)b;
    Win *w = data;
    if(avm_run_is_running(w->run))
        return;
    sync_plan(w);
    char *problem = avm_plan_check(&w->plan);
    if(problem) {
        set_status(w, problem);
        g_free(problem);
        return;
    }
    if(w->plan.allowChanges && w->plan.profile != AVM_PROFILE_CLIENT) {
        char *thumb = avm_plan_thumbprint(&w->plan);
        dlg_allow_changes_run(w->win, w->plan.url, thumb, w->plan.tofu, on_allowed, w);
        g_free(thumb);
        return;
    }
    start_run(w);
}

static void on_abort(GtkButton *b, gpointer data) {
    (void)b;
    Win *w = data;
    if(!avm_run_is_running(w->run))
        return;
    avm_run_abort(w->run);
    gtk_widget_set_sensitive(w->abortBtn, FALSE);
    set_status(w, "Aborting: the test in progress finishes, then the target is restored…");
}

static void on_export_folder(GObject *src, GAsyncResult *res, gpointer data) {
    Win *w = data;
    GError *e = NULL;
    GFile *f = gtk_file_dialog_select_folder_finish(GTK_FILE_DIALOG(src), res, &e);
    if(!f) {
        g_clear_error(&e);
        return;
    }
    char *dir = g_file_get_path(f);
    g_object_unref(f);
    if(dir && w->run && avm_run_export(w->run, dir, &e)) {
        char *m = g_strdup_printf("Exported report.html, junit.xml and events.jsonl to %s", dir);
        set_status(w, m);
        g_free(m);
    } else {
        char *m = g_strdup_printf("Export failed: %s", e ? e->message : "no folder");
        set_status(w, m);
        g_free(m);
    }
    g_clear_error(&e);
    g_free(dir);
}

static void on_export(GtkButton *b, gpointer data) {
    (void)b;
    Win *w = data;
    if(!w->run || avm_run_is_running(w->run))
        return;
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_title(d, "Export the report to a folder");
    gtk_file_dialog_set_modal(d, TRUE);
    gtk_file_dialog_select_folder(d, w->win, NULL, on_export_folder, w);
    g_object_unref(d);
}

static void on_launched(GObject *src, GAsyncResult *res, gpointer data) {
    GError *e = NULL;
    if(!gtk_file_launcher_launch_finish(GTK_FILE_LAUNCHER(src), res, &e)) {
        char *m = g_strdup_printf("Cannot open the report: %s", e ? e->message : "");
        set_status(data, m);
        g_free(m);
    }
    g_clear_error(&e);
}

static void on_open(GtkButton *b, gpointer data) {
    (void)b;
    Win *w = data;
    if(!w->run)
        return;
    char *rp = report_path(w);
    GFile *f = g_file_new_for_path(rp);
    GtkFileLauncher *l = gtk_file_launcher_new(f);
    gtk_file_launcher_launch(l, w->win, NULL, on_launched, w);
    g_object_unref(l);
    g_object_unref(f);
    g_free(rp);
}

static gboolean on_close(GtkWindow *win, gpointer data) {
    (void)win;
    Win *w = data;
    if(!avm_run_is_running(w->run))
        return FALSE;
    /* never leave a target changed: abort, restore, then close */
    w->closeWhenDone = TRUE;
    on_abort(NULL, w);
    return TRUE;
}

static GtkWidget *button(const char *label, const char *tooltip, GCallback cb, Win *w) {
    GtkWidget *b = gtk_button_new_with_mnemonic(label);
    gtk_widget_set_tooltip_text(b, tooltip);
    g_signal_connect(b, "clicked", cb, w);
    return b;
}

static GtkWidget *build_results(Win *w) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_add_css_class(box, "results");
    w->banner = GTK_LABEL(gtk_label_new(NULL));
    gtk_label_set_wrap(w->banner, TRUE);
    gtk_label_set_xalign(w->banner, 0);
    gtk_widget_add_css_class(GTK_WIDGET(w->banner), "changes-banner");
    gtk_widget_set_visible(GTK_WIDGET(w->banner), FALSE);
    gtk_box_append(GTK_BOX(box), GTK_WIDGET(w->banner));

    w->status = GTK_LABEL(gtk_label_new("Choose a profile and a preset, then Run. "
                                        "Read-only is the default."));
    gtk_label_set_wrap(w->status, TRUE);
    gtk_label_set_xalign(w->status, 0);
    gtk_label_set_selectable(w->status, TRUE);
    gtk_box_append(GTK_BOX(box), GTK_WIDGET(w->status));
    w->progress = GTK_PROGRESS_BAR(gtk_progress_bar_new());
    gtk_box_append(GTK_BOX(box), GTK_WIDGET(w->progress));

    w->list = GTK_LIST_BOX(gtk_list_box_new());
    gtk_list_box_set_selection_mode(w->list, GTK_SELECTION_NONE);
    gtk_widget_add_css_class(GTK_WIDGET(w->list), "verdicts");
    GtkWidget *placeholder = gtk_label_new("No run yet.");
    gtk_widget_add_css_class(placeholder, "dim-label");
    gtk_list_box_set_placeholder(w->list, placeholder);
    GtkWidget *sc = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(sc), GTK_WIDGET(w->list));
    gtk_widget_set_vexpand(sc, TRUE);
    gtk_box_append(GTK_BOX(box), sc);

    GtkWidget *view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
    w->log = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    GtkWidget *logSc = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(logSc), view);
    gtk_widget_set_size_request(logSc, -1, 160);
    w->logExpander = GTK_EXPANDER(gtk_expander_new_with_mnemonic("Engine _log (TAP)"));
    gtk_expander_set_child(w->logExpander, logSc);
    gtk_box_append(GTK_BOX(box), GTK_WIDGET(w->logExpander));
    return box;
}

static void load_css(void) {
    static gboolean done;
    if(done)
        return;
    done = TRUE;
    GtkCssProvider *css = gtk_css_provider_new();
    gtk_css_provider_load_from_string(
        css, ".form, .results { padding: 12px; }\n"
             ".field-label { font-weight: bold; margin-top: 6px; }\n"
             ".verdict { font-weight: bold; }\n"
             ".verdict-pass { color: #26a269; }\n"
             ".verdict-fail { color: #c01c28; }\n"
             ".verdict-warn { color: #c64600; }\n"
             ".verdict-ns, .verdict-nt, .verdict-running { color: alpha(currentColor, 0.65); }\n"
             ".test-id { font-family: monospace; }\n"
             ".clause { opacity: 0.75; }\n"
             ".evidence { font-family: monospace; font-size: smaller; }\n"
             ".changes-banner { background: alpha(#e5a50a, 0.25); padding: 8px; "
             "border-radius: 6px; }\n"
             ".verdicts row { padding: 4px 6px; }\n");
    gtk_style_context_add_provider_for_display(gdk_display_get_default(), GTK_STYLE_PROVIDER(css),
                                               GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(css);
}

GtkWindow *win_main_new(GtkApplication *app) {
    load_css();
    Win *w = g_new0(Win, 1);
    w->rows = g_ptr_array_new_with_free_func(vrow_free);
    avm_plan_init(&w->plan);
    w->win = GTK_WINDOW(gtk_application_window_new(app));
    gtk_window_set_title(w->win, "OpenGDS Auditor");
    gtk_window_set_default_size(w->win, 1100, 720);
    g_object_set_data_full(G_OBJECT(w->win), "gdsaudit-win", w, win_free);

    GtkWidget *header = gtk_header_bar_new();
    w->runBtn = button("_Run", "Run the chosen profile and preset", G_CALLBACK(on_run), w);
    gtk_widget_add_css_class(w->runBtn, "suggested-action");
    w->abortBtn = button("A_bort", "Stop after the current test and restore the target",
                         G_CALLBACK(on_abort), w);
    w->openBtn = button("_Open report", "Open this run's HTML report", G_CALLBACK(on_open), w);
    w->exportBtn = button("_Export…", "Write report.html, junit.xml and events.jsonl to a folder",
                          G_CALLBACK(on_export), w);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), w->runBtn);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), w->abortBtn);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), w->exportBtn);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), w->openBtn);
    gtk_window_set_titlebar(w->win, header);

    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_paned_set_start_child(GTK_PANED(paned), build_form(w));
    gtk_paned_set_end_child(GTK_PANED(paned), build_results(w));
    gtk_paned_set_resize_start_child(GTK_PANED(paned), FALSE);
    gtk_paned_set_shrink_start_child(GTK_PANED(paned), FALSE);
    gtk_window_set_child(w->win, paned);

    load_plan_into_form(w);
    set_running(w, FALSE);
    gtk_widget_set_sensitive(w->openBtn, FALSE);
    g_signal_connect(w->win, "close-request", G_CALLBACK(on_close), w);
    return w->win;
}

gboolean win_main_check(GtkWindow *win) {
    Win *w = g_object_get_data(G_OBJECT(win), "gdsaudit-win");
    return w && w->runBtn && w->list && w->profile && w->preset &&
           gtk_drop_down_get_selected(w->preset) == AVM_PRESET_QUICK &&
           !gtk_check_button_get_active(w->allowChanges);
}
