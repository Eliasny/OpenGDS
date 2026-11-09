/* OpenGDS Auditor view-model - the form as a plan file (avm_plan.h, plan
 * files): one mapping between the form's fields and the plan's keys, used
 * for saving and opening plans and for the command line of every UI run.
 * SPDX-License-Identifier: MPL-2.0 */
#include "avm_plan.h"

#include <gio/gio.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "common/banned.h"

static gboolean set(const char *s) {
    return s && *s;
}

/* The keys the form has a field for, by profile; the UI's own per-run
 * keys (report folder, events, operator answers) are never taken. */
typedef enum { K_EXTRA, K_FORM, K_RUN } key_use;

static key_use use_of(AvmProfile pr, const char *key) {
    static const char *const run[] = {"report.dir", "report.events", "hooks.prompts"};
    static const struct {
        const char *key;
        unsigned profiles; /* bit per AvmProfile */
    } form[] = {
        {"identity.work", 7},          {"target.url", 5},
        {"tests.allow_changes", 5},    {"identity.user", 5},
        {"identity.password_file", 5}, {"target.server_cert", 1},
        {"target.tofu", 1},            {"identity.admin_cert", 1},
        {"identity.admin_key", 1},     {"identity.admin_user", 1},
        {"identity.admin_password_file", 1}, {"tests.slow", 1},
        {"hooks.restart_cmd", 1},      {"target.trust", 4},
        {"target.crl", 4},             {"target.listen", 2},
        {"identity.client_user", 2},   {"hooks.trigger", 2},
    };
    for(size_t i = 0; i < G_N_ELEMENTS(run); i++)
        if(!strcmp(key, run[i]))
            return K_RUN;
    for(size_t i = 0; i < G_N_ELEMENTS(form); i++)
        if(!strcmp(key, form[i].key))
            return (form[i].profiles >> pr) & 1u ? K_FORM : K_EXTRA;
    return K_EXTRA;
}

void avm_plan_extra_set(AvmPlan *p, const char *key, char **values) {
    for(guint i = 0; i < p->extra->len; i++) {
        AvmPlanExtra *x = g_ptr_array_index(p->extra, i);
        if(!strcmp(x->key, key)) {
            g_strfreev(x->values);
            x->values = values;
            return;
        }
    }
    AvmPlanExtra *x = g_new0(AvmPlanExtra, 1);
    x->key = g_strdup(key);
    x->values = values;
    g_ptr_array_add(p->extra, x);
}

/* A path as the plan keeps it: absolute (from the current folder). */
static char *abs_path(const char *v) {
    return g_canonicalize_filename(v, NULL);
}

static gboolean is_path(const ga_plan *g, const char *key, guint i, const char *v) {
    ga_plan_type t = GA_PLAN_STRING;
    if(!ga_plan_key_type(ga_plan_profile(g), key, &t))
        return FALSE;
    return t == GA_PLAN_PATH || t == GA_PLAN_PATHS ||
           (t == GA_PLAN_COMMAND && i == 0 && strchr(v, '/'));
}

static gboolean put_value(ga_plan *g, const char *key, guint i, const char *v, GError **error) {
    char *a = is_path(g, key, i, v) ? abs_path(v) : g_strdup(v);
    gboolean ok = i == 0 ? ga_plan_set(g, key, a) : ga_plan_add(g, key, a);
    if(!ok)
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                    "The plan does not take \"%s\" for %s.", a, key);
    g_free(a);
    return ok;
}

/* put: one value, if set */
static gboolean put(ga_plan *g, const char *key, const char *v, GError **error) {
    return !set(v) || put_value(g, key, 0, v, error);
}

static gboolean put_list(ga_plan *g, const char *key, char **v, GError **error) {
    guint n = 0;
    for(char **s = v; s && *s; s++) {
        char *t = g_strstrip(g_strdup(*s));
        gboolean ok = !*t || put_value(g, key, n++, t, error);
        g_free(t);
        if(!ok)
            return FALSE;
    }
    return TRUE;
}

static gboolean put_server(ga_plan *g, const AvmPlan *p, GError **error) {
    gboolean ok = TRUE;
    if(p->tofu)
        ok = ga_plan_set(g, "target.tofu", "true");
    else
        ok = put(g, "target.server_cert", p->serverCert, error);
    if(ok && set(p->adminCert))
        ok = put(g, "identity.admin_cert", p->adminCert, error) &&
             put(g, "identity.admin_key", p->adminKey, error);
    else if(ok && set(p->adminUser))
        ok = put(g, "identity.admin_user", p->adminUser, error) &&
             put(g, "identity.admin_password_file", p->adminPasswordFile, error);
    if(ok && p->slow)
        ok = ga_plan_set(g, "tests.slow", "true");
    return ok && put(g, "hooks.restart_cmd", p->restartCmd, error);
}

static gboolean put_gds(ga_plan *g, const AvmPlan *p, GError **error) {
    char **trust = g_strsplit(p->trustFiles ? p->trustFiles : "", ";", -1);
    gboolean ok = put_list(g, "target.trust", trust, error);
    g_strfreev(trust);
    return ok && put(g, "target.crl", p->crlFile, error);
}

static gboolean put_client(ga_plan *g, const AvmPlan *p, GError **error) {
    char port[16];
    g_snprintf(port, sizeof(port), "%u", p->listenPort);
    gboolean ok = ga_plan_set(g, "target.listen", port) &&
                  put(g, "identity.client_user", p->clientUser, error);
    if(ok && set(p->triggerCmd)) {
        char **argv = NULL;
        ok = g_shell_parse_argv(p->triggerCmd, NULL, &argv, error) &&
             put_list(g, "hooks.trigger", argv, error);
        g_strfreev(argv);
    }
    return ok;
}

static const char *const presetNames[AVM_PRESET_COUNT] = {"quick", "full", "certification"};

static gboolean put_form(ga_plan *g, const AvmPlan *p, GError **error) {
    if(!ga_plan_set_preset(g, presetNames[p->preset]) ||
       (set(p->name) && !ga_plan_set_name(g, p->name)))
        return FALSE;
    if(!put(g, "identity.work", p->workDir, error))
        return FALSE;
    if(p->profile == AVM_PROFILE_CLIENT)
        return put_client(g, p, error);
    if(!put(g, "target.url", p->url, error) ||
       (p->allowChanges && !ga_plan_set(g, "tests.allow_changes", "true")))
        return FALSE;
    if(set(p->user) && !(put(g, "identity.user", p->user, error) &&
                         put(g, "identity.password_file", p->passwordFile, error)))
        return FALSE;
    return p->profile == AVM_PROFILE_SERVER ? put_server(g, p, error) : put_gds(g, p, error);
}

ga_plan *avm_plan_to_ga(const AvmPlan *p, GError **error) {
    ga_plan *g = ga_plan_new(avm_profile_name(p->profile));
    gboolean ok = g && put_form(g, p, error);
    for(guint i = 0; ok && p->extra && i < p->extra->len; i++) {
        const AvmPlanExtra *x = g_ptr_array_index(p->extra, i);
        if(use_of(p->profile, x->key) != K_EXTRA ||
           !ga_plan_key_type(avm_profile_name(p->profile), x->key, NULL))
            continue; /* another profile's key, after a change of profile */
        for(guint j = 0; ok && x->values[j]; j++)
            ok = put_value(g, x->key, j, x->values[j], error);
    }
    if(!ok) {
        if(error && !*error)
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                        "The form cannot be written as a plan.");
        ga_plan_free(g);
        return NULL;
    }
    return g;
}

/* ---- plan -> form ---- */

static char *get(const ga_plan *g, const char *key, const char *baseDir) {
    const char *v = ga_plan_get(g, key, 0);
    if(!v)
        return g_strdup("");
    return is_path(g, key, 0, v) ? g_canonicalize_filename(v, baseDir) : g_strdup(v);
}

static gboolean get_bool(const ga_plan *g, const char *key) {
    return g_strcmp0(ga_plan_get(g, key, 0), "true") == 0;
}

static void take(char **field, char *value) {
    g_free(*field);
    *field = value;
}

static char **values_of(const ga_plan *g, const char *key, const char *baseDir) {
    size_t n = ga_plan_count(g, key);
    char **v = g_new0(char *, n + 1);
    for(size_t i = 0; i < n; i++) {
        const char *s = ga_plan_get(g, key, i);
        v[i] = is_path(g, key, (guint)i, s) ? g_canonicalize_filename(s, baseDir) : g_strdup(s);
    }
    return v;
}

/* One word of the trigger in shell syntax: quoted only when it has to be. */
static char *shell_word(const char *w) {
    gboolean plain = *w != '\0';
    for(const char *c = w; *c && plain; c++)
        plain = g_ascii_isalnum(*c) || strchr("_./:=+,@%-", *c);
    return plain ? g_strdup(w) : g_shell_quote(w);
}

static void from_client(AvmPlan *p, const ga_plan *g, const char *baseDir) {
    guint64 port = 0;
    const char *l = ga_plan_get(g, "target.listen", 0);
    if(l && g_ascii_string_to_unsigned(l, 10, 1, 65535, &port, NULL))
        p->listenPort = (guint)port;
    if(ga_plan_get(g, "identity.client_user", 0))
        take(&p->clientUser, get(g, "identity.client_user", baseDir));
    char **trigger = values_of(g, "hooks.trigger", baseDir);
    GString *s = g_string_new(NULL);
    for(char **t = trigger; *t; t++) {
        char *q = shell_word(*t);
        g_string_append_printf(s, "%s%s", s->len ? " " : "", q);
        g_free(q);
    }
    g_strfreev(trigger);
    take(&p->triggerCmd, g_string_free(s, FALSE));
}

static void from_server(AvmPlan *p, const ga_plan *g, const char *baseDir) {
    p->tofu = get_bool(g, "target.tofu");
    take(&p->serverCert, get(g, "target.server_cert", baseDir));
    take(&p->adminCert, get(g, "identity.admin_cert", baseDir));
    take(&p->adminKey, get(g, "identity.admin_key", baseDir));
    take(&p->adminUser, get(g, "identity.admin_user", baseDir));
    take(&p->adminPasswordFile, get(g, "identity.admin_password_file", baseDir));
    take(&p->restartCmd, get(g, "hooks.restart_cmd", baseDir));
    p->slow = get_bool(g, "tests.slow");
}

static void from_gds(AvmPlan *p, const ga_plan *g, const char *baseDir) {
    GString *trust = g_string_new(NULL);
    for(size_t i = 0; i < ga_plan_count(g, "target.trust"); i++) {
        char *v = g_canonicalize_filename(ga_plan_get(g, "target.trust", i), baseDir);
        g_string_append_printf(trust, "%s%s", trust->len ? ";" : "", v);
        g_free(v);
    }
    take(&p->trustFiles, g_string_free(trust, FALSE));
    take(&p->crlFile, get(g, "target.crl", baseDir));
}

static void from_extra(AvmPlan *p, const ga_plan *g, const char *baseDir) {
    for(size_t i = 0; i < ga_plan_key_count(); i++) {
        const char *key = ga_plan_key_at(i);
        if(ga_plan_count(g, key) > 0 && use_of(p->profile, key) == K_EXTRA)
            avm_plan_extra_set(p, key, values_of(g, key, baseDir));
    }
}

gboolean avm_plan_from_ga(AvmPlan *p, const ga_plan *g, const char *baseDir, GError **error) {
    const char *profile = ga_plan_profile(g);
    int pr = -1;
    for(int i = 0; i < 3; i++)
        if(!g_strcmp0(profile, avm_profile_name((AvmProfile)i)))
            pr = i;
    if(pr < 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Unknown profile %s",
                    profile ? profile : "(none)");
        return FALSE;
    }
    /* gds takes one CRL in the form: more stay as they are, in extra */
    gboolean crls = pr == AVM_PROFILE_GDS && ga_plan_count(g, "target.crl") > 1;
    avm_plan_clear(p);
    avm_plan_init(p);
    p->profile = (AvmProfile)pr;
    const char *preset = ga_plan_preset(g);
    AvmPreset ps = get_bool(g, "tests.allow_changes") ? AVM_PRESET_FULL : AVM_PRESET_QUICK;
    for(int i = 0; preset && i < AVM_PRESET_COUNT; i++)
        if(!strcmp(preset, presetNames[i]))
            ps = (AvmPreset)i;
    avm_plan_apply_preset(p, ps);
    p->allowChanges = get_bool(g, "tests.allow_changes"); /* the plan's own choice */
    avm_plan_set(&p->name, ga_plan_name(g));
    take(&p->workDir, get(g, "identity.work", baseDir));
    take(&p->url, get(g, "target.url", baseDir));
    take(&p->user, get(g, "identity.user", baseDir));
    take(&p->passwordFile, get(g, "identity.password_file", baseDir));
    if(pr == AVM_PROFILE_SERVER)
        from_server(p, g, baseDir);
    else if(pr == AVM_PROFILE_CLIENT)
        from_client(p, g, baseDir);
    else
        from_gds(p, g, baseDir);
    from_extra(p, g, baseDir);
    if(crls) {
        avm_plan_set(&p->crlFile, "");
        avm_plan_extra_set(p, "target.crl", values_of(g, "target.crl", baseDir));
    }
    return TRUE;
}

char *avm_plan_extra_text(const AvmPlan *p) {
    GString *s = g_string_new(NULL);
    for(guint i = 0; p->extra && i < p->extra->len; i++) {
        const AvmPlanExtra *x = g_ptr_array_index(p->extra, i);
        if(!ga_plan_key_type(avm_profile_name(p->profile), x->key, NULL))
            continue;
        char *v = g_strjoinv(", ", x->values);
        g_string_append_printf(s, "%s%s = %s", s->len ? "; " : "", x->key, v);
        g_free(v);
    }
    return s->len ? g_string_free(s, FALSE) : (g_string_free(s, TRUE), NULL);
}

/* ---- files ---- */

gboolean avm_plan_save_file(const AvmPlan *p, const char *path, GError **error) {
    ga_plan *g = avm_plan_to_ga(p, error);
    if(!g)
        return FALSE;
    char *dir = g_path_get_dirname(path);
    char err[512] = "";
    gboolean ok = g_mkdir_with_parents(dir, 0700) == 0;
    if(!ok)
        g_set_error(error, G_FILE_ERROR, (gint)g_file_error_from_errno(errno), "cannot create %s",
                    dir);
    else if(!(ok = ga_plan_save(g, path, err, sizeof(err))))
        g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_FAILED, "%s", err);
    g_free(dir);
    ga_plan_free(g);
    return ok;
}

gboolean avm_plan_load_file(AvmPlan *p, const char *path, GError **error) {
    char err[512] = "";
    ga_plan *g = ga_plan_load(path, err, sizeof(err));
    if(!g) {
        g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_FAILED, "%s", err);
        return FALSE;
    }
    char *abs = g_canonicalize_filename(path, NULL);
    char *dir = g_path_get_dirname(abs);
    gboolean ok = avm_plan_from_ga(p, g, dir, error);
    g_free(dir);
    g_free(abs);
    ga_plan_free(g);
    return ok;
}

/* ---- the run's command line ---- */

char **avm_plan_argv(const AvmPlan *p, const char *engine, const char *events,
                     const char *reportDir, GError **error) {
    ga_plan *g = avm_plan_to_ga(p, error);
    if(!g)
        return NULL;
    int n = 0;
    char **plan = ga_plan_argv(g, NULL, &n);
    ga_plan_free(g);
    if(!plan) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "out of memory");
        return NULL;
    }
    GPtrArray *a = g_ptr_array_new();
    g_ptr_array_add(a, g_strdup(engine));
    g_ptr_array_add(a, g_strdup(plan[0])); /* the profile */
    if(set(events)) {
        g_ptr_array_add(a, g_strdup("--events"));
        g_ptr_array_add(a, g_strdup(events));
    }
    if(set(reportDir)) {
        g_ptr_array_add(a, g_strdup("--report"));
        g_ptr_array_add(a, g_strdup(reportDir));
    }
    for(int i = 1; i < n; i++)
        g_ptr_array_add(a, g_strdup(plan[i]));
    free((void *)plan);
    g_ptr_array_add(a, NULL);
    return (char **)g_ptr_array_free(a, FALSE);
}
