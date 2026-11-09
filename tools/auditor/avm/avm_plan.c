/* OpenGDS Auditor view-model - plan, presets and the headless command line.
 * SPDX-License-Identifier: MPL-2.0 */
#include "avm_plan.h"

#include <string.h>

#include "common/banned.h"

#define AVM_MAX_CERT ((gsize)64 * 1024)

static const char *const profileNames[] = {"server", "client", "gds"};
static const char *const profileLabels[] = {"Server (push-managed)", "Client (pulls from a GDS)",
                                            "GDS"};
static const char *const presetLabels[AVM_PRESET_COUNT] = {
    "Quick read-only check", "Full run", "Preparation for certification"};
static const char *const presetDescriptions[AVM_PRESET_COUNT] = {
    "Runs every test that only reads. Nothing is written to the target; tests that would "
    "change it are Not tested.",
    "Runs every test, including those that change the target. The Auditor saves the target's "
    "trust list and certificates first and restores them at the end.",
    "Runs every test with changes allowed, and needs the hooks for operator steps, so a run "
    "with any Not tested result is marked Incomplete. Self-test, not OPC Foundation "
    "certification."};

const char *avm_profile_name(AvmProfile p) {
    return (size_t)p < G_N_ELEMENTS(profileNames) ? profileNames[p] : "server";
}

const char *avm_profile_label(AvmProfile p) {
    return (size_t)p < G_N_ELEMENTS(profileLabels) ? profileLabels[p] : "";
}

const char *avm_preset_label(AvmPreset p) {
    return (size_t)p < AVM_PRESET_COUNT ? presetLabels[p] : "";
}

const char *avm_preset_description(AvmPreset p) {
    return (size_t)p < AVM_PRESET_COUNT ? presetDescriptions[p] : "";
}

void avm_plan_extra_free(gpointer x) {
    AvmPlanExtra *e = x;
    g_free(e->key);
    g_strfreev(e->values);
    g_free(e);
}

void avm_plan_set(char **field, const char *value) {
    char *c = g_strdup(value ? value : "");
    g_free(*field);
    *field = c;
}

void avm_plan_init(AvmPlan *p) {
    memset(p, 0, sizeof(*p));
    p->profile = AVM_PROFILE_SERVER;
    char *work = g_build_filename(g_get_user_data_dir(), "gdsaudit", "work", NULL);
    avm_plan_set(&p->workDir, work);
    g_free(work);
    avm_plan_set(&p->url, "opc.tcp://localhost:4840");
    avm_plan_set(&p->user, "");
    avm_plan_set(&p->passwordFile, "");
    avm_plan_set(&p->serverCert, "");
    avm_plan_set(&p->adminCert, "");
    avm_plan_set(&p->adminKey, "");
    avm_plan_set(&p->adminUser, "");
    avm_plan_set(&p->adminPasswordFile, "");
    avm_plan_set(&p->trustFiles, "");
    avm_plan_set(&p->crlFile, "");
    p->listenPort = 4850;
    avm_plan_set(&p->triggerCmd, "");
    avm_plan_set(&p->clientUser, "registrar");
    avm_plan_set(&p->restartCmd, "");
    avm_plan_set(&p->name, "");
    p->extra = g_ptr_array_new_with_free_func(avm_plan_extra_free);
    avm_plan_apply_preset(p, AVM_PRESET_QUICK);
}

void avm_plan_clear(AvmPlan *p) {
    char **fields[] = {&p->workDir,    &p->url,        &p->user,    &p->passwordFile,
                       &p->serverCert, &p->trustFiles, &p->crlFile, &p->triggerCmd,
                       &p->clientUser, &p->adminCert, &p->adminKey, &p->adminUser,
                       &p->adminPasswordFile, &p->restartCmd, &p->name};
    for(size_t i = 0; i < G_N_ELEMENTS(fields); i++)
        g_clear_pointer(fields[i], g_free);
    g_clear_pointer(&p->extra, g_ptr_array_unref);
}

void avm_plan_apply_preset(AvmPlan *p, AvmPreset preset) {
    p->preset = preset;
    p->allowChanges = preset != AVM_PRESET_QUICK;
    p->slow = preset != AVM_PRESET_QUICK; /* a full run is every test */
}

static gboolean set(const char *s) {
    return s && *s;
}

static char *check_server(const AvmPlan *p) {
    if(!set(p->serverCert) && !p->tofu)
        return g_strdup("Choose the target's certificate, or allow trust on first use "
                        "(test setups only).");
    if(set(p->serverCert) && p->tofu)
        return g_strdup("Choose either a pinned certificate or trust on first use, not both.");
    if(set(p->adminCert) != set(p->adminKey))
        return g_strdup("An admin certificate needs its key, and a key its certificate.");
    if(set(p->adminUser) && !set(p->adminPasswordFile))
        return g_strdup("An admin user needs a password file.");
    if(set(p->adminUser) && set(p->adminCert))
        return g_strdup("Choose either an admin certificate or an admin user, not both.");
    if(p->preset == AVM_PRESET_CERT && !set(p->restartCmd))
        return g_strdup("Preparation for certification needs the restart command, so the "
                        "persistence tests can run.");
    return NULL;
}

static char *check_target(const AvmPlan *p) {
    if(!set(p->url) || !g_str_has_prefix(p->url, "opc.tcp://"))
        return g_strdup("Enter the target's endpoint URL (opc.tcp://host:port).");
    if(set(p->user) && !set(p->passwordFile))
        return g_strdup("A user name needs a password file.");
    if(p->profile == AVM_PROFILE_SERVER)
        return check_server(p);
    if(p->profile == AVM_PROFILE_GDS && !set(p->trustFiles))
        return g_strdup("Choose at least one CA certificate the GDS is trusted through.");
    return NULL;
}

char *avm_plan_check(const AvmPlan *p) {
    if(!set(p->workDir))
        return g_strdup("Choose a work folder for the Auditor's identity and test CA.");
    if(p->profile == AVM_PROFILE_CLIENT) {
        if(p->listenPort == 0 || p->listenPort > 65535)
            return g_strdup("Choose a port between 1 and 65535 for the fake GDS.");
        if(p->preset == AVM_PRESET_CERT && !set(p->triggerCmd))
            return g_strdup("Preparation for certification needs the trigger command, so "
                            "every client test can run.");
        if(set(p->triggerCmd)) {
            char **argv = NULL;
            GError *e = NULL;
            if(!g_shell_parse_argv(p->triggerCmd, NULL, &argv, &e)) {
                char *m = g_strdup_printf("The trigger command cannot be read: %s", e->message);
                g_error_free(e);
                return m;
            }
            g_strfreev(argv);
        }
        return NULL;
    }
    return check_target(p);
}

char *avm_plan_thumbprint(const AvmPlan *p) {
    if(p->profile != AVM_PROFILE_SERVER || p->tofu || !set(p->serverCert))
        return NULL;
    char *data = NULL;
    gsize len = 0;
    if(!g_file_get_contents(p->serverCert, &data, &len, NULL))
        return NULL;
    char *hex = NULL;
    if(len > 0 && len <= AVM_MAX_CERT) {
        hex = g_compute_checksum_for_data(G_CHECKSUM_SHA1, (const guchar *)data, len);
        if(hex)
            for(char *c = hex; *c; c++)
                *c = g_ascii_toupper(*c);
    }
    g_free(data);
    return hex;
}

/* ---- saved form ---- */

#define GROUP "plan"

/* The string fields kept: key in the file, member of AvmPlan */
#define PLAN_STRINGS(X)                                                        \
    X("work", workDir)                                                         \
    X("url", url)                                                              \
    X("user", user)                                                            \
    X("password_file", passwordFile)                                           \
    X("server_cert", serverCert)                                               \
    X("admin_cert", adminCert)                                                 \
    X("admin_key", adminKey)                                                   \
    X("admin_user", adminUser)                                                 \
    X("admin_password_file", adminPasswordFile)                                \
    X("trust", trustFiles)                                                     \
    X("crl", crlFile)                                                          \
    X("trigger", triggerCmd)                                                   \
    X("client_user", clientUser)                                               \
    X("restart_cmd", restartCmd)                                               \
    X("name", name)

/* keys of the plan file the form has no field for: "x.tests.only" */
#define EXTRA_PREFIX "x."

void avm_plan_to_keyfile(const AvmPlan *p, GKeyFile *k, const char *group) {
    g_key_file_set_string(k, group, "profile", avm_profile_name(p->profile));
    g_key_file_set_integer(k, group, "preset", (gint)p->preset);
    g_key_file_set_boolean(k, group, "allow_changes", p->allowChanges);
    g_key_file_set_boolean(k, group, "tofu", p->tofu);
    g_key_file_set_integer(k, group, "listen_port", (gint)p->listenPort);
#define SAVE(key, member) g_key_file_set_string(k, group, key, p->member ? p->member : "");
    PLAN_STRINGS(SAVE)
#undef SAVE
    for(guint i = 0; p->extra && i < p->extra->len; i++) {
        const AvmPlanExtra *x = g_ptr_array_index(p->extra, i);
        char *key = g_strconcat(EXTRA_PREFIX, x->key, NULL);
        g_key_file_set_string_list(k, group, key, (const char *const *)x->values,
                                   g_strv_length(x->values));
        g_free(key);
    }
}

gboolean avm_keyfile_save(GKeyFile *k, const char *path, GError **error) {
    char *dir = g_path_get_dirname(path);
    gboolean ok = g_mkdir_with_parents(dir, 0700) == 0 && g_key_file_save_to_file(k, path, error);
    if(!ok && error && !*error)
        g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_FAILED, "cannot create %s", dir);
    g_free(dir);
    return ok;
}

gboolean avm_plan_save(const AvmPlan *p, const char *path, GError **error) {
    return avm_plan_save_file(p, path, error);
}

static void load_numbers(AvmPlan *p, GKeyFile *k, const char *group) {
    GError *e = NULL;
    gint preset = g_key_file_get_integer(k, group, "preset", &e);
    if(!e && preset >= 0 && preset < AVM_PRESET_COUNT)
        avm_plan_apply_preset(p, (AvmPreset)preset);
    g_clear_error(&e);
    gboolean b = g_key_file_get_boolean(k, group, "allow_changes", &e);
    if(!e)
        p->allowChanges = b;
    g_clear_error(&e);
    b = g_key_file_get_boolean(k, group, "tofu", &e);
    if(!e)
        p->tofu = b;
    g_clear_error(&e);
    gint port = g_key_file_get_integer(k, group, "listen_port", &e);
    if(!e && port > 0 && port <= 65535)
        p->listenPort = (guint)port;
    g_clear_error(&e);
}

static void load_string(GKeyFile *k, const char *group, const char *key, char **member) {
    char *v = g_key_file_get_string(k, group, key, NULL);
    if(v)
        avm_plan_set(member, v);
    g_free(v);
}

static void load_extra_key(AvmPlan *p, GKeyFile *k, const char *group, const char *key) {
    if(!g_str_has_prefix(key, EXTRA_PREFIX))
        return;
    const char *name = key + strlen(EXTRA_PREFIX);
    if(!ga_plan_key_type(avm_profile_name(p->profile), name, NULL))
        return;
    char **values = g_key_file_get_string_list(k, group, key, NULL, NULL);
    if(values && *values)
        avm_plan_extra_set(p, name, values);
    else
        g_strfreev(values);
}

static void load_extra(AvmPlan *p, GKeyFile *k, const char *group) {
    g_ptr_array_set_size(p->extra, 0); /* the loaded plan's own, not the last one's */
    char **keys = g_key_file_get_keys(k, group, NULL, NULL);
    for(char **key = keys; key && *key; key++)
        load_extra_key(p, k, group, *key);
    g_strfreev(keys);
}

void avm_plan_from_keyfile(AvmPlan *p, GKeyFile *k, const char *group) {
    char *profile = g_key_file_get_string(k, group, "profile", NULL);
    for(int i = 0; profile && i < 3; i++)
        if(!strcmp(profile, avm_profile_name((AvmProfile)i)))
            p->profile = (AvmProfile)i;
    g_free(profile);
    load_numbers(p, k, group);
#define LOAD(key, member) load_string(k, group, key, &p->member);
    PLAN_STRINGS(LOAD)
#undef LOAD
    load_extra(p, k, group);
}

/* Before plan files the form was kept in last-plan.ini, group [plan]. */
static gboolean load_legacy(AvmPlan *p, const char *path, GError **error) {
    char *dir = g_path_get_dirname(path);
    char *ini = g_build_filename(dir, "last-plan.ini", NULL);
    g_free(dir);
    GKeyFile *k = g_key_file_new();
    gboolean ok = g_key_file_load_from_file(k, ini, G_KEY_FILE_NONE, error);
    if(ok)
        avm_plan_from_keyfile(p, k, GROUP);
    g_key_file_unref(k);
    g_free(ini);
    return ok;
}

gboolean avm_plan_load(AvmPlan *p, const char *path, GError **error) {
    if(!g_file_test(path, G_FILE_TEST_EXISTS) && g_str_has_suffix(path, "last-plan.toml"))
        return load_legacy(p, path, error);
    return avm_plan_load_file(p, path, error);
}

char *avm_plan_default_path(void) {
    return g_build_filename(g_get_user_config_dir(), "gdsaudit", "last-plan.toml", NULL);
}
