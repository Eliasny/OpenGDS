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
    avm_plan_apply_preset(p, AVM_PRESET_QUICK);
}

void avm_plan_clear(AvmPlan *p) {
    char **fields[] = {&p->workDir,    &p->url,        &p->user,    &p->passwordFile,
                       &p->serverCert, &p->trustFiles, &p->crlFile, &p->triggerCmd,
                       &p->clientUser, &p->adminCert, &p->adminKey, &p->adminUser,
                       &p->adminPasswordFile};
    for(size_t i = 0; i < G_N_ELEMENTS(fields); i++)
        g_clear_pointer(fields[i], g_free);
}

void avm_plan_apply_preset(AvmPlan *p, AvmPreset preset) {
    p->preset = preset;
    p->allowChanges = preset != AVM_PRESET_QUICK;
}

static gboolean set(const char *s) {
    return s && *s;
}

static char *check_target(const AvmPlan *p) {
    if(!set(p->url) || !g_str_has_prefix(p->url, "opc.tcp://"))
        return g_strdup("Enter the target's endpoint URL (opc.tcp://host:port).");
    if(set(p->user) && !set(p->passwordFile))
        return g_strdup("A user name needs a password file.");
    if(p->profile == AVM_PROFILE_SERVER && !set(p->serverCert) && !p->tofu)
        return g_strdup("Choose the target's certificate, or allow trust on first use "
                        "(test setups only).");
    if(p->profile == AVM_PROFILE_SERVER && set(p->serverCert) && p->tofu)
        return g_strdup("Choose either a pinned certificate or trust on first use, not both.");
    if(p->profile == AVM_PROFILE_SERVER && set(p->adminCert) != set(p->adminKey))
        return g_strdup("An admin certificate needs its key, and a key its certificate.");
    if(p->profile == AVM_PROFILE_SERVER && set(p->adminUser) && !set(p->adminPasswordFile))
        return g_strdup("An admin user needs a password file.");
    if(p->profile == AVM_PROFILE_SERVER && set(p->adminUser) && set(p->adminCert))
        return g_strdup("Choose either an admin certificate or an admin user, not both.");
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

static void add(GPtrArray *a, const char *s) {
    g_ptr_array_add(a, g_strdup(s));
}

static void add_opt(GPtrArray *a, const char *flag, const char *value) {
    if(!set(value))
        return;
    add(a, flag);
    add(a, value);
}

static void add_server_args(GPtrArray *a, const AvmPlan *p) {
    if(p->tofu)
        add(a, "--tofu");
    else
        add_opt(a, "--server-cert", p->serverCert);
    if(set(p->adminCert)) {
        add_opt(a, "--admin-cert", p->adminCert);
        add_opt(a, "--admin-key", p->adminKey);
    } else if(set(p->adminUser)) {
        add_opt(a, "--admin-user", p->adminUser);
        add_opt(a, "--admin-password-file", p->adminPasswordFile);
    }
    if(set(p->user)) {
        add_opt(a, "--user", p->user);
        add_opt(a, "--user-password-file", p->passwordFile);
    }
}

static void add_target_args(GPtrArray *a, const AvmPlan *p) {
    add_opt(a, "--url", p->url);
    if(p->allowChanges)
        add(a, "--allow-changes");
    if(p->profile == AVM_PROFILE_SERVER) {
        add_server_args(a, p);
        return;
    }
    if(set(p->user)) {
        add_opt(a, "--user", p->user);
        add_opt(a, "--password-file", p->passwordFile);
    }
    char **trust = g_strsplit(p->trustFiles, ";", -1);
    for(char **t = trust; *t; t++) {
        char *s = g_strstrip(*t);
        add_opt(a, "--trust", s);
    }
    g_strfreev(trust);
    add_opt(a, "--crl", p->crlFile);
}

char **avm_plan_argv(const AvmPlan *p, const char *engine, const char *events,
                     const char *reportDir, GError **error) {
    char **trigger = NULL;
    if(p->profile == AVM_PROFILE_CLIENT && set(p->triggerCmd) &&
       !g_shell_parse_argv(p->triggerCmd, NULL, &trigger, error))
        return NULL;
    GPtrArray *a = g_ptr_array_new();
    add(a, engine);
    add(a, avm_profile_name(p->profile));
    add_opt(a, "--events", events);
    add_opt(a, "--report", reportDir);
    add_opt(a, "--work", p->workDir);
    if(p->profile == AVM_PROFILE_CLIENT) {
        char port[16];
        g_snprintf(port, sizeof(port), "%u", p->listenPort);
        add_opt(a, "--listen", port);
        add_opt(a, "--user", p->clientUser);
        if(trigger) {
            add(a, "--");
            for(char **t = trigger; *t; t++)
                add(a, *t);
        }
    } else {
        add_target_args(a, p);
    }
    g_strfreev(trigger);
    g_ptr_array_add(a, NULL);
    return (char **)g_ptr_array_free(a, FALSE);
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
