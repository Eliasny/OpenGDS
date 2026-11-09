/* OpenGDS Auditor view-model - what to run (Auditor plan avm/avm_plan.c):
 * the profile form, the presets, the checks before a run starts, and the
 * headless command line the run is made of. No GTK here, so it is tested
 * without a display.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_AVM_PLAN_H
#define GDSAUDIT_AVM_PLAN_H

#include <glib.h>

#include "gdsaudit/plan.h"

typedef enum { AVM_PROFILE_SERVER = 0, AVM_PROFILE_CLIENT, AVM_PROFILE_GDS } AvmProfile;

typedef enum {
    AVM_PRESET_QUICK = 0, /* quick read-only check: nothing written to the target */
    AVM_PRESET_FULL,      /* full run: every test, changes allowed */
    AVM_PRESET_CERT       /* preparation for certification: full run, hooks required,
                             any Not tested makes the run Incomplete */
} AvmPreset;

#define AVM_PRESET_COUNT 3

const char *avm_profile_name(AvmProfile p); /* "server", "client", "gds" */
const char *avm_profile_label(AvmProfile p);
const char *avm_preset_label(AvmPreset p);
const char *avm_preset_description(AvmPreset p);

/* The form. Strings are owned by the plan (g_free'd by avm_plan_clear);
 * empty strings count as unset. */
typedef struct {
    AvmProfile profile;
    AvmPreset preset;
    gboolean allowChanges; /* set from the preset, the user can change it */
    gboolean slow;         /* server: run the tests flagged slow; set from the preset */
    char *workDir;
    /* server and gds */
    char *url;
    char *user, *passwordFile;
    /* server */
    char *serverCert; /* pinned target certificate (DER) */
    /* server: how the Auditor gets SecurityAdmin (default: its own
     * <work>/admin identity), and user/passwordFile are a plain user */
    char *adminCert, *adminKey;
    char *adminUser, *adminPasswordFile;
    gboolean tofu;    /* trust on first use: test setups only */
    /* gds */
    char *trustFiles; /* CA certificates, separated by ';' */
    char *crlFile;
    /* client */
    guint listenPort;
    char *triggerCmd; /* argv in shell syntax, run without a shell */
    char *clientUser;
    /* server: shell command that restarts the target (SRV-PER-*) */
    char *restartCmd;
    /* plan file: its name for people, and the keys the form has no field
     * for (AvmPlanExtra*), kept so a loaded plan runs and saves unchanged */
    char *name;
    GPtrArray *extra;
} AvmPlan;

typedef struct {
    char *key;     /* "tests.only" */
    char **values; /* NULL-terminated; one item unless the key is an array */
} AvmPlanExtra;

void avm_plan_init(AvmPlan *p);
void avm_plan_extra_free(gpointer x);
/* Keep key with values (takes the vector) in p->extra, replacing it. */
void avm_plan_extra_set(AvmPlan *p, const char *key, char **values);
void avm_plan_clear(AvmPlan *p);
/* Choose a preset: sets allowChanges from it. */
void avm_plan_apply_preset(AvmPlan *p, AvmPreset preset);
/* Replace one string field (takes a copy). */
void avm_plan_set(char **field, const char *value);

/* Checks before a run starts. Returns NULL if the plan can run, else a
 * message for the user (g_free it). */
char *avm_plan_check(const AvmPlan *p);

/* The headless command line for the plan: ENGINE PROFILE ... with
 * --events EVENTS and --report REPORT_DIR. NULL-terminated; g_strfreev it.
 * NULL (and *error set) if the trigger command cannot be parsed. */
char **avm_plan_argv(const AvmPlan *p, const char *engine, const char *events,
                     const char *reportDir, GError **error);

/* Plan files (gdsaudit/plan.h, docs/auditor/plan-files.md): the form as
 * the plan `gdsaudit run` runs. avm_plan_argv is built from the same plan,
 * so a plan saved here runs headless with the same command line.
 * to_ga gives absolute paths (relative ones are taken from the current
 * folder); NULL and *error if a value is refused. from_ga replaces the form;
 * relative paths in g are joined to baseDir. The report and events paths
 * and hooks.prompts belong to each UI run and are not taken. */
ga_plan *avm_plan_to_ga(const AvmPlan *p, GError **error);
gboolean avm_plan_from_ga(AvmPlan *p, const ga_plan *g, const char *baseDir, GError **error);
/* The kept plan keys that apply to the profile, for people
 * ("tests.only = SRV-TL; ..."); NULL if none. g_free it. */
char *avm_plan_extra_text(const AvmPlan *p);
gboolean avm_plan_save_file(const AvmPlan *p, const char *path, GError **error);
gboolean avm_plan_load_file(AvmPlan *p, const char *path, GError **error);

/* The form between sessions: the plan file avm_plan_default_path (paths,
 * never passwords). load reads the older last-plan.ini when there is no
 * plan file yet, and returns FALSE if neither can be read. */
gboolean avm_plan_save(const AvmPlan *p, const char *path, GError **error);
gboolean avm_plan_load(AvmPlan *p, const char *path, GError **error);
/* The same fields in one group of a key file (saved targets keep one plan
 * per group); from_keyfile keeps the current values for missing keys. */
void avm_plan_to_keyfile(const AvmPlan *p, GKeyFile *k, const char *group);
void avm_plan_from_keyfile(AvmPlan *p, GKeyFile *k, const char *group);
/* Save a key file, creating its folder (0700). */
gboolean avm_keyfile_save(GKeyFile *k, const char *path, GError **error);
/* <user config>/gdsaudit/last-plan.toml; g_free it. */
char *avm_plan_default_path(void);

/* SHA-1 thumbprint of the pinned server certificate as hex, as the target
 * would show it; NULL if there is no readable pinned certificate. */
char *avm_plan_thumbprint(const AvmPlan *p);

#endif
