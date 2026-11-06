/* OpenGDS Auditor view-model - what to run (Auditor plan avm/avm_plan.c):
 * the profile form, the presets, the checks before a run starts, and the
 * headless command line the run is made of. No GTK here, so it is tested
 * without a display.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_AVM_PLAN_H
#define GDSAUDIT_AVM_PLAN_H

#include <glib.h>

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
} AvmPlan;

void avm_plan_init(AvmPlan *p);
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

/* SHA-1 thumbprint of the pinned server certificate as hex, as the target
 * would show it; NULL if there is no readable pinned certificate. */
char *avm_plan_thumbprint(const AvmPlan *p);

#endif
