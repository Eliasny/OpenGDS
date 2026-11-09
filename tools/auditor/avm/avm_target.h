/* OpenGDS Auditor view-model - targets (Auditor plan avm/avm_target.c):
 * discovery through the headless engine ("gdsaudit discover", cli/discover.h)
 * and saved targets. No GTK here, so it is tested without a display.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_AVM_TARGET_H
#define GDSAUDIT_AVM_TARGET_H

#include <gio/gio.h>

#include "avm_plan.h"

/* ---- discovery ---- */

typedef struct {
    char *url, *policyUri, *mode; /* mode: none, sign, signandencrypt */
    guint level;                  /* SecurityLevel: higher is stronger */
    char *thumbprint;             /* SHA-1 hex, "" if no certificate */
    char *userTokens;             /* comma-separated: anonymous, username, ... */
    char *certFile;               /* the certificate written by --certs, or "" */
    char *certText;               /* subject | issuer | notAfter */
} AvmEndpoint;

typedef struct {
    GPtrArray *endpoints; /* AvmEndpoint*, duplicates (same url, policy, mode) left out */
    GPtrArray *servers;   /* char*: "name (uri), type" */
    GPtrArray *errors;    /* char*: "step url: status" */
} AvmDiscovery;

/* The policy's short name: the part after '#' of its URI. */
const char *avm_policy_name(const char *policyUri);

/* Parse the output of "gdsaudit discover". Lines that are not records are
 * skipped. Endpoints are sorted by security (level, then mode) strongest
 * first. Never NULL; free with avm_discovery_free. */
AvmDiscovery *avm_discovery_parse(const char *output);
void avm_discovery_free(AvmDiscovery *d);

/* Run "ENGINE discover --url URL --certs CERTS_DIR" without blocking; done
 * gets the parsed result, or NULL and an error message. */
typedef void (*AvmDiscoverDone)(AvmDiscovery *d, const char *error, gpointer user);
void avm_discover(const char *engine, const char *url, const char *certsDir,
                  GCancellable *cancel, AvmDiscoverDone done, gpointer user);
/* <user data>/gdsaudit/certs: where discovered certificates are written. */
char *avm_discover_certs_dir(void);

/* Use an endpoint in the plan: its URL, and its certificate pinned (TOFU
 * off). The endpoint's policy and mode are not part of the plan: the
 * profiles choose their own (the server profile opens every endpoint). */
void avm_plan_use_endpoint(AvmPlan *p, const AvmEndpoint *e);

/* ---- saved targets ----
 * One key file; each target is a group holding a whole plan (target URL,
 * pinned certificate, identity paths; never passwords). */

/* <user config>/gdsaudit/targets.ini; g_free it. */
char *avm_targets_default_path(void);
/* TRUE if name can be a target name: 1-64 bytes of UTF-8, no control
 * characters, no '[' or ']'. */
gboolean avm_target_name_ok(const char *name);
/* Names in file order; never NULL (empty if the file is missing). */
char **avm_targets_list(const char *path);
gboolean avm_target_save(const char *path, const char *name, const AvmPlan *p, GError **error);
gboolean avm_target_load(const char *path, const char *name, AvmPlan *p, GError **error);
gboolean avm_target_delete(const char *path, const char *name, GError **error);

#endif
