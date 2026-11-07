/* OpenGDS Auditor - plan files (Auditor plan core/plan.c): one TOML file
 * describes a run, so a plan saved in the desktop UI runs unchanged
 * headless with `gdsaudit run PLAN.toml`. Format: docs/auditor/plan-files.md.
 *
 * A plan holds the profile and the profile's options, grouped in the tables
 * [target], [identity], [tests], [hooks] and [report]. Every key maps to one
 * command-line option of the profile (ga_plan_argv), so a plan and a command
 * line give the same run. Passwords are never stored, only the paths of
 * password files. Relative paths are relative to the plan file.
 *
 * libc only: the headless binary and the desktop UI both link it.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_PLAN_H
#define GDSAUDIT_PLAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#define GA_PLAN_SCHEMA "gdsaudit-plan"
#define GA_PLAN_VERSION 1
#define GA_PLAN_MAX_FILE ((size_t)64 * 1024)
#define GA_PLAN_MAX_VALUE 4096 /* bytes per string */
#define GA_PLAN_MAX_ITEMS 32   /* per array */

typedef struct ga_plan ga_plan;

typedef enum {
    GA_PLAN_STRING = 0,
    GA_PLAN_PATH,    /* string; relative to the plan file */
    GA_PLAN_BOOL,    /* "true" or "false" */
    GA_PLAN_INT,     /* decimal */
    GA_PLAN_PATHS,   /* array of paths; the option repeats */
    GA_PLAN_COMMAND  /* array of strings: the client's trigger after "--";
                        the first is a path if it has a '/' */
} ga_plan_type;

/* A new, empty plan for "server", "client" or "gds"; NULL for another
 * profile or out of memory. */
ga_plan *ga_plan_new(const char *profile);
void ga_plan_free(ga_plan *p);
const char *ga_plan_profile(const ga_plan *p);

/* Optional free text for people (the UI's target name); NULL if none. */
const char *ga_plan_name(const ga_plan *p);
bool ga_plan_set_name(ga_plan *p, const char *name);
/* Optional UI preset: "quick", "full" or "certification"; headless runs
 * keep it but do not use it. */
const char *ga_plan_preset(const ga_plan *p);
bool ga_plan_set_preset(ga_plan *p, const char *preset);

/* Keys are "table.key", for example "target.url". The key must exist for
 * the plan's profile (ga_plan_key_type) and the value must suit its type.
 * set replaces the value (for an array: makes it one item); add appends
 * to an array; unset removes the key. Values are copied. */
bool ga_plan_set(ga_plan *p, const char *key, const char *value);
bool ga_plan_add(ga_plan *p, const char *key, const char *value);
void ga_plan_unset(ga_plan *p, const char *key);
/* Number of values of key (0 if unset), and value i (NULL past the end) */
size_t ga_plan_count(const ga_plan *p, const char *key);
const char *ga_plan_get(const ga_plan *p, const char *key, size_t i);
/* The key's type for profile; false if the profile has no such key. */
bool ga_plan_key_type(const char *profile, const char *key, ga_plan_type *type);
/* The option a key gives for profile ("--url"); NULL if none. For
 * GA_PLAN_COMMAND it is "--". */
const char *ga_plan_key_option(const char *profile, const char *key);

/* Load a plan. On error returns NULL and err names the file, the line and
 * the reason. */
ga_plan *ga_plan_load(const char *path, char *err, size_t errLen);
/* Parse plan text (name is used in error messages). */
ga_plan *ga_plan_parse(const char *text, size_t len, const char *name, char *err,
                       size_t errLen);
/* Save through PATH.tmp and a rename. */
bool ga_plan_save(const ga_plan *p, const char *path, char *err, size_t errLen);
/* Write the plan as TOML. */
bool ga_plan_write(const ga_plan *p, FILE *f);

/* The command line the plan stands for: { profile, options..., ["--",
 * trigger...], NULL }, without the program name. Relative paths are joined
 * to baseDir (NULL or "" keeps them as they are). The array and its strings
 * are one allocation: free(argv). NULL on out of memory. */
char **ga_plan_argv(const ga_plan *p, const char *baseDir, int *argc);

#endif
