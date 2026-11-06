/* OpenGDS Auditor view-model - targets (avm_target.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include "avm_target.h"

#include <string.h>

/* ---- discovery ---- */

#define MAX_RECORDS 1024 /* lines read from one discovery */

const char *avm_policy_name(const char *policyUri) {
    const char *hash = policyUri ? strrchr(policyUri, '#') : NULL;
    return hash ? hash + 1 : (policyUri ? policyUri : "");
}

static void endpoint_free(gpointer p) {
    AvmEndpoint *e = p;
    g_free(e->url);
    g_free(e->policyUri);
    g_free(e->mode);
    g_free(e->thumbprint);
    g_free(e->userTokens);
    g_free(e->certFile);
    g_free(e->certText);
    g_free(e);
}

void avm_discovery_free(AvmDiscovery *d) {
    if(!d)
        return;
    g_ptr_array_unref(d->endpoints);
    g_ptr_array_unref(d->servers);
    g_ptr_array_unref(d->errors);
    g_free(d);
}

static int mode_rank(const char *mode) {
    if(!strcmp(mode, "signandencrypt"))
        return 2;
    return !strcmp(mode, "sign") ? 1 : 0;
}

static gint by_strength(gconstpointer a, gconstpointer b) {
    const AvmEndpoint *x = *(AvmEndpoint *const *)a;
    const AvmEndpoint *y = *(AvmEndpoint *const *)b;
    if(x->level != y->level)
        return x->level > y->level ? -1 : 1;
    return mode_rank(y->mode) - mode_rank(x->mode);
}

static gboolean same_endpoint(const AvmEndpoint *a, const AvmEndpoint *b) {
    return !strcmp(a->url, b->url) && !strcmp(a->policyUri, b->policyUri) &&
           !strcmp(a->mode, b->mode);
}

static void add_endpoint(AvmDiscovery *d, char **f) {
    AvmEndpoint *e = g_new0(AvmEndpoint, 1);
    e->url = g_strdup(f[1]);
    e->policyUri = g_strdup(f[2]);
    e->mode = g_strdup(f[3]);
    guint64 level = 0;
    if(!g_ascii_string_to_unsigned(f[4], 10, 0, 255, &level, NULL))
        level = 0;
    e->level = (guint)level;
    e->thumbprint = g_strdup(f[5]);
    e->userTokens = g_strdup(f[6]);
    e->certFile = g_strdup(f[7]);
    e->certText = g_strdup(f[8]);
    for(guint i = 0; i < d->endpoints->len; i++) {
        if(same_endpoint(g_ptr_array_index(d->endpoints, i), e)) {
            endpoint_free(e);
            return;
        }
    }
    g_ptr_array_add(d->endpoints, e);
}

static void add_record(AvmDiscovery *d, char **f, guint n) {
    if(!strcmp(f[0], "endpoint") && n >= 9) {
        add_endpoint(d, f);
    } else if(!strcmp(f[0], "server") && n >= 5) {
        g_ptr_array_add(d->servers, g_strdup_printf("%s (%s), %s", f[2], f[1], f[3]));
    } else if(!strcmp(f[0], "network") && n >= 5) {
        g_ptr_array_add(d->servers, g_strdup_printf("%s at %s (on the network)", f[2], f[3]));
    } else if(!strcmp(f[0], "error") && n >= 4) {
        const char *step = !strcmp(f[1], "findservers")    ? "FindServers"
                           : !strcmp(f[1], "getendpoints") ? "GetEndpoints"
                                                           : "FindServersOnNetwork";
        g_ptr_array_add(d->errors, g_strdup_printf("%s on %s: %s", step, f[2], f[3]));
    }
}

AvmDiscovery *avm_discovery_parse(const char *output) {
    AvmDiscovery *d = g_new0(AvmDiscovery, 1);
    d->endpoints = g_ptr_array_new_with_free_func(endpoint_free);
    d->servers = g_ptr_array_new_with_free_func(g_free);
    d->errors = g_ptr_array_new_with_free_func(g_free);
    char **lines = g_strsplit(output ? output : "", "\n", MAX_RECORDS + 1);
    for(guint i = 0; lines[i] && i < MAX_RECORDS; i++) {
        if(!g_utf8_validate(lines[i], -1, NULL))
            continue;
        char **f = g_strsplit(lines[i], "\t", 10);
        guint n = g_strv_length(f);
        if(n > 0)
            add_record(d, f, n);
        g_strfreev(f);
    }
    g_strfreev(lines);
    g_ptr_array_sort(d->endpoints, by_strength);
    return d;
}

typedef struct {
    AvmDiscoverDone done;
    gpointer user;
} DiscoverCall;

/* NUL-terminated copy of a pipe's bytes (lines with invalid UTF-8 are
 * skipped by the parser, so one bad name does not lose the rest). */
static char *bytes_text(GBytes *b) {
    gsize len = 0;
    const char *data = b ? g_bytes_get_data(b, &len) : NULL;
    return data ? g_strndup(data, len) : g_strdup("");
}

static void on_discovered(GObject *src, GAsyncResult *res, gpointer data) {
    DiscoverCall *call = data;
    GBytes *outB = NULL, *errB = NULL;
    GError *e = NULL;
    GSubprocess *proc = G_SUBPROCESS(src);
    if(!g_subprocess_communicate_finish(proc, res, &outB, &errB, &e)) {
        call->done(NULL, e ? e->message : "discovery failed", call->user);
    } else if(g_subprocess_get_if_exited(proc) && g_subprocess_get_exit_status(proc) == 2) {
        char *err = g_strstrip(bytes_text(errB));
        call->done(NULL, *err && g_utf8_validate(err, -1, NULL) ? err : "the URL was not accepted",
                   call->user);
        g_free(err);
    } else {
        char *out = bytes_text(outB);
        AvmDiscovery *d = avm_discovery_parse(out);
        call->done(d, NULL, call->user);
        avm_discovery_free(d);
        g_free(out);
    }
    g_clear_error(&e);
    if(outB)
        g_bytes_unref(outB);
    if(errB)
        g_bytes_unref(errB);
    g_free(call);
}

void avm_discover(const char *engine, const char *url, const char *certsDir,
                  GCancellable *cancel, AvmDiscoverDone done, gpointer user) {
    GError *e = NULL;
    GSubprocess *proc = g_subprocess_new(
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE, &e, engine, "discover",
        "--url", url, "--certs", certsDir, NULL);
    if(!proc) {
        done(NULL, e ? e->message : "cannot start the engine", user);
        g_clear_error(&e);
        return;
    }
    DiscoverCall *call = g_new0(DiscoverCall, 1);
    call->done = done;
    call->user = user;
    g_subprocess_communicate_async(proc, NULL, cancel, on_discovered, call);
    g_object_unref(proc);
}

char *avm_discover_certs_dir(void) {
    return g_build_filename(g_get_user_data_dir(), "gdsaudit", "certs", NULL);
}

void avm_plan_use_endpoint(AvmPlan *p, const AvmEndpoint *e) {
    avm_plan_set(&p->url, e->url);
    if(e->certFile && *e->certFile) {
        avm_plan_set(&p->serverCert, e->certFile);
        p->tofu = FALSE;
    }
}

/* ---- saved targets ---- */

#define MAX_NAME 64

char *avm_targets_default_path(void) {
    return g_build_filename(g_get_user_config_dir(), "gdsaudit", "targets.ini", NULL);
}

gboolean avm_target_name_ok(const char *name) {
    size_t len = name ? strlen(name) : 0;
    if(len == 0 || len > MAX_NAME || !g_utf8_validate(name, -1, NULL))
        return FALSE;
    for(const char *c = name; *c; c = g_utf8_next_char(c)) {
        gunichar u = g_utf8_get_char(c);
        if(g_unichar_iscntrl(u) || u == '[' || u == ']')
            return FALSE;
    }
    return TRUE;
}

static GKeyFile *load_file(const char *path, gboolean mustExist, GError **error) {
    GKeyFile *k = g_key_file_new();
    GError *e = NULL;
    if(!g_key_file_load_from_file(k, path, G_KEY_FILE_KEEP_COMMENTS, &e)) {
        if(mustExist || !g_error_matches(e, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
            g_propagate_error(error, e);
            g_key_file_unref(k);
            return NULL;
        }
        g_clear_error(&e);
    }
    return k;
}

static gboolean check_name(const char *name, GError **error) {
    if(avm_target_name_ok(name))
        return TRUE;
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                "A target name is 1 to %d characters, without [ ] or control characters.",
                MAX_NAME);
    return FALSE;
}

char **avm_targets_list(const char *path) {
    GKeyFile *k = load_file(path, FALSE, NULL);
    char **names = k ? g_key_file_get_groups(k, NULL) : NULL;
    if(k)
        g_key_file_unref(k);
    return names ? names : g_new0(char *, 1);
}

gboolean avm_target_save(const char *path, const char *name, const AvmPlan *p, GError **error) {
    if(!check_name(name, error))
        return FALSE;
    GKeyFile *k = load_file(path, FALSE, error);
    if(!k)
        return FALSE;
    g_key_file_remove_group(k, name, NULL); /* a saved target is replaced whole */
    avm_plan_to_keyfile(p, k, name);
    gboolean ok = avm_keyfile_save(k, path, error);
    g_key_file_unref(k);
    return ok;
}

gboolean avm_target_load(const char *path, const char *name, AvmPlan *p, GError **error) {
    if(!check_name(name, error))
        return FALSE;
    GKeyFile *k = load_file(path, TRUE, error);
    if(!k)
        return FALSE;
    gboolean ok = g_key_file_has_group(k, name);
    if(ok)
        avm_plan_from_keyfile(p, k, name);
    else
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "No saved target named %s", name);
    g_key_file_unref(k);
    return ok;
}

gboolean avm_target_delete(const char *path, const char *name, GError **error) {
    if(!check_name(name, error))
        return FALSE;
    GKeyFile *k = load_file(path, TRUE, error);
    if(!k)
        return FALSE;
    gboolean ok = g_key_file_remove_group(k, name, error) && avm_keyfile_save(k, path, error);
    g_key_file_unref(k);
    return ok;
}
