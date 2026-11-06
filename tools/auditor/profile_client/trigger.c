/* OpenGDS Auditor client profile - trigger hook. See trigger.h.
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "trigger.h"
#include "probe.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "common/buf.h"
#include "common/limits.h"
#include "fake_gds.h"
#include "common/banned.h"

#define TRIG_ENV_MAX 16
#define TRIG_ENV_LEN (GDS_MAX_PATH + 64)

/* Passed through from the Auditor's own environment (sanitizer settings for
 * the self-test targets, a usable PATH and HOME). Nothing else leaks in. */
static const char *const passThrough[] = {"PATH",         "HOME",         "ASAN_OPTIONS",
                                          "UBSAN_OPTIONS", "TSAN_OPTIONS", "LSAN_OPTIONS",
                                          "LD_LIBRARY_PATH"};

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void serve(void) {
    fg_iterate();
    probe_iterate();
}

typedef struct {
    char store[TRIG_ENV_MAX][TRIG_ENV_LEN];
    char *envp[TRIG_ENV_MAX + 1];
    size_t n;
} trig_env;

static gds_status env_add(trig_env *e, const char *name, const char *value) {
    if(e->n == TRIG_ENV_MAX || !value)
        return value ? GDS_ETOOBIG : GDS_OK;
    gds_status r = gds_path(e->store[e->n], TRIG_ENV_LEN, "%s=%s", name, value);
    if(r != GDS_OK)
        return r;
    e->envp[e->n] = e->store[e->n];
    e->n++;
    e->envp[e->n] = NULL;
    return GDS_OK;
}

static gds_status build_env(trig_env *e, const trig_cfg *cfg, const char *user) {
    memset(e, 0, sizeof(*e));
    gds_status r = GDS_OK;
    for(size_t i = 0; i < GDS_ARRAY_SIZE(passThrough) && r == GDS_OK; i++)
        r = env_add(e, passThrough[i], getenv(passThrough[i]));
    if(r == GDS_OK) r = env_add(e, "GDSAUDIT_GDS_URL", fg_url());
    if(r == GDS_OK) r = env_add(e, "GDSAUDIT_GDS_CA", fg_ca_path());
    if(r == GDS_OK) r = env_add(e, "GDSAUDIT_GDS_CRL", fg_crl_path());
    if(r == GDS_OK) r = env_add(e, "GDSAUDIT_GDS_USER", user);
    if(r == GDS_OK) r = env_add(e, "GDSAUDIT_GDS_PASSWORD_FILE", fg_password_path());
    if(r == GDS_OK) r = env_add(e, "GDSAUDIT_CLIENT_DIR", cfg->clientDir);
    if(r == GDS_OK) r = env_add(e, "GDSAUDIT_ACTION", cfg->action);
    if(r == GDS_OK && cfg->action) r = env_add(e, "GDSAUDIT_PROBE_URL", cfg->probeUrl);
    return r;
}

static gds_status spawn(const trig_cfg *cfg, char *const *envp, pid_t *pid) {
    posix_spawn_file_actions_t fa;
    if(posix_spawn_file_actions_init(&fa) != 0)
        return GDS_ENOMEM;
    int rc = posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, cfg->logPath,
                                              O_WRONLY | O_CREAT | O_APPEND, 0600);
    if(rc == 0)
        rc = posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDERR_FILENO);
    if(rc == 0)
        rc = posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    if(rc == 0)
        rc = posix_spawn(pid, cfg->argv[0], &fa, NULL, cfg->argv, envp);
    posix_spawn_file_actions_destroy(&fa);
    if(rc != 0) {
        fprintf(stderr, "trigger %s: %s\n", cfg->argv[0], strerror(rc));
        return GDS_EIO;
    }
    return GDS_OK;
}

/* SIGTERM, then SIGKILL after 2 s; reaps the child. */
static void stop_child(pid_t pid) {
    int st = 0;
    (void)kill(pid, SIGTERM);
    double t0 = now_ms();
    while(now_ms() - t0 < 2000.0) {
        if(waitpid(pid, &st, WNOHANG) == pid)
            return;
        serve();
    }
    (void)kill(pid, SIGKILL);
    (void)waitpid(pid, &st, 0);
}

gds_status trig_run(const trig_cfg *cfg, const char *user, trig_result *res) {
    memset(res, 0, sizeof(*res));
    if(!cfg->argv || !cfg->argv[0])
        return GDS_EINVAL;
    static trig_env env; /* large: keep it off the stack */
    gds_status r = build_env(&env, cfg, user);
    if(r != GDS_OK)
        return r;
    pid_t pid = 0;
    double t0 = now_ms();
    if((r = spawn(cfg, env.envp, &pid)) != GDS_OK)
        return r;
    for(;;) {
        int st = 0;
        pid_t w = waitpid(pid, &st, WNOHANG);
        if(w == pid) {
            res->exited = WIFEXITED(st);
            res->exitStatus = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
            break;
        }
        if(w < 0 && errno != EINTR) {
            r = GDS_EIO;
            break;
        }
        if(now_ms() - t0 > 1000.0 * cfg->timeoutSeconds) {
            stop_child(pid);
            res->exited = false;
            break;
        }
        serve();
    }
    /* Serve what the client sent just before it exited (CloseSession) */
    for(int i = 0; i < 5; i++)
        serve();
    res->ms = now_ms() - t0;
    return r;
}
