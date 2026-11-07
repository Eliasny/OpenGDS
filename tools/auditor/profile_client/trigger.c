/* OpenGDS Auditor client profile - trigger hook. See trigger.h.
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "trigger.h"
#include "probe.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include "common/platform.h" /* windows.h */
#else
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "common/buf.h"
#include "common/limits.h"
#include "fake_gds.h"
#include "common/banned.h"

#define TRIG_ENV_MAX 24
#define TRIG_ENV_LEN (GDS_MAX_PATH + 64)

/* Passed through from the Auditor's own environment (sanitizer settings for
 * the self-test targets, a usable PATH and HOME). Nothing else leaks in. */
#ifdef _WIN32
/* Windows programs need these to start at all (SystemRoot) or to find
 * their profile and temporary folders. */
static const char *const passThrough[] = {"PATH",        "PATHEXT",      "SystemRoot", "SystemDrive",
                                          "windir",      "COMSPEC",      "TEMP",       "TMP",
                                          "USERPROFILE", "LOCALAPPDATA", "APPDATA"};
#else
static const char *const passThrough[] = {"PATH",         "HOME",         "ASAN_OPTIONS",
                                          "UBSAN_OPTIONS", "TSAN_OPTIONS", "LSAN_OPTIONS",
                                          "LD_LIBRARY_PATH"};
#endif

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
    if(r == GDS_OK && cfg->probeUrl) r = env_add(e, "GDSAUDIT_PROBE_URL", cfg->probeUrl);
    if(r == GDS_OK) r = env_add(e, "GDSAUDIT_PROMPT_USER", cfg->promptUser);
    if(r == GDS_OK) r = env_add(e, "GDSAUDIT_PROMPT_PASSWORD_FILE", cfg->promptPasswordFile);
    char rs[24];
    if(r == GDS_OK && cfg->runSeconds > 0 &&
       (r = gds_path(rs, sizeof(rs), "%ld", cfg->runSeconds)) == GDS_OK)
        r = env_add(e, "GDSAUDIT_RUN_SECONDS", rs);
    return r;
}

#ifdef _WIN32
/* One argument for CreateProcess's command line, quoted the way the
 * Microsoft C runtime splits it again (backslashes double only before a
 * quote). */
static bool quote_arg(char *out, size_t outLen, size_t *k, const char *arg) {
    bool plain = *arg && !strpbrk(arg, " \t\n\v\"");
    size_t need = strlen(arg) * 2 + 4;
    if(*k + need >= outLen)
        return false;
    if(*k)
        out[(*k)++] = ' ';
    if(plain) {
        memcpy(out + *k, arg, strlen(arg));
        *k += strlen(arg);
        return true;
    }
    out[(*k)++] = '"';
    for(const char *p = arg;; p++) {
        size_t bs = 0;
        while(*p == '\\') {
            p++;
            bs++;
        }
        if(!*p) {
            for(size_t i = 0; i < bs * 2; i++)
                out[(*k)++] = '\\';
            break;
        }
        if(*p == '"')
            bs = bs * 2 + 1;
        for(size_t i = 0; i < bs; i++)
            out[(*k)++] = '\\';
        out[(*k)++] = *p;
    }
    out[(*k)++] = '"';
    out[*k] = '\0';
    return true;
}

static bool is_batch(const char *prog) {
    size_t n = strlen(prog);
    return n > 4 && (_stricmp(prog + n - 4, ".bat") == 0 || _stricmp(prog + n - 4, ".cmd") == 0);
}

/* The environment block: "NAME=value\0...\0\0", sorted by name as Windows
 * expects. */
static int env_cmp(const void *a, const void *b) {
    return _stricmp(*(const char *const *)a, *(const char *const *)b);
}

static HANDLE current; /* the hook trig_run waits for, NULL if none */

static gds_status spawn(const trig_cfg *cfg, trig_env *env, HANDLE *proc) {
    static char cmd[32768], block[TRIG_ENV_MAX * TRIG_ENV_LEN + 1];
    size_t k = 0;
    cmd[0] = '\0';
    /* a .bat or .cmd runs through cmd.exe /c */
    const char *comspec = getenv("COMSPEC");
    if(is_batch(cfg->argv[0]) && (!quote_arg(cmd, sizeof(cmd), &k, comspec ? comspec : "cmd.exe") ||
                                  !quote_arg(cmd, sizeof(cmd), &k, "/c")))
        return GDS_ETOOBIG;
    for(char *const *a = cfg->argv; *a; a++)
        if(!quote_arg(cmd, sizeof(cmd), &k, *a))
            return GDS_ETOOBIG;
    qsort(env->envp, env->n, sizeof(env->envp[0]), env_cmp);
    size_t b = 0;
    for(size_t i = 0; i < env->n; i++) {
        size_t l = strlen(env->envp[i]) + 1;
        memcpy(block + b, env->envp[i], l);
        b += l;
    }
    block[b] = '\0';
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE}; /* inherited by the hook */
    HANDLE log = CreateFileA(cfg->logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             &sa, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE nul = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                             OPEN_EXISTING, 0, NULL);
    gds_status r = GDS_EIO;
    if(log != INVALID_HANDLE_VALUE && nul != INVALID_HANDLE_VALUE) {
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof(si));
        memset(&pi, 0, sizeof(pi));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = nul;
        si.hStdOutput = log;
        si.hStdError = log;
        if(CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, block, NULL, &si, &pi)) {
            CloseHandle(pi.hThread);
            *proc = pi.hProcess;
            r = GDS_OK;
        } else {
            fprintf(stderr, "trigger %s: CreateProcess error %lu\n", cfg->argv[0],
                    (unsigned long)GetLastError());
        }
    }
    if(log != INVALID_HANDLE_VALUE)
        CloseHandle(log);
    if(nul != INVALID_HANDLE_VALUE)
        CloseHandle(nul);
    return r;
}

bool trig_child_running(void) {
    return current && WaitForSingleObject(current, 0) == WAIT_TIMEOUT;
}

gds_status trig_run(const trig_cfg *cfg, const char *user, trig_result *res) {
    memset(res, 0, sizeof(*res));
    if(!cfg->argv || !cfg->argv[0])
        return GDS_EINVAL;
    static trig_env env; /* large: keep it off the stack */
    gds_status r = build_env(&env, cfg, user);
    if(r != GDS_OK)
        return r;
    HANDLE proc = NULL;
    double t0 = now_ms();
    if((r = spawn(cfg, &env, &proc)) != GDS_OK)
        return r;
    current = proc;
    for(;;) {
        DWORD w = WaitForSingleObject(proc, 0);
        if(w == WAIT_OBJECT_0) {
            DWORD code = 0;
            res->exited = GetExitCodeProcess(proc, &code) != 0;
            res->exitStatus = (int)code;
            break;
        }
        if(w != WAIT_TIMEOUT) {
            r = GDS_EIO;
            break;
        }
        if(now_ms() - t0 > 1000.0 * ((double)cfg->timeoutSeconds + (double)cfg->runSeconds)) {
            /* no SIGTERM for an arbitrary process on Windows */
            (void)TerminateProcess(proc, 1);
            (void)WaitForSingleObject(proc, 5000);
            res->exited = false;
            break;
        }
        serve();
    }
    current = NULL;
    CloseHandle(proc);
    for(int i = 0; i < 5; i++)
        serve();
    res->ms = now_ms() - t0;
    return r;
}
#else
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

static pid_t current; /* the hook trig_run waits for, 0 if none */

bool trig_child_running(void) {
    if(current <= 0)
        return false;
    siginfo_t si;
    memset(&si, 0, sizeof(si));
    if(waitid(P_PID, (id_t)current, &si, WEXITED | WNOHANG | WNOWAIT) != 0)
        return false;
    return si.si_pid == 0;
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
    current = pid;
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
        if(now_ms() - t0 > 1000.0 * ((double)cfg->timeoutSeconds + (double)cfg->runSeconds)) {
            stop_child(pid);
            res->exited = false;
            break;
        }
        serve();
    }
    current = 0;
    /* Serve what the client sent just before it exited (CloseSession) */
    for(int i = 0; i < 5; i++)
        serve();
    res->ms = now_ms() - t0;
    return r;
}
#endif
