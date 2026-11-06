/* OpenGDS - in-process containment (sandbox.h).
 * SPDX-License-Identifier: MPL-2.0 */
#define _GNU_SOURCE /* O_PATH */
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifdef GDS_HAVE_SECCOMP
#include <seccomp.h>
#endif

#include "common/sandbox.h"
#include "common/banned.h"

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define SANITIZER_BUILD 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#define SANITIZER_BUILD 1
#endif
#endif
#ifndef SANITIZER_BUILD
#define SANITIZER_BUILD 0
#endif

/* ---- Landlock ---- */

/* Rights by ABI version; newer kernels than the headers are handled here,
 * so a build on old headers still uses what the running kernel offers. */
#define LL_FS_ABI1 ((1ULL << 13) - 1) /* EXECUTE .. MAKE_SYM */
#define LL_FS_REFER (1ULL << 13)       /* ABI 2 */
#define LL_FS_TRUNCATE (1ULL << 14)    /* ABI 3 */
#define LL_FS_IOCTL_DEV (1ULL << 15)   /* ABI 5 */
#define LL_NET_ALL 3ULL                /* ABI 4: BIND_TCP | CONNECT_TCP */
#define LL_SCOPE_ALL 3ULL              /* ABI 6: abstract UNIX sockets, signals */

#define LL_READ (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)
#define LL_WRITE (LL_READ | LANDLOCK_ACCESS_FS_WRITE_FILE | LL_FS_TRUNCATE)
#define LL_CREATE                                                                               \
    (LL_WRITE | LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |                \
     LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG)
#define LL_FILE_RIGHTS                                                                          \
    (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE | LL_FS_TRUNCATE |            \
     LANDLOCK_ACCESS_FS_EXECUTE | LL_FS_IOCTL_DEV)

typedef struct {
    uint64_t fs, net, scoped;
} ll_ruleset_attr; /* struct landlock_ruleset_attr of ABI 6, sized per ABI */

static int ll_abi(void) {
    long v = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    return v > 0 ? (int)v : 0;
}

static uint64_t ll_handled_fs(int abi) {
    uint64_t fs = LL_FS_ABI1;
    if(abi >= 2)
        fs |= LL_FS_REFER;
    if(abi >= 3)
        fs |= LL_FS_TRUNCATE;
    if(abi >= 5)
        fs |= LL_FS_IOCTL_DEV;
    return fs;
}

static gds_status ll_add(int rs, const gds_sb_path *p, uint64_t handled) {
    uint64_t want = p->access == GDS_SB_CREATE  ? LL_CREATE
                    : p->access == GDS_SB_WRITE ? LL_WRITE
                                                : LL_READ;
    int fd = open(p->path, O_PATH | O_CLOEXEC);
    if(fd < 0) {
        fprintf(stderr, "opengds: sandbox: %s does not exist, left out\n", p->path);
        return GDS_OK;
    }
    struct stat st;
    gds_status r = GDS_OK;
    if(fstat(fd, &st) != 0) {
        r = GDS_EIO;
    } else {
        if(!S_ISDIR(st.st_mode))
            want &= LL_FILE_RIGHTS; /* directory rights are refused on a file */
        struct landlock_path_beneath_attr pb = {.allowed_access = want & handled, .parent_fd = fd};
        if(syscall(SYS_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) != 0)
            r = GDS_EIO;
    }
    (void)close(fd);
    if(r != GDS_OK)
        fprintf(stderr, "opengds: sandbox: Landlock rule for %s: %s\n", p->path, strerror(errno));
    return r;
}

static gds_status apply_landlock(const gds_sandbox *sb, int *abiOut) {
    int abi = ll_abi();
    *abiOut = abi;
    if(abi == 0) {
        fprintf(stderr, "opengds: sandbox: the kernel has no Landlock; file access is not "
                        "restricted in the process\n");
        return GDS_OK;
    }
    ll_ruleset_attr attr = {ll_handled_fs(abi), LL_NET_ALL, LL_SCOPE_ALL};
    size_t size = abi >= 6 ? sizeof(attr) : abi >= 4 ? 2 * sizeof(uint64_t) : sizeof(uint64_t);
    long rs = syscall(SYS_landlock_create_ruleset, &attr, size, 0);
    if(rs < 0) {
        fprintf(stderr, "opengds: sandbox: Landlock ruleset: %s\n", strerror(errno));
        return GDS_EIO;
    }
    gds_status r = GDS_OK;
    for(size_t i = 0; r == GDS_OK && i < sb->nPaths; i++)
        r = ll_add((int)rs, &sb->paths[i], attr.fs);
    if(r == GDS_OK && syscall(SYS_landlock_restrict_self, rs, 0) != 0) {
        fprintf(stderr, "opengds: sandbox: Landlock restrict: %s\n", strerror(errno));
        r = GDS_EIO;
    }
    (void)close((int)rs);
    return r;
}

/* ---- seccomp ---- */

#ifdef GDS_HAVE_SECCOMP
/* What the signer calls after start-up: files in its directories, its
 * inherited sockets, memory, time and randomness. */
static const char *const signerAllow[] = {
    "read", "write", "readv", "writev", "pread64", "pwrite64", "lseek", "close",
    "fstat", "newfstatat", "statx", "stat", "lstat", "openat", "open", "fcntl",
    "fsync", "fdatasync", "ftruncate", "rename", "renameat", "renameat2", "unlink", "unlinkat",
    "mkdir", "mkdirat", "fchmod", "fchown", "getcwd", "readlink", "readlinkat", "access",
    "faccessat", "faccessat2", "sendmsg", "recvmsg", "sendto", "recvfrom", "getsockopt",
    "accept", "accept4", "shutdown", "poll", "ppoll", "munmap", "mremap", "madvise", "brk",
    "futex", "getrandom", "clock_gettime", "clock_nanosleep", "nanosleep", "gettimeofday",
    "time", "exit", "exit_group", "rt_sigreturn", "rt_sigprocmask", "rt_sigaction",
    "sigaltstack", "getpid", "gettid", "getuid", "geteuid", "getgid", "getegid", "tgkill",
    "sched_yield", "uname", "sysinfo", "prlimit64", "restart_syscall", "flock",
};

/* Never needed; their use means the process was taken over. */
static const char *const killAlways[] = {
    "execve", "execveat", "ptrace", "process_vm_readv", "process_vm_writev", "mount",
    "umount2", "pivot_root", "chroot", "bpf", "keyctl", "add_key", "request_key",
    "init_module", "finit_module", "delete_module", "kexec_load", "kexec_file_load",
    "perf_event_open", "userfaultfd", "unshare", "setns", "personality",
};
static const char *const signerKill[] = {"socket", "socketpair", "connect", "bind", "listen"};

static gds_status add_names(scmp_filter_ctx ctx, uint32_t action, const char *const *names,
                            size_t n) {
    for(size_t i = 0; i < n; i++) {
        int nr = seccomp_syscall_resolve_name(names[i]);
        if(nr == __NR_SCMP_ERROR)
            continue; /* not on this architecture */
        if(seccomp_rule_add(ctx, action, nr, 0) != 0) {
            fprintf(stderr, "opengds: sandbox: seccomp rule for %s\n", names[i]);
            return GDS_EIO;
        }
    }
    return GDS_OK;
}

/* mmap and mprotect only without PROT_EXEC: no new executable memory. */
static gds_status add_noexec(scmp_filter_ctx ctx) {
    int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 1,
                              SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, 0));
    if(rc == 0)
        rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 1,
                              SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, 0));
    return rc == 0 ? GDS_OK : GDS_EIO;
}

static gds_status apply_seccomp(const gds_sandbox *sb) {
    if(sb->profile != GDS_SB_SIGNER)
        return GDS_EINVAL;
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    if(!ctx)
        return GDS_ENOMEM;
    gds_status r = add_names(ctx, SCMP_ACT_ALLOW, signerAllow,
                             sizeof(signerAllow) / sizeof(signerAllow[0]));
    if(r == GDS_OK)
        r = add_noexec(ctx);
    if(r == GDS_OK)
        r = add_names(ctx, SCMP_ACT_KILL_PROCESS, killAlways,
                      sizeof(killAlways) / sizeof(killAlways[0]));
    if(r == GDS_OK)
        r = add_names(ctx, SCMP_ACT_KILL_PROCESS, signerKill,
                      sizeof(signerKill) / sizeof(signerKill[0]));
    if(r == GDS_OK && seccomp_load(ctx) != 0) {
        fprintf(stderr, "opengds: sandbox: loading the seccomp filter failed\n");
        r = GDS_EIO;
    }
    seccomp_release(ctx);
    return r;
}
#endif

gds_status gds_sandbox_apply(const gds_sandbox *sb, gds_sandbox_report *report) {
    gds_sandbox_report rep;
    memset(&rep, 0, sizeof(rep));
    if(!sb || (sb->nPaths > 0 && !sb->paths))
        return GDS_EINVAL;
    if(SANITIZER_BUILD) {
        rep.skipped = true;
        fprintf(stderr, "opengds: sandbox: skipped in a sanitizer build\n");
        if(report)
            *report = rep;
        return GDS_OK;
    }
    if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return GDS_EIO;
    gds_status r = apply_landlock(sb, &rep.landlockAbi);
#ifdef GDS_HAVE_SECCOMP
    if(r == GDS_OK)
        r = apply_seccomp(sb);
    rep.seccomp = r == GDS_OK;
#endif
    if(report)
        *report = rep;
    return r;
}
