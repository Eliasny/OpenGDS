/* OpenGDS - in-process containment (docs/architecture.md, "Run-time
 * containment"): PR_SET_NO_NEW_PRIVS, a Landlock file system ruleset and a
 * seccomp allowlist. Applied once, after start-up has opened what it needs;
 * it cannot be undone and is inherited by threads created later.
 *
 * Landlock is skipped with a warning on kernels without it (the systemd
 * unit still applies). seccomp needs libseccomp at build time (optional,
 * GDS_HAVE_SECCOMP); without it only Landlock applies. Builds with
 * AddressSanitizer or ThreadSanitizer skip the sandbox, because their
 * runtimes read /proc and LeakSanitizer stops the process with ptrace.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_COMMON_SANDBOX_H
#define OPENGDS_COMMON_SANDBOX_H

#include <stdbool.h>
#include <stddef.h>

#include "common/compiler.h"
#include "common/errors.h"

typedef enum {
    GDS_SB_READ = 1,   /* read files and list directories */
    GDS_SB_WRITE = 2,  /* also write and truncate existing files */
    GDS_SB_CREATE = 3, /* also create, rename and remove files and directories */
} gds_sb_access;

typedef struct {
    const char *path; /* a directory (rights apply beneath it) or a file */
    gds_sb_access access;
} gds_sb_path;

/* The system calls a profile allows. Anything else fails with EPERM;
 * execve, ptrace, mount, bpf, keyctl, module loading and (for the signer)
 * socket, connect, bind and listen kill the process. The daemon may create
 * threads but no processes: clone without CLONE_THREAD fails, and clone3
 * (whose flags a filter cannot read) answers ENOSYS so libc uses clone. */
typedef enum {
    GDS_SB_SIGNER, /* files, its inherited sockets (recvmsg/sendmsg/accept) */
    GDS_SB_DAEMON, /* also threads, TCP servers (socket/bind/listen) and epoll */
} gds_sb_profile;

typedef struct {
    gds_sb_profile profile;
    const gds_sb_path *paths; /* the only file system access left */
    size_t nPaths;
    /* Landlock ABI 4+: the one TCP port the process may bind (0: none).
     * TCP connect is never allowed. */
    unsigned short tcpBindPort;
} gds_sandbox;

/* What gds_sandbox_apply() put in place, for the log and the tests. */
typedef struct {
    bool skipped;   /* a sanitizer build: nothing applied */
    int landlockAbi; /* 0 = the kernel has no Landlock */
    bool seccomp;   /* the seccomp filter is loaded */
} gds_sandbox_report;

/* Apply the sandbox to the calling process. A path that does not exist is
 * left out (with a warning); any other failure is returned and the process
 * should exit, because it may be half sandboxed. */
GDS_MUST_CHECK gds_status gds_sandbox_apply(const gds_sandbox *sb, gds_sandbox_report *report);

#endif
