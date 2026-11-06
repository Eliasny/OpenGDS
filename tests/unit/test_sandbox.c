/* OpenGDS - the in-process sandbox (common/sandbox.h). Each case runs in a
 * child process, which sends its gds_sandbox_report through a pipe and
 * then tries something: the parent checks the result against what the
 * report says was applied (no Landlock on old kernels, no seccomp without
 * libseccomp, nothing in sanitizer builds).
 * SPDX-License-Identifier: MPL-2.0 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "check.h"
#include "common/buf.h"
#include "common/sandbox.h"
#include "common/banned.h"

static char roDir[1024], rwDir[1024], outside[1024];

typedef enum { FILES, SOCKET, EXEC } action;

static bool can_open(const char *path, int flags) {
    int fd = open(path, flags | O_CLOEXEC, 0600);
    if(fd < 0)
        return false;
    (void)close(fd);
    return true;
}

/* In the child: 0 when every file and memory rule held. */
static int files_case(const gds_sandbox_report *rep) {
    char p[1100], q[1100];
    bool ll = !rep->skipped && rep->landlockAbi > 0;
    bool sc = !rep->skipped && rep->seccomp;
    if(gds_path(p, sizeof(p), "%s/data", roDir) != GDS_OK || !can_open(p, O_RDONLY))
        return 1;
    if(ll && can_open(p, O_WRONLY))
        return 2; /* read-only directory */
    if(ll && can_open(outside, O_RDONLY))
        return 3; /* a file under no rule */
    if(gds_path(p, sizeof(p), "%s/new.tmp", rwDir) != GDS_OK ||
       gds_path(q, sizeof(q), "%s/new", rwDir) != GDS_OK ||
       !can_open(p, O_WRONLY | O_CREAT | O_TRUNC) || rename(p, q) != 0 || unlink(q) != 0)
        return 4; /* the create directory allows the atomic write pattern */
    pid_t pid = fork();
    if(pid == 0)
        _exit(0);
    if(pid > 0)
        (void)waitpid(pid, NULL, 0);
    if(sc && (pid >= 0 || errno != EPERM))
        return 5; /* no new processes */
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(page == MAP_FAILED)
        return 6;
    int rc = mprotect(page, 4096, PROT_READ | PROT_EXEC);
    if(sc && rc == 0)
        return 7; /* no new executable memory */
    (void)munmap(page, 4096);
    return 0;
}

/* Fork a child that sandboxes itself, reports, and runs `a`. */
static bool run(action a, gds_sandbox_report *rep, int *status) {
    int fds[2];
    if(pipe(fds) != 0)
        return false;
    pid_t pid = fork();
    if(pid < 0) {
        (void)close(fds[0]);
        (void)close(fds[1]);
        return false;
    }
    if(pid == 0) {
        (void)close(fds[0]);
        gds_sb_path paths[] = {{roDir, GDS_SB_READ}, {rwDir, GDS_SB_CREATE}};
        gds_sandbox sb = {GDS_SB_SIGNER, paths, 2};
        gds_sandbox_report r;
        if(gds_sandbox_apply(&sb, &r) != GDS_OK)
            _exit(90);
        if(write(fds[1], &r, sizeof(r)) != (ssize_t)sizeof(r))
            _exit(91);
        (void)close(fds[1]);
        if(a == FILES)
            _exit(files_case(&r));
        if(a == SOCKET) {
            int s = socket(AF_INET, SOCK_STREAM, 0);
            _exit(s >= 0 ? 0 : 92);
        }
        char *argv[] = {"true", NULL};
        char *envp[] = {NULL};
        (void)execve("/bin/true", argv, envp);
        _exit(93);
    }
    (void)close(fds[1]);
    bool ok = read(fds[0], rep, sizeof(*rep)) == (ssize_t)sizeof(*rep);
    (void)close(fds[0]);
    ok = waitpid(pid, status, 0) == pid && ok;
    return ok;
}

static bool killed_by_seccomp(int status) {
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS;
}

static void setup(const char *dir) {
    CHECK(gds_path(roDir, sizeof(roDir), "%s/ro", dir) == GDS_OK);
    CHECK(gds_path(rwDir, sizeof(rwDir), "%s/rw", dir) == GDS_OK);
    CHECK(gds_path(outside, sizeof(outside), "%s/outside", dir) == GDS_OK);
    CHECK(gds_mkdirs(roDir, 0700) == GDS_OK && gds_mkdirs(rwDir, 0700) == GDS_OK);
    char data[1100];
    CHECK(gds_path(data, sizeof(data), "%s/data", roDir) == GDS_OK);
    CHECK(gds_file_write_atomic(data, "x", 1, 0600) == GDS_OK);
    CHECK(gds_file_write_atomic(outside, "x", 1, 0600) == GDS_OK);
}

/* socket and execve kill the process when the filter is loaded */
static void check_killed(action a) {
    gds_sandbox_report rep;
    int status = 0;
    if(CHECK(run(a, &rep, &status)))
        CHECK(rep.seccomp ? killed_by_seccomp(status) : WIFEXITED(status));
}

int main(int argc, char **argv) {
    if(argc != 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    setup(argv[1]);
    gds_sandbox_report rep;
    int status = 0;
    if(CHECK(run(FILES, &rep, &status))) {
        printf("# sandbox: skipped %d, Landlock ABI %d, seccomp %d\n", rep.skipped,
               rep.landlockAbi, rep.seccomp);
        CHECK(WIFEXITED(status));
        CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    check_killed(SOCKET);
    check_killed(EXEC);

    gds_sandbox bad = {GDS_SB_SIGNER, NULL, 1};
    CHECK(gds_sandbox_apply(&bad, NULL) == GDS_EINVAL);
    return CHECK_DONE();
}
