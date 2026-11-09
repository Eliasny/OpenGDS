/* opengdsd: the OpenGDS Global Discovery Server daemon.
 *
 *   opengdsd --config FILE
 *
 * Starts opengds-signer (when `signer` is configured) over a socketpair so
 * the CA key never enters this process (decision G1), issues the GDS's
 * own certificate through it on first start, and serves until SIGINT or
 * SIGTERM. Once started it sandboxes itself (common/sandbox.h: Landlock,
 * seccomp; docs/opengdsd.md). Configuration: src/daemon/config.h.
 * SPDX-License-Identifier: MPL-2.0 */
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ca.h"
#include "ca_ipc.h"
#include "config.h"
#include "gds_server.h"
#include "own_cert.h"
#include "push_engine.h"
#include "store.h"
#include "common/sandbox.h"
#include "common/banned.h"

#define SIGNER_TIMEOUT_MS 30000
#define MAX_PASSPHRASE 1024
#define HOST_MAX 256

static volatile UA_Boolean running = true;

static void on_signal(int sig) {
    (void)sig;
    running = false;
}

static int usage(void) {
    fprintf(stderr, "usage: opengdsd --config FILE\n");
    return 2;
}

/* Child: the socket is the only descriptor that survives exec (everything
 * else is O_CLOEXEC or closed here); its number goes to --fd. */
static void exec_signer(const gdsd_config *c, int fd, const char *storePath) {
    if(fcntl(fd, F_SETFD, 0) != 0)
        _exit(127);
    for(int i = 3; i < 1024; i++)
        if(i != fd)
            (void)close(i);
    char fdArg[16];
    if(gds_path(fdArg, sizeof(fdArg), "%d", fd) != GDS_OK)
        _exit(127);
    const char *argv[16];
    int n = 0;
    argv[n++] = c->signer;
    argv[n++] = "--fd";
    argv[n++] = fdArg;
    argv[n++] = "--store";
    argv[n++] = storePath;
    argv[n++] = "--ca-dir";
    argv[n++] = c->caDir;
    if(c->organization[0]) {
        argv[n++] = "--organization";
        argv[n++] = c->organization;
    }
    if(c->caPassphraseFile[0]) {
        argv[n++] = "--passphrase-file"; /* a path; the secret stays in the file */
        argv[n++] = c->caPassphraseFile;
    }
    argv[n] = NULL;
    execv(c->signer, (char *const *)(uintptr_t)argv);
    _exit(127);
}

static gds_status start_signer(const gdsd_config *c, const char *storePath, pid_t *pid,
                               gds_ca **ca) {
    int sv[2];
    if(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) != 0)
        return GDS_EIO;
    *pid = fork();
    if(*pid < 0) {
        (void)close(sv[0]);
        (void)close(sv[1]);
        return GDS_EIO;
    }
    if(*pid == 0) {
        (void)close(sv[0]);
        exec_signer(c, sv[1], storePath);
    }
    (void)close(sv[1]);
    return gds_ca_ipc_open(sv[0], SIGNER_TIMEOUT_MS, ca);
}

/* A signer started by systemd (opengds-signer.socket, Accept=yes): one
 * connection is one signer instance. Only the opengds and opengds-ca users
 * can open the socket (SocketMode=0660). */
static gds_status connect_signer(const char *path, gds_ca **ca) {
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    size_t n = strlen(path);
    if(n >= sizeof(a.sun_path))
        return GDS_ETOOBIG;
    memcpy(a.sun_path, path, n + 1);
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if(fd < 0)
        return GDS_EIO;
    if(connect(fd, (const struct sockaddr *)&a, sizeof(a)) != 0) {
        fprintf(stderr, "opengdsd: signer socket %s: cannot connect\n", path);
        (void)close(fd);
        return GDS_EREMOTE;
    }
    return gds_ca_ipc_open(fd, SIGNER_TIMEOUT_MS, ca);
}

static gds_status read_passphrase(const char *file, gds_buf *out) {
    char path[GDS_MAX_PATH];
    if(!file[0]) {
        const char *creds = getenv("CREDENTIALS_DIRECTORY"); /* a directory, not a secret */
        if(!creds || gds_path(path, sizeof(path), "%s/ca-passphrase", creds) != GDS_OK)
            return GDS_ENOTFOUND;
        file = path;
    }
    gds_status r = gds_file_read(file, MAX_PASSPHRASE, out);
    while(r == GDS_OK && out->len > 0 &&
          (out->data[out->len - 1] == '\n' || out->data[out->len - 1] == '\r'))
        out->len--;
    if(r == GDS_OK && out->len == 0) {
        gds_buf_free_secret(out);
        r = GDS_EINVAL;
    }
    return r;
}

/* Development only: the CA key in this process. */
static gds_status start_inprocess_ca(const gdsd_config *c, gds_ca **ca) {
    fprintf(stderr, "opengdsd: no signer configured; the CA key is held by opengdsd "
                    "(not for production, decision G1)\n");
    gds_buf pass = {0};
    gds_status r = read_passphrase(c->caPassphraseFile, &pass);
    if(r != GDS_OK) {
        fprintf(stderr, "opengdsd: CA key passphrase: %s\n", gds_status_name(r));
        return r;
    }
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = c->caDir;
    cc.organization = c->organization[0] ? c->organization : NULL;
    cc.keyPassphrase = &pass;
    r = gds_ca_openssl_open(&cc, ca);
    gds_buf_free_secret(&pass);
    return r;
}

static void install_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGINT, &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = SIG_IGN;
    (void)sigaction(SIGPIPE, &sa, NULL);
}

static const char *endpoint_host(const gdsd_config *c, char *buf, size_t len) {
    if(c->hostname[0])
        return c->hostname;
    if(c->loopbackOnly)
        return "localhost";
    if(gethostname(buf, len) == 0) {
        buf[len - 1] = '\0';
        return buf;
    }
    return "localhost";
}

typedef struct {
    gdsd_config cfg;
    gds_users users;
    gds_store *store;
    gds_ca *ca;
    pid_t signer;
    gds_buf cert, key;
    gds_server *server;
    push_engine *push;
    gds_buf issuers[GDS_CA_ISSUERS];
    size_t issuersN;
} daemon_state;

static gds_status start(daemon_state *d) {
    char storePath[GDS_MAX_PATH];
    gds_status r = gds_users_load(d->cfg.usersFile, &d->users);
    if(r != GDS_OK) {
        fprintf(stderr, "opengdsd: users file %s: %s\n", d->cfg.usersFile, gds_status_name(r));
        return r;
    }
    r = gds_mkdirs(d->cfg.dataDir, 0750);
    if(r == GDS_OK)
        r = gds_path(storePath, sizeof(storePath), "%s/opengds.db", d->cfg.dataDir);
    if(r == GDS_OK)
        r = gds_store_open(storePath, &d->store);
    if(r != GDS_OK) {
        fprintf(stderr, "opengdsd: store in %s: %s\n", d->cfg.dataDir, gds_status_name(r));
        return r;
    }
    if(d->cfg.signerSocket[0])
        r = connect_signer(d->cfg.signerSocket, &d->ca);
    else if(d->cfg.signer[0])
        r = start_signer(&d->cfg, storePath, &d->signer, &d->ca);
    else
        r = start_inprocess_ca(&d->cfg, &d->ca);
    if(r != GDS_OK) {
        fprintf(stderr, "opengdsd: CA: %s\n", gds_status_name(r));
        return r;
    }
    char hostBuf[HOST_MAX];
    gdsd_own_params op = {d->cfg.dataDir, d->cfg.applicationUri, d->cfg.applicationName,
                          d->cfg.productUri, endpoint_host(&d->cfg, hostBuf, sizeof(hostBuf)),
                          d->cfg.port};
    r = gdsd_own_cert(&op, d->store, d->ca, &d->cert, &d->key);
    if(r != GDS_OK) {
        fprintf(stderr, "opengdsd: own certificate: %s\n", gds_status_name(r));
        return r;
    }
    gds_server_config sc = {0};
    sc.port = d->cfg.port;
    sc.hostname = d->cfg.hostname[0] ? d->cfg.hostname : NULL;
    sc.loopbackOnly = d->cfg.loopbackOnly;
    sc.applicationUri = d->cfg.applicationUri;
    sc.productUri = d->cfg.productUri;
    sc.applicationName = d->cfg.applicationName;
    sc.ownCert = d->cert;
    sc.ownKey = d->key;
    sc.store = d->store;
    sc.ca = d->ca;
    sc.users = &d->users;
    sc.approval = (gds_approval_policy)d->cfg.approval; /* same values, config.h */
    return gds_server_new(&sc, &d->server);
}

/* The push engine (docs/push.md "Scheduled pushes"), after the sandbox */
static gds_status start_push(daemon_state *d) {
    if(!d->cfg.push)
        return GDS_OK;
    push_engine_cfg pc;
    memset(&pc, 0, sizeof(pc));
    pc.server = d->server;
    pc.cert = d->cert;
    pc.key = d->key;
    for(unsigned i = 0; i < GDS_CA_ISSUERS; i++)
        if(gds_ca_get_issuer_cert(d->ca, (gds_ca_issuer)i, &d->issuers[d->issuersN]) == GDS_OK)
            d->issuersN++;
    pc.issuers = d->issuers;
    pc.issuersN = d->issuersN;
    pc.tickMs = d->cfg.pushIntervalS * 1000u;
    pc.concurrency = d->cfg.pushConcurrency;
    pc.jitterS = d->cfg.pushJitterS;
    pc.backoffMinS = d->cfg.pushBackoffMinS;
    pc.backoffMaxS = d->cfg.pushBackoffMaxS;
    pc.rejectedS = d->cfg.pushRejectedS;
    gds_status r = push_engine_start(&pc, &d->push);
    if(r != GDS_OK)
        fprintf(stderr, "opengdsd: push engine: %s\n", gds_status_name(r));
    return r;
}

static void stop(daemon_state *d) {
    push_engine_stop(d->push); /* before the server it uses */
    for(size_t i = 0; i < d->issuersN; i++)
        gds_buf_free(&d->issuers[i]);
    gds_server_delete(d->server);
    gds_ca_close(d->ca); /* closes the signer socket: the signer exits */
    if(d->signer > 0)
        (void)waitpid(d->signer, NULL, 0);
    gds_store_close(d->store);
    gds_buf_free(&d->cert);
    gds_buf_free_secret(&d->key);
}

/* System files the server still reads after start-up: name resolution for
 * its endpoint host, and the time zone for log lines. */
static const char *const systemFiles[] = {
    "/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/host.conf",
    "/etc/gai.conf", "/etc/localtime",
};

#define MAX_SB_PATHS 10

/* After start-up: the data directory, the CA directory (in-process CA
 * only), the configuration and users files, and the system files above.
 * TCP: bind on the configured port only; connect to any port only when
 * the push engine runs (it connects to the managed Servers). */
static gds_status sandbox(const daemon_state *d, const char *configPath) {
    gds_sb_path paths[MAX_SB_PATHS];
    size_t n = 0;
    paths[n++] = (gds_sb_path){d->cfg.dataDir, GDS_SB_CREATE};
    if(!d->cfg.signer[0] && !d->cfg.signerSocket[0])
        paths[n++] = (gds_sb_path){d->cfg.caDir, GDS_SB_CREATE};
    paths[n++] = (gds_sb_path){configPath, GDS_SB_READ};
    paths[n++] = (gds_sb_path){d->cfg.usersFile, GDS_SB_READ};
    for(size_t i = 0; i < sizeof(systemFiles) / sizeof(systemFiles[0]) && n < MAX_SB_PATHS; i++)
        if(access(systemFiles[i], F_OK) == 0)
            paths[n++] = (gds_sb_path){systemFiles[i], GDS_SB_READ};
    gds_sandbox sb = {.profile = GDS_SB_DAEMON, .paths = paths, .nPaths = n,
                      .tcpBindPort = d->cfg.port, .tcpConnect = d->cfg.push};
    gds_sandbox_report rep;
    gds_status r = gds_sandbox_apply(&sb, &rep);
    if(r != GDS_OK)
        fprintf(stderr, "opengdsd: sandbox: %s\n", gds_status_name(r));
    else if(!rep.skipped)
        fprintf(stderr, "opengdsd: sandbox: Landlock ABI %d, seccomp %s\n", rep.landlockAbi,
                rep.seccomp ? "on" : "not built in");
    return r;
}

int main(int argc, char **argv) {
    if(argc != 3 || strcmp(argv[1], "--config") != 0)
        return usage();
    /* The store is group-readable: with signer_socket the signer runs as its
     * own user in the daemon's group and re-reads every request it signs.
     * Keys are written 0600 explicitly, data_dir/own is 0700. */
    umask(027);
    install_signals();
    static daemon_state d;
    unsigned line = 0;
    gds_status r = gdsd_config_load(argv[2], &d.cfg, &line);
    if(r != GDS_OK) {
        if(line)
            fprintf(stderr, "opengdsd: %s:%u: invalid line\n", argv[2], line);
        else
            fprintf(stderr, "opengdsd: %s: %s (application_uri, data_dir, users_file and "
                            "ca_dir are required)\n", argv[2], gds_status_name(r));
        return 2;
    }
    r = start(&d);
    if(r == GDS_OK)
        r = sandbox(&d, argv[2]);
    if(r == GDS_OK)
        r = start_push(&d);
    if(r == GDS_OK)
        r = gds_server_run(d.server, &running);
    stop(&d);
    return r == GDS_OK ? 0 : 1;
}
