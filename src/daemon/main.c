/* opengdsd: the OpenGDS Global Discovery Server daemon.
 *
 *   opengdsd --config FILE
 *
 * Starts opengds-signer (when `signer` is configured) over a socketpair so
 * the CA key never enters this process (decision G1), issues the GDS's
 * own certificate through it on first start, and serves until SIGINT or
 * SIGTERM. Configuration: src/daemon/config.h.
 * SPDX-License-Identifier: MPL-2.0 */
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ca.h"
#include "ca_ipc.h"
#include "config.h"
#include "gds_server.h"
#include "own_cert.h"
#include "store.h"
#include "common/banned.h"

#define SIGNER_FD 3
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

/* Child: the socket on fd 3, nothing else inherited, then exec. */
static void exec_signer(const gdsd_config *c, int fd, const char *storePath) {
    if(fd == SIGNER_FD) {
        if(fcntl(fd, F_SETFD, 0) != 0)
            _exit(127);
    } else if(dup2(fd, SIGNER_FD) != SIGNER_FD) {
        _exit(127);
    }
    for(int i = SIGNER_FD + 1; i < 1024; i++)
        (void)close(i);
    const char *argv[16];
    int n = 0;
    argv[n++] = c->signer;
    argv[n++] = "--fd";
    argv[n++] = "3";
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
} daemon_state;

static gds_status start(daemon_state *d) {
    char storePath[GDS_MAX_PATH];
    gds_status r = gds_users_load(d->cfg.usersFile, &d->users);
    if(r != GDS_OK) {
        fprintf(stderr, "opengdsd: users file %s: %s\n", d->cfg.usersFile, gds_status_name(r));
        return r;
    }
    r = gds_mkdirs(d->cfg.dataDir, 0700);
    if(r == GDS_OK)
        r = gds_path(storePath, sizeof(storePath), "%s/opengds.db", d->cfg.dataDir);
    if(r == GDS_OK)
        r = gds_store_open(storePath, &d->store);
    if(r != GDS_OK) {
        fprintf(stderr, "opengdsd: store in %s: %s\n", d->cfg.dataDir, gds_status_name(r));
        return r;
    }
    r = d->cfg.signer[0] ? start_signer(&d->cfg, storePath, &d->signer, &d->ca)
                         : start_inprocess_ca(&d->cfg, &d->ca);
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
    sc.autoApprove = d->cfg.autoApprove;
    return gds_server_new(&sc, &d->server);
}

static void stop(daemon_state *d) {
    gds_server_delete(d->server);
    gds_ca_close(d->ca); /* closes the signer socket: the signer exits */
    if(d->signer > 0)
        (void)waitpid(d->signer, NULL, 0);
    gds_store_close(d->store);
    gds_buf_free(&d->cert);
    gds_buf_free_secret(&d->key);
}

int main(int argc, char **argv) {
    if(argc != 3 || strcmp(argv[1], "--config") != 0)
        return usage();
    umask(077);
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
        r = gds_server_run(d.server, &running);
    stop(&d);
    return r == GDS_OK ? 0 : 1;
}
