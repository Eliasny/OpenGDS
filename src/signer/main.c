/* opengds-signer: holds the CA key, signs only what the store says was
 * requested (decision G1; docs/architecture.md "Split by privilege").
 *
 *   opengds-signer (--fd N | --listen PATH) --store PATH --ca-dir DIR
 *                  [--organization O] [--passphrase-file F] [--plugin-fd N]
 *
 * --fd is a connected SOCK_SEQPACKET socket to opengdsd: inherited from
 * opengdsd (`signer` in its configuration), or `--fd systemd` for socket
 * activation (opengds-signer.socket with Accept=yes, one instance per
 * opengdsd connection). --listen PATH is for hosts without systemd (e.g. a
 * signer container sharing a socket volume with opengdsd): the signer
 * creates a SOCK_SEQPACKET socket at PATH (mode 0660; the directory's
 * permissions decide who may reach it) and serves one connection at a time,
 * each until it closes. The CA key passphrase comes from
 * --passphrase-file or $CREDENTIALS_DIRECTORY/ca-passphrase (systemd
 * LoadCredentialEncrypted=); never from argv or the environment.
 * Sandboxing (seccomp, Landlock) follows in the MVP milestone.
 * SPDX-License-Identifier: MPL-2.0 */
#include <openssl/crypto.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "ca.h"
#include "common/buf.h"
#include "common/limits.h"
#include "common/safeint.h"
#include "signer.h"
#include "store.h"
#include "common/banned.h"

#define SECURE_HEAP_BYTES 65536
#define MAX_PASSPHRASE 1024

typedef struct {
    long fd, pluginFd;
    const char *store, *caDir, *organization, *passFile, *listen;
} options;

static int usage(void) {
    fprintf(stderr, "usage: opengds-signer (--fd N | --listen PATH) --store PATH --ca-dir DIR "
                    "[--organization O] [--passphrase-file F] [--plugin-fd N]\n");
    return 2;
}

/* Socket activation (sd_listen_fds protocol, opengds-signer.socket with
 * Accept=yes): exactly one connected socket on fd 3, meant for this pid. */
static bool systemd_fd(long *fd) {
    long pid = 0, n = 0;
    const char *ep = getenv("LISTEN_PID"); /* not secrets: process ids */
    const char *en = getenv("LISTEN_FDS");
    if(!ep || !en || !gds_parse_long(ep, 1, 0x7fffffffL, &pid) || !gds_parse_long(en, 1, 1, &n) ||
       pid != (long)getpid())
        return false;
    *fd = 3; /* SD_LISTEN_FDS_START */
    return true;
}

static bool parse_args(int argc, char **argv, options *o) {
    memset(o, 0, sizeof(*o));
    o->fd = -1;
    o->pluginFd = -1;
    for(int i = 1; i < argc; i += 2) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if(!v)
            return false;
        bool ok = true;
        if(strcmp(a, "--fd") == 0 && strcmp(v, "systemd") == 0)
            ok = systemd_fd(&o->fd);
        else if(strcmp(a, "--fd") == 0)
            ok = gds_parse_long(v, 0, 65535, &o->fd);
        else if(strcmp(a, "--listen") == 0) {
            ok = !o->listen && v[0] == '/';
            o->listen = v;
        } else if(strcmp(a, "--plugin-fd") == 0)
            ok = gds_parse_long(v, 0, 65535, &o->pluginFd);
        else if(strcmp(a, "--store") == 0)
            o->store = v;
        else if(strcmp(a, "--ca-dir") == 0)
            o->caDir = v;
        else if(strcmp(a, "--organization") == 0)
            o->organization = v;
        else if(strcmp(a, "--passphrase-file") == 0)
            o->passFile = v;
        else
            ok = false;
        if(!ok)
            return false;
    }
    return (o->fd >= 0) != (o->listen != NULL) && o->store && o->caDir;
}

static gds_status read_passphrase(const char *file, gds_buf *out) {
    char path[GDS_MAX_PATH];
    if(!file) {
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

static bool is_seqpacket(int fd) {
    int type = 0;
    socklen_t len = sizeof(type);
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) == 0 && type == SOCK_SEQPACKET;
}

static gds_status open_ca(const options *o, gds_ca **ca) {
    gds_buf pass = {0};
    gds_status r = read_passphrase(o->passFile, &pass);
    if(r != GDS_OK) {
        fprintf(stderr, "opengds-signer: CA key passphrase: %s\n", gds_status_name(r));
        return r;
    }
    gds_ca_config cfg;
    gds_ca_config_init(&cfg);
    cfg.dir = o->caDir;
    cfg.organization = o->organization;
    cfg.keyPassphrase = &pass;
    cfg.pluginFd = (int)o->pluginFd;
    r = gds_ca_openssl_open(&cfg, ca);
    gds_buf_free_secret(&pass);
    if(r != GDS_OK)
        fprintf(stderr, "opengds-signer: CA in %s: %s\n", o->caDir, gds_status_name(r));
    return r;
}

/* --listen: a fresh socket at path; a stale one (a previous run) is replaced. */
static int listen_at(const char *path) {
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    size_t n = strlen(path);
    if(n >= sizeof(a.sun_path)) {
        fprintf(stderr, "opengds-signer: --listen %s: path too long\n", path);
        return -1;
    }
    memcpy(a.sun_path, path, n + 1);
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if(fd < 0)
        return -1;
    struct stat st;
    if(lstat(path, &st) == 0 && S_ISSOCK(st.st_mode))
        (void)unlink(path);
    /* 0660 from the start: no window where the socket is more open */
    mode_t old = umask(0117);
    int ok = bind(fd, (const struct sockaddr *)&a, sizeof(a));
    umask(old);
    if(ok != 0 || listen(fd, 4) != 0) {
        fprintf(stderr, "opengds-signer: --listen %s: cannot bind\n", path);
        (void)close(fd);
        return -1;
    }
    return fd;
}

/* One opengdsd at a time; each connection is served until it closes. A
 * failed connection (protocol error, peer gone) ends that connection only. */
static gds_status serve_listen(gds_signer *s, int lfd) {
    for(;;) {
        int c = accept(lfd, NULL, NULL); /* the signer never execs */
        if(c < 0) {
            if(errno == EINTR || errno == ECONNABORTED)
                continue;
            return GDS_EIO;
        }
        gds_status r = gds_signer_serve(s, c);
        if(r != GDS_OK)
            fprintf(stderr, "opengds-signer: connection ended: %s\n", gds_status_name(r));
        (void)close(c);
    }
}

int main(int argc, char **argv) {
    options o;
    if(!parse_args(argc, argv, &o))
        return usage();
    umask(077);
    /* private key material lives in OpenSSL's secure heap (mlock'd, guarded) */
    if(CRYPTO_secure_malloc_init(SECURE_HEAP_BYTES, 32) == 0)
        fprintf(stderr, "opengds-signer: secure heap unavailable, continuing without it\n");
    int lfd = -1;
    if(o.listen) {
        lfd = listen_at(o.listen);
        if(lfd < 0)
            return 1;
    } else if(!is_seqpacket((int)o.fd)) {
        fprintf(stderr, "opengds-signer: --fd %ld is not a SOCK_SEQPACKET socket\n", o.fd);
        return 2;
    }
    gds_signer s = {NULL, NULL};
    gds_status r = gds_store_open_readonly(o.store, &s.store);
    if(r != GDS_OK) {
        fprintf(stderr, "opengds-signer: store %s: %s\n", o.store, gds_status_name(r));
        return 1;
    }
    r = open_ca(&o, &s.ca);
    if(r == GDS_OK)
        r = o.listen ? serve_listen(&s, lfd) : gds_signer_serve(&s, (int)o.fd);
    gds_ca_close(s.ca);
    gds_store_close(s.store);
    if(lfd >= 0)
        (void)close(lfd);
    return r == GDS_OK ? 0 : 1;
}
