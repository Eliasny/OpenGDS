/* opengds-signer: holds the CA key, signs only what the store says was
 * requested (decision G1; docs/architecture.md "Split by privilege").
 *
 *   opengds-signer --fd N --store PATH --ca-dir DIR [--organization O]
 *                  [--passphrase-file F] [--plugin-fd N]
 *
 * --fd is a connected SOCK_SEQPACKET socket to opengdsd (inherited, or from
 * systemd socket activation). The CA key passphrase comes from
 * --passphrase-file or $CREDENTIALS_DIRECTORY/ca-passphrase (systemd
 * LoadCredentialEncrypted=); never from argv or the environment.
 * Sandboxing (seccomp, Landlock) follows in the MVP milestone.
 * SPDX-License-Identifier: MPL-2.0 */
#include <openssl/crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>

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
    const char *store, *caDir, *organization, *passFile;
} options;

static int usage(void) {
    fprintf(stderr, "usage: opengds-signer --fd N --store PATH --ca-dir DIR "
                    "[--organization O] [--passphrase-file F] [--plugin-fd N]\n");
    return 2;
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
        if(strcmp(a, "--fd") == 0)
            ok = gds_parse_long(v, 0, 65535, &o->fd);
        else if(strcmp(a, "--plugin-fd") == 0)
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
    return o->fd >= 0 && o->store && o->caDir;
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

int main(int argc, char **argv) {
    options o;
    if(!parse_args(argc, argv, &o))
        return usage();
    umask(077);
    /* private key material lives in OpenSSL's secure heap (mlock'd, guarded) */
    if(CRYPTO_secure_malloc_init(SECURE_HEAP_BYTES, 32) == 0)
        fprintf(stderr, "opengds-signer: secure heap unavailable, continuing without it\n");
    if(!is_seqpacket((int)o.fd)) {
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
        r = gds_signer_serve(&s, (int)o.fd);
    gds_ca_close(s.ca);
    gds_store_close(s.store);
    return r == GDS_OK ? 0 : 1;
}
