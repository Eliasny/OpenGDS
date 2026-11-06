/* OpenGDS fuzz targets - shared fixture helpers (see fuzz.h).
 * SPDX-License-Identifier: MPL-2.0 */
#define _XOPEN_SOURCE 700
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "common/limits.h"
#include "fuzz.h"
#include "common/banned.h"

static char tmpRoot[GDS_MAX_PATH];

static int remove_entry(const char *path, const struct stat *sb, int flag, struct FTW *ftw) {
    (void)sb, (void)flag, (void)ftw;
    return remove(path);
}

static void remove_tmp(void) {
    if(tmpRoot[0])
        (void)nftw(tmpRoot, remove_entry, 16, FTW_DEPTH | FTW_PHYS);
    tmpRoot[0] = '\0';
}

gds_status fuzz_tmpdir(char *out, size_t outLen) {
    if(tmpRoot[0])
        return GDS_ESTATE;
    const char *base = getenv("TMPDIR");
    if(!base || base[0] != '/')
        base = "/tmp";
    gds_status r = gds_path(tmpRoot, sizeof(tmpRoot), "%s/opengds-fuzz-XXXXXX", base);
    if(r != GDS_OK)
        return r;
    if(!mkdtemp(tmpRoot)) {
        tmpRoot[0] = '\0';
        return GDS_EIO;
    }
    if(atexit(remove_tmp) != 0) {
        remove_tmp();
        return GDS_ENOMEM;
    }
    return gds_path(out, outLen, "%s", tmpRoot);
}

const uint8_t *fuzz_passphrase(size_t *len) {
    static const uint8_t pass[] = "opengds-fuzz-fixture-passphrase";
    *len = sizeof(pass) - 1;
    return pass;
}

gds_status fuzz_make_csr(gds_buf *out) {
    memset(out, 0, sizeof(*out));
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    X509_REQ *req = X509_REQ_new();
    gds_status r = GDS_ECRYPTO;
    int len = 0;
    if(key && req && X509_REQ_set_pubkey(req, key) == 1 &&
       X509_REQ_sign(req, key, EVP_sha256()) > 0)
        len = i2d_X509_REQ(req, NULL);
    if(len > 0) {
        out->data = malloc((size_t)len);
        unsigned char *p = out->data;
        r = !out->data ? GDS_ENOMEM : i2d_X509_REQ(req, &p) == len ? GDS_OK : GDS_ECRYPTO;
    }
    if(r == GDS_OK)
        out->len = (size_t)len;
    else
        gds_buf_free(out);
    X509_REQ_free(req);
    EVP_PKEY_free(key);
    return r;
}
