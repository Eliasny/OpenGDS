/* OpenGDS - owned byte buffers and bounded, atomic file I/O.
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "buf.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "limits.h"
#include "safeint.h"
#include "banned.h"

const char *gds_status_name(gds_status s) {
    switch(s) {
    case GDS_OK: return "ok";
    case GDS_ENOMEM: return "out of memory";
    case GDS_EOVERFLOW: return "size overflow";
    case GDS_ETOOBIG: return "input above limit";
    case GDS_EINVAL: return "invalid input";
    case GDS_ENOTFOUND: return "not found";
    case GDS_EIO: return "i/o error";
    case GDS_ECRYPTO: return "crypto error";
    case GDS_EDENIED: return "access denied";
    case GDS_ESTATE: return "invalid state";
    case GDS_EREMOTE: return "remote error";
    }
    return "unknown";
}

void gds_buf_free(gds_buf *b) {
    if(!b)
        return;
    free(b->data);
    b->data = NULL;
    b->len = 0;
}

void gds_buf_free_secret(gds_buf *b) {
    if(!b)
        return;
    if(b->data)
        OPENSSL_cleanse(b->data, b->len);
    gds_buf_free(b);
}

gds_status gds_buf_dup(const void *data, size_t len, gds_buf *out) {
    out->data = NULL;
    out->len = 0;
    if(len == 0)
        return GDS_OK;
    if(!data)
        return GDS_EINVAL;
    out->data = malloc(len);
    if(!out->data)
        return GDS_ENOMEM;
    memcpy(out->data, data, len);
    out->len = len;
    return GDS_OK;
}

gds_status gds_buf_append(gds_buf *b, const void *data, size_t len, size_t maxLen) {
    if(len == 0)
        return GDS_OK;
    size_t newLen;
    if(gds_add_size(b->len, len, &newLen))
        return GDS_EOVERFLOW;
    if(newLen > maxLen)
        return GDS_ETOOBIG;
    uint8_t *p = realloc(b->data, newLen);
    if(!p)
        return GDS_ENOMEM; /* b is unchanged and still owned by the caller */
    memcpy(p + b->len, data, len);
    b->data = p;
    b->len = newLen;
    return GDS_OK;
}

gds_status gds_file_read(const char *path, size_t maxLen, gds_buf *out) {
    out->data = NULL;
    out->len = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if(fd < 0)
        return errno == ENOENT ? GDS_ENOTFOUND : GDS_EIO;
    gds_status ret = GDS_EIO;
    struct stat st;
    if(fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0)
        goto cleanup;
    if((unsigned long long)st.st_size > maxLen) {
        ret = GDS_ETOOBIG;
        goto cleanup;
    }
    size_t n = (size_t)st.st_size;
    out->data = malloc(n ? n : 1);
    if(!out->data) {
        ret = GDS_ENOMEM;
        goto cleanup;
    }
    size_t got = 0;
    while(got < n) {
        ssize_t r = read(fd, out->data + got, n - got);
        if(r < 0 && errno == EINTR)
            continue;
        if(r <= 0)
            goto cleanup;
        got += (size_t)r;
    }
    out->len = n;
    ret = GDS_OK;
cleanup:
    close(fd);
    if(ret != GDS_OK)
        gds_buf_free(out);
    return ret;
}

gds_status gds_file_write_atomic(const char *path, const void *data, size_t len,
                                 mode_t mode) {
    char tmp[GDS_MAX_PATH];
    gds_status ret = gds_path(tmp, sizeof(tmp), "%s.tmp", path);
    if(ret != GDS_OK)
        return ret;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, mode);
    if(fd < 0)
        return GDS_EIO;
    ret = GDS_EIO;
    if(fchmod(fd, mode) != 0) /* umask must not widen or narrow the mode */
        goto cleanup;
    const uint8_t *p = data;
    size_t done = 0;
    while(done < len) {
        ssize_t w = write(fd, p + done, len - done);
        if(w < 0 && errno == EINTR)
            continue;
        if(w <= 0)
            goto cleanup;
        done += (size_t)w;
    }
    if(fsync(fd) != 0)
        goto cleanup;
    ret = GDS_OK;
cleanup:
    if(close(fd) != 0)
        ret = GDS_EIO;
    if(ret == GDS_OK && rename(tmp, path) != 0)
        ret = GDS_EIO;
    if(ret != GDS_OK)
        unlink(tmp);
    return ret;
}

gds_status gds_mkdirs(const char *path, mode_t mode) {
    char tmp[GDS_MAX_PATH];
    gds_status ret = gds_path(tmp, sizeof(tmp), "%s", path);
    if(ret != GDS_OK)
        return ret;
    for(char *p = tmp + 1; *p; p++) {
        if(*p != '/')
            continue;
        *p = '\0';
        if(mkdir(tmp, mode) != 0 && errno != EEXIST)
            return GDS_EIO;
        *p = '/';
    }
    if(mkdir(tmp, mode) != 0 && errno != EEXIST)
        return GDS_EIO;
    return GDS_OK;
}

gds_status gds_path(char *out, size_t outLen, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out, outLen, fmt, ap);
    va_end(ap);
    if(n < 0 || (size_t)n >= outLen) {
        if(outLen > 0)
            out[0] = '\0';
        return GDS_ETOOBIG;
    }
    return GDS_OK;
}

gds_status gds_hex(const uint8_t *data, size_t len, char *out, size_t outLen) {
    static const char digits[] = "0123456789ABCDEF";
    size_t need;
    if(gds_mul_size(len, 2, &need) || gds_add_size(need, 1, &need))
        return GDS_EOVERFLOW;
    if(need > outLen)
        return GDS_ETOOBIG;
    for(size_t i = 0; i < len; i++) {
        out[2 * i] = digits[data[i] >> 4];
        out[2 * i + 1] = digits[data[i] & 0x0F];
    }
    out[2 * len] = '\0';
    return GDS_OK;
}
