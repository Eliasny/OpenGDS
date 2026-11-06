/* OpenGDS - owned byte buffers and bounded, atomic file I/O.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Ownership: a gds_buf owns its data (malloc'd). gds_buf_free() frees it and
 * zeroes the struct; calling it on a zeroed struct is a no-op. Functions
 * with a `gds_buf *out` parameter initialise *out; the caller frees it. */
#ifndef OPENGDS_COMMON_BUF_H
#define OPENGDS_COMMON_BUF_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "compiler.h"
#include "errors.h"

typedef struct {
    uint8_t *data;
    size_t len;
} gds_buf;

void gds_buf_free(gds_buf *b);
/* Like gds_buf_free, but wipes the bytes first (keys, passwords). */
void gds_buf_free_secret(gds_buf *b);
GDS_MUST_CHECK gds_status gds_buf_dup(const void *data, size_t len, gds_buf *out);
GDS_MUST_CHECK gds_status gds_buf_append(gds_buf *b, const void *data, size_t len,
                                         size_t maxLen);

/* Read a whole regular file of at most maxLen bytes. */
GDS_MUST_CHECK gds_status gds_file_read(const char *path, size_t maxLen, gds_buf *out);
/* Write to <path>.tmp (created with `mode`), fsync, rename over <path>.
 * A crash leaves either the old or the new file, never half of one. */
GDS_MUST_CHECK gds_status gds_file_write_atomic(const char *path, const void *data,
                                                size_t len, mode_t mode);
/* mkdir -p with the given mode for every created component. */
GDS_MUST_CHECK gds_status gds_mkdirs(const char *path, mode_t mode);
/* snprintf that fails on truncation instead of silently cutting. */
GDS_MUST_CHECK gds_status gds_path(char *out, size_t outLen, const char *fmt, ...)
    GDS_FORMAT(3, 4);

/* Upper-case hex of `len` bytes into out (needs 2*len+1 bytes). */
GDS_MUST_CHECK gds_status gds_hex(const uint8_t *data, size_t len, char *out, size_t outLen);

#endif
