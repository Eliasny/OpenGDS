/* OpenGDS - gdsctl backup and restore: the store and the CA directory in
 * one encrypted archive (docs/architecture.md, "Backup").
 *
 * Backup takes an online snapshot of the SQLite store (sqlite3_backup), then
 * the regular files of the CA directory: the passphrase-protected CA key,
 * the CA certificate, the CRL and the signer's issuance journal. The store
 * goes first, so the journal copy can only be ahead of it ("signed, not
 * committed"), never behind. A journal is copied up to its last complete
 * line.
 *
 * Archive: "OGDSBAK1", scrypt parameters (log2 N, r, p), a 16-byte salt and
 * a 12-byte nonce, then the AES-256-GCM ciphertext of the entries and the
 * 16-byte tag; the header is the GCM additional data. The key is scrypt of
 * the backup passphrase. Entries: type (1 store, 2 CA file), name length
 * (2 bytes), name, size (8 bytes), data, all big-endian; type 0 ends.
 *
 * Restore decrypts into new files next to the targets and checks the tag
 * before anything is used. It then runs the verify-audit check on the
 * restored store against the restored journal and any other journals given
 * (the other nodes' journals of a replicated deployment). Only a clean
 * result, or one whose only findings are "signed, not committed", is
 * moved into place; the targets must not exist.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_GDSCTL_BACKUP_H
#define OPENGDS_GDSCTL_BACKUP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/buf.h"
#include "common/compiler.h"
#include "verify_audit.h"

#define GDS_BACKUP_LOG2N 17 /* scrypt N = 2^17, r = 8, p = 1: 128 MiB */
#define GDS_BACKUP_MIN_LOG2N 10
#define GDS_BACKUP_MAX_LOG2N 20
#define GDS_BACKUP_MAX_FILES 64

/* Writes the archive (mode 0600; it must not exist). log2N: the scrypt
 * cost, GDS_BACKUP_LOG2N outside tests. */
GDS_MUST_CHECK gds_status gds_backup_create(const char *storePath, const char *caDir,
                                            const char *archive, const gds_buf *passphrase,
                                            unsigned log2N);

typedef struct {
    int64_t entries;   /* files restored */
    gds_va_summary va; /* the verify-audit result */
    int64_t blocking;  /* findings other than "signed, not committed" */
} gds_restore_summary;

/* journals: the other nodes' journals; the restored journal, when the
 * archive has one, is checked after them, so a finding's journal index
 * nJournals names it. GDS_OK: restored and in place. GDS_ESTATE: the check found blocking
 * findings (reported through report); nothing was put in place.
 * GDS_ECRYPTO: wrong passphrase or a damaged archive. GDS_EEXISTS: a
 * target exists. */
GDS_MUST_CHECK gds_status gds_backup_restore(const char *archive, const gds_buf *passphrase,
                                             const char *storePath, const char *caDir,
                                             const char *const *journals, size_t nJournals,
                                             gds_va_report report, void *ctx,
                                             gds_restore_summary *sum);

#endif
