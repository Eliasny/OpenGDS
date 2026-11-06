/* OpenGDS - the signer's own issuance journal (docs/architecture.md,
 * "opengds-signer"; UASM ask A8, issue #19).
 *
 * The signer appends one line for every SIGN_CSR it answers, before the
 * answer leaves the process, in a file opengdsd cannot write (the CA
 * directory). In a replicated deployment every node has its own signer and
 * journal but all share one store, so `gdsctl verify-audit` checks that
 * each certificate in the store is in exactly one journal, and reports
 * journal entries that never reached the store ("signed, not committed").
 *
 * Line format (text, one entry per line, fields separated by one space):
 *   <seq> <time> <op> <requestId> <serial> <derSha256> <status> <hash>
 *   seq        1, 2, 3 ... without gaps
 *   time       UA_DateTime (100 ns since 1601)
 *   op         ISSUED or REFUSED
 *   requestId  the store's request id (a GUID)
 *   serial     upper-case hex, "-" when refused
 *   derSha256  SHA-256 of the certificate DER in upper-case hex, "-" when refused
 *   status     the gds_status number, 0 when issued
 *   hash       gds_audit_hash(previous hash, seq, time, "<op> ... <status>"),
 *              32 zero bytes before entry 1; upper-case hex
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_SIGNER_JOURNAL_H
#define OPENGDS_SIGNER_JOURNAL_H

#include <open62541/types.h>

#include <stdbool.h>
#include <stdint.h>

#include "ca.h"
#include "common/buf.h"
#include "common/compiler.h"
#include "store.h"

#define GDS_JOURNAL_FILE "issuance.journal"
#define GDS_JOURNAL_MAX_SERIAL 32 /* bytes; RFC 5280 allows 20 */
#define GDS_JOURNAL_MAX_LINE 512

typedef struct gds_journal gds_journal;

/* Opens (or creates, mode 0600) the journal for appending. The existing
 * entries are verified first: a broken chain or a torn line gives
 * GDS_ESTATE, and a journal another process holds gives GDS_EEXISTS
 * (flock), so a signer never extends a journal it cannot vouch for. */
GDS_MUST_CHECK gds_status gds_journal_open(const char *path, gds_journal **out);
void gds_journal_close(gds_journal *j);

/* Append and fsync one entry. On an error nothing may be handed out. */
GDS_MUST_CHECK gds_status gds_journal_issued(gds_journal *j, const UA_Guid *requestId,
                                             const gds_ca_issued *cert);
GDS_MUST_CHECK gds_status gds_journal_refused(gds_journal *j, const UA_Guid *requestId,
                                              gds_status why);

typedef struct {
    int64_t seq;
    int64_t time;
    bool issued;
    UA_Guid requestId;
    uint8_t serial[GDS_JOURNAL_MAX_SERIAL];
    size_t serialLen; /* 0 when refused */
    uint8_t derSha256[GDS_AUDIT_HASH];
    int status;
} gds_journal_entry;

/* Returns false to stop. */
typedef bool (*gds_journal_cb)(void *ctx, const gds_journal_entry *e);

/* Reads and verifies a journal from the start. GDS_ESTATE with *badSeq set
 * (the line number) at the first entry that does not parse or verify; the
 * entries before it have been passed to cb. */
GDS_MUST_CHECK gds_status gds_journal_read(const char *path, gds_journal_cb cb, void *ctx,
                                           int64_t *badSeq);

#endif
