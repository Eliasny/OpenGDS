/* OpenGDS - gdsctl verify-audit: one store against several signer journals
 * (UASM ask A8, issue #19).
 *
 * In a replicated deployment every node runs its own opengds-signer with
 * its own issuance journal, and all nodes share one store. The check:
 *   - the store's audit log chain verifies (gds_store_audit_verify);
 *   - every journal's chain verifies (gds_journal_read);
 *   - every certificate in the store is ISSUED in exactly one journal
 *     entry, with the same DER digest;
 *   - every ISSUED journal entry whose certificate is not in the store is
 *     reported as "signed, not committed" (the signer answered, but the
 *     store write never happened, for example across a failover).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_GDSCTL_VERIFY_AUDIT_H
#define OPENGDS_GDSCTL_VERIFY_AUDIT_H

#include <stddef.h>
#include <stdint.h>

#include "journal.h"
#include "store.h"

typedef enum {
    GDS_VA_STORE_AUDIT_BROKEN = 1, /* seq: first bad audit row */
    GDS_VA_JOURNAL_BROKEN,         /* journal, seq: first bad entry */
    GDS_VA_NOT_JOURNALLED,         /* serial, appId: in the store, in no journal */
    GDS_VA_SEVERAL_ENTRIES,        /* serial, journal, seq: one of several entries */
    GDS_VA_DIGEST_MISMATCH,        /* serial, journal, seq: store DER differs */
    GDS_VA_SIGNED_NOT_COMMITTED    /* serial, journal, seq, requestId */
} gds_va_kind;

typedef struct {
    gds_va_kind kind;
    size_t journal; /* index into the journals array, when it names one */
    int64_t seq;
    const uint8_t *serial;
    size_t serialLen;
    UA_Guid appId;
    UA_Guid requestId;
} gds_va_finding;

typedef void (*gds_va_report)(void *ctx, const gds_va_finding *f);

typedef struct {
    int64_t certificates;  /* in the store */
    int64_t auditRows;     /* in the store's audit log; -1 when the backend has none */
    int64_t issued;        /* ISSUED entries over all journals */
    int64_t findings;
} gds_va_summary;

/* GDS_OK when the check ran (findings are reported, not errors); an error
 * when the store or a journal could not be read at all. */
GDS_MUST_CHECK gds_status gds_verify_audit(gds_store *store, const char *const *journals,
                                           size_t nJournals, gds_va_report report, void *ctx,
                                           gds_va_summary *sum);

#endif
