/* OpenGDS - store interface (OpenGDS plan "Store"; the whole interface from
 * T1, backed by SQLite in store_sqlite.c). Single-writer: every call comes
 * from the server thread or holds the caller's store lock.
 *
 * Ownership: inputs are borrowed. Outputs (records, requests, buffers) are
 * owned by the caller and released with the matching _clear / free.
 *
 * Backends (UASM ask A4, issue #15): every call dispatches through a
 * gds_store_backend. SQLite is built in (gds_store_open); a plugin, such as
 * a replicated store, brings its own with gds_store_open_backend.
 *
 * Errors: every write may return GDS_ENOTLEADER when a replicated backend
 * loses or lacks leadership before its commit. The write then changed
 * nothing. The core maps it to Bad_InvalidState, never retries it locally,
 * and returns nothing from the refused write to the client ("commit before
 * return"). The SQLite backend never returns it.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_STORE_H
#define OPENGDS_STORE_H

#include <open62541/types.h>
#include <open62541/types_gds_generated.h>

#include <stdbool.h>
#include <stdint.h>

#include "common/buf.h"
#include "common/compiler.h"

typedef struct gds_store gds_store;

/* Open (and create or migrate) the database at path, mode 0600. */
GDS_MUST_CHECK gds_status gds_store_open(const char *path, gds_store **out);
/* Read-only connection for opengds-signer, which re-reads requests and
 * records instead of trusting opengdsd. Never creates or migrates; refuses
 * a schema other than the latest. The database must already be in WAL mode
 * with its -shm file accessible to the reader. */
GDS_MUST_CHECK gds_status gds_store_open_readonly(const char *path, gds_store **out);
void gds_store_close(gds_store *s);
/* Schema version after migration. */
int gds_store_schema_version(gds_store *s);

/* Applications. The record's applicationId identifier is the GUID `id`.
 * GDS_EEXISTS if the ApplicationUri is registered already. */
GDS_MUST_CHECK gds_status gds_store_app_insert(gds_store *s, const UA_Guid *id,
                                               const UA_ApplicationRecordDataType *rec);
GDS_MUST_CHECK gds_status gds_store_app_get(gds_store *s, const UA_Guid *id,
                                            UA_ApplicationRecordDataType *out);
/* Records with this ApplicationUri (at most max). *out is a UA array. */
GDS_MUST_CHECK gds_status gds_store_app_find_uri(gds_store *s, const UA_String *uri, size_t max,
                                                 UA_ApplicationRecordDataType **out, size_t *n);

/* Replace the record (and its searchable names). GDS_ENOTFOUND if the id
 * is unknown, GDS_EEXISTS if the new ApplicationUri belongs to another one. */
GDS_MUST_CHECK gds_status gds_store_app_update(gds_store *s, const UA_Guid *id,
                                               const UA_ApplicationRecordDataType *rec);
/* Remove the record with its requests and certificates. GDS_ENOTFOUND if
 * unknown. (Revocation of its certificates comes with REVOKE in T2.) */
GDS_MUST_CHECK gds_status gds_store_app_delete(gds_store *s, const UA_Guid *id);
/* Visit records in record-id order from fromRecordId; the record id is the
 * QueryApplications counter (OPC 10000-12 §6.5.10). rec->applicationId has
 * namespace 0; the callback borrows rec and returns false to stop. */
typedef bool (*gds_store_scan_cb)(void *ctx, int64_t recordId,
                                  const UA_ApplicationRecordDataType *rec);
GDS_MUST_CHECK gds_status gds_store_app_scan(gds_store *s, int64_t fromRecordId,
                                             gds_store_scan_cb cb, void *ctx);

/* Certificate requests: Received -> Issued -> Delivered (or Failed). */
typedef enum {
    GDS_REQ_RECEIVED = 1,
    GDS_REQ_ISSUED = 2,
    GDS_REQ_DELIVERED = 3,
    GDS_REQ_FAILED = 4
} gds_req_state;

typedef struct {
    UA_Guid id, appId;
    uint32_t groupId;  /* numeric id in the GDS namespace */
    uint32_t certType; /* numeric id in namespace 0 */
    gds_req_state state;
    gds_buf csr;
    gds_buf cert;
    UA_StatusCode error;
} gds_request;

void gds_request_clear(gds_request *r);
GDS_MUST_CHECK gds_status gds_store_req_insert(gds_store *s, const gds_request *r);
GDS_MUST_CHECK gds_status gds_store_req_get(gds_store *s, const UA_Guid *id, gds_request *out);
/* Oldest request in state Received; GDS_ENOTFOUND if none. */
GDS_MUST_CHECK gds_status gds_store_req_next_received(gds_store *s, gds_request *out);
GDS_MUST_CHECK gds_status gds_store_req_set_state(gds_store *s, const UA_Guid *id,
                                                  gds_req_state state, const gds_buf *cert,
                                                  UA_StatusCode error);

/* Issued certificates. */
GDS_MUST_CHECK gds_status gds_store_cert_add(gds_store *s, const UA_Guid *appId, uint32_t groupId,
                                             uint32_t certType, const gds_buf *serial,
                                             const gds_buf *der, int64_t notBefore,
                                             int64_t notAfter);
/* Newest unrevoked certificate; GDS_ENOTFOUND if none. */
GDS_MUST_CHECK gds_status gds_store_cert_latest(gds_store *s, const UA_Guid *appId,
                                                uint32_t groupId, uint32_t certType, gds_buf *der,
                                                int64_t *notAfter);

/* ---- the audit log (issue #18) ----
 * Append-only and hash-chained: row n's hash is
 *   SHA-256(prev_hash || seq (8 bytes, big-endian) || time (8 bytes,
 *           big-endian, UA_DateTime) || body)
 * with prev_hash the hash of row n-1, or 32 zero bytes for row 1. Rows
 * are numbered 1, 2, 3 ... without gaps. The body is opaque to the store
 * (the server writes the OPC UA binary encoding of the event, see
 * src/server/gds_audit.c). Every backend computes the chain with
 * gds_audit_hash, in the same transaction as the row. */
#define GDS_AUDIT_HASH 32
#define GDS_MAX_AUDIT_BODY ((size_t)64 * 1024)

typedef struct {
    int64_t seq;
    int64_t time;     /* UA_DateTime */
    gds_buf body;     /* borrowed in a scan callback */
    uint8_t prevHash[GDS_AUDIT_HASH];
    uint8_t hash[GDS_AUDIT_HASH];
} gds_audit_row;

GDS_MUST_CHECK gds_status gds_audit_hash(const uint8_t prev[GDS_AUDIT_HASH], int64_t seq,
                                         int64_t time, const gds_buf *body,
                                         uint8_t out[GDS_AUDIT_HASH]);

/* Appends a row (one transaction); *seq gets its number. GDS_ETOOBIG above
 * GDS_MAX_AUDIT_BODY. May return GDS_ENOTLEADER like every write. */
GDS_MUST_CHECK gds_status gds_store_audit_append(gds_store *s, int64_t time, const gds_buf *body,
                                                 int64_t *seq);
/* Visits rows from fromSeq in order; the callback borrows the row and
 * returns false to stop. GDS_EUNSUPPORTED for a backend without a log. */
typedef bool (*gds_audit_scan_cb)(void *ctx, const gds_audit_row *row);
GDS_MUST_CHECK gds_status gds_store_audit_scan(gds_store *s, int64_t fromSeq,
                                               gds_audit_scan_cb cb, void *ctx);
/* Walks the whole log: every hash recomputed, every seq in order.
 * GDS_OK, or GDS_ESTATE with *badSeq the first row that does not verify. */
GDS_MUST_CHECK gds_status gds_store_audit_verify(gds_store *s, int64_t *rows, int64_t *badSeq);

/* ---- backends (issue #15) ----
 * A backend implements every operation above with the same contract, on
 * its own context. Every function pointer is required. Each write is one
 * transaction: it commits fully or changes nothing. The core calls a
 * backend from one thread at a time (see "Single-writer" above). */
#define GDS_STORE_ABI_MAJOR 1u
#define GDS_STORE_ABI_MINOR 1u /* 1: the audit log */

typedef struct {
    uint32_t abi_major;
    uint32_t abi_minor;
    size_t struct_size;
    void (*close)(void *ctx); /* takes ctx */
    int (*schema_version)(void *ctx);
    gds_status (*app_insert)(void *ctx, const UA_Guid *id, const UA_ApplicationRecordDataType *rec);
    gds_status (*app_get)(void *ctx, const UA_Guid *id, UA_ApplicationRecordDataType *out);
    gds_status (*app_find_uri)(void *ctx, const UA_String *uri, size_t max,
                               UA_ApplicationRecordDataType **out, size_t *n);
    gds_status (*app_update)(void *ctx, const UA_Guid *id, const UA_ApplicationRecordDataType *rec);
    gds_status (*app_delete)(void *ctx, const UA_Guid *id);
    gds_status (*app_scan)(void *ctx, int64_t fromRecordId, gds_store_scan_cb cb, void *cbCtx);
    gds_status (*req_insert)(void *ctx, const gds_request *r);
    gds_status (*req_get)(void *ctx, const UA_Guid *id, gds_request *out);
    gds_status (*req_next_received)(void *ctx, gds_request *out);
    gds_status (*req_set_state)(void *ctx, const UA_Guid *id, gds_req_state state,
                                const gds_buf *cert, UA_StatusCode error);
    gds_status (*cert_add)(void *ctx, const UA_Guid *appId, uint32_t groupId, uint32_t certType,
                           const gds_buf *serial, const gds_buf *der, int64_t notBefore,
                           int64_t notAfter);
    gds_status (*cert_latest)(void *ctx, const UA_Guid *appId, uint32_t groupId,
                              uint32_t certType, gds_buf *der, int64_t *notAfter);
    /* minor 1 */
    gds_status (*audit_append)(void *ctx, int64_t time, const gds_buf *body, int64_t *seq);
    gds_status (*audit_scan)(void *ctx, int64_t fromSeq, gds_audit_scan_cb cb, void *cbCtx);
} gds_store_backend;

/* A store on a plugin backend. The vtable is copied; ctx is taken, and
 * gds_store_close passes it to be->close (also when this call fails).
 * GDS_EINVAL for another ABI major, a struct_size below the minor 0
 * fields, or a missing function. A minor 0 backend (no audit log) works;
 * its audit calls return GDS_EUNSUPPORTED. */
GDS_MUST_CHECK gds_status gds_store_open_backend(const gds_store_backend *be, void *ctx,
                                                 gds_store **out);

#endif
