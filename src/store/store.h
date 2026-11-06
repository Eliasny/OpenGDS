/* OpenGDS - store interface (OpenGDS plan "Store"; the whole interface from
 * T1, backed by SQLite in store_sqlite.c). Single-writer: every call comes
 * from the server thread or holds the caller's store lock.
 *
 * Ownership: inputs are borrowed. Outputs (records, requests, buffers) are
 * owned by the caller and released with the matching _clear / free.
 *
 * Errors: every write may return GDS_ENOTLEADER when a replicated backend
 * (the UASM cluster plugin, issue #15) is not the primary; the server maps it
 * to Bad_InvalidState. The SQLite backend never returns it.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_STORE_H
#define OPENGDS_STORE_H

#include <open62541/types.h>
#include <open62541/types_gds_generated.h>

#include <stdint.h>

#include "common/buf.h"
#include "common/compiler.h"

typedef struct gds_store gds_store;

/* Open (and create or migrate) the database at path, mode 0600. */
GDS_MUST_CHECK gds_status gds_store_open(const char *path, gds_store **out);
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

#endif
