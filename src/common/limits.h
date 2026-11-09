/* OpenGDS - upper bounds for every input (docs/architecture.md, limits table).
 * Configuration may lower these, never raise them.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_COMMON_LIMITS_H
#define OPENGDS_COMMON_LIMITS_H

#include <stddef.h>

#define GDS_MAX_CSR_SIZE          ((size_t)16 * 1024)
#define GDS_MAX_CERT_SIZE         ((size_t)16 * 1024)
/* Certificate serial (RFC 5280 §4.1.2.2: at most 20 octets; room for others) */
#define GDS_MAX_SERIAL_SIZE       ((size_t)64)
#define GDS_MAX_CHAIN_LEN         ((size_t)8)
#define GDS_MAX_KEY_SIZE          ((size_t)16 * 1024)
/* StartNewKeyPairRequest PrivateKeyPassword (UTF-8 bytes) */
#define GDS_MAX_KEY_PASSWORD      ((size_t)256)
/* Key pair requests whose password or key waits in opengdsd memory */
#define GDS_MAX_KEYPAIR_REQUESTS  ((size_t)64)
#define GDS_MAX_CRL_SIZE          ((size_t)1024 * 1024)
#define GDS_MAX_TRUSTLIST_SIZE    ((size_t)4 * 1024 * 1024)
#define GDS_MAX_TRUSTLIST_ENTRIES ((size_t)1000)
#define GDS_MAX_STRING            ((size_t)4096)
#define GDS_MAX_APPLICATION_URI   ((size_t)1024)
#define GDS_MAX_ARRAY_FIELD       ((size_t)32)
#define GDS_MAX_QUERY_RECORDS     ((size_t)1000)
#define GDS_MAX_TL_HANDLES        ((size_t)4)
#define GDS_MAX_PENDING_PER_APP   ((size_t)4)
/* Requests waiting for an administrator (spike 1, decision D1) */
#define GDS_MAX_PENDING_APPROVALS 10000u
#define GDS_MAX_PATH              ((size_t)1024)
/* Servers the push engine manages (store push_targets) */
#define GDS_MAX_PUSH_TARGETS      ((size_t)100000)
/* Encoded ApplicationRecordDataType: URI + names + 32 URLs + capabilities */
#define GDS_MAX_RECORD_SIZE       ((size_t)256 * 1024)

#endif
