/* OpenGDS - the opengdsd <-> opengds-signer protocol (docs/architecture.md,
 * "Split by privilege"). One message per SOCK_SEQPACKET datagram, fixed
 * and versioned, big-endian, every length checked. Fuzzed by
 * tests/fuzz/fuzz_signer_ipc.c.
 *
 * Header (12 bytes): magic u32 "OGSG" | version u16 | op u16 | bodyLen u32
 * Request bodies:
 *   SIGN_CSR   requestId (16 bytes). The signer reads the CSR, the record
 *              and the request state from the store itself.
 *   GET_CHAIN  empty
 *   ISSUE_CRL  empty
 * Reply body: status u32, then on GDS_OK:
 *   SIGN_CSR   notBefore i64 | notAfter i64 | serialLen u16 | serial |
 *              derLen u32 | der
 *   GET_CHAIN, ISSUE_CRL   derLen u32 | der
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_SIGNER_PROTO_H
#define OPENGDS_SIGNER_PROTO_H

#include <open62541/types.h>

#include <stddef.h>
#include <stdint.h>

#include "ca.h"
#include "common/buf.h"
#include "common/compiler.h"

#define GDS_SIGP_MAGIC 0x4F475347u /* "OGSG" */
#define GDS_SIGP_VERSION 1u
#define GDS_SIGP_HEADER 12u
/* One datagram must fit the default AF_UNIX send buffer (net.core.wmem_default
 * 212992). A CRL above this needs the chunked ISSUE_CRL of W2. */
#define GDS_SIGP_MAX_MSG ((size_t)128 * 1024)
#define GDS_SIGP_MAX_SERIAL 64u

/* Op codes follow gds_ca_op; GET_CHAIN has no CA operation of its own. */
typedef enum {
    GDS_SIGP_SIGN_CSR = GDS_CA_OP_SIGN_CSR,
    GDS_SIGP_ISSUE_CRL = GDS_CA_OP_ISSUE_CRL,
    GDS_SIGP_GET_CHAIN = 5
} gds_sigp_op;

GDS_MUST_CHECK gds_status gds_sigp_encode_request(gds_sigp_op op, const UA_Guid *requestId,
                                                  gds_buf *out);
GDS_MUST_CHECK gds_status gds_sigp_decode_request(const uint8_t *msg, size_t len, gds_sigp_op *op,
                                                  UA_Guid *requestId);

/* issued for SIGN_CSR, der for GET_CHAIN / ISSUE_CRL; both ignored unless
 * status is GDS_OK. */
GDS_MUST_CHECK gds_status gds_sigp_encode_reply(gds_sigp_op op, gds_status status,
                                                const gds_ca_issued *issued, const gds_buf *der,
                                                gds_buf *out);
/* Decodes a reply to `op`. *status is the signer's result; the return value
 * says whether the message itself was well-formed. */
GDS_MUST_CHECK gds_status gds_sigp_decode_reply(gds_sigp_op op, const uint8_t *msg, size_t len,
                                                gds_status *status, gds_ca_issued *issued,
                                                gds_buf *der);

#endif
