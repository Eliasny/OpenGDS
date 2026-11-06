/* OpenGDS - opengds-signer request handling (no I/O, so it can be tested
 * and fuzzed directly). The signer trusts nothing opengdsd sends except a
 * request id: the request, its state, the CSR and the application record
 * all come from its own read-only store connection (docs/architecture.md).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_SIGNER_H
#define OPENGDS_SIGNER_H

#include <stddef.h>
#include <stdint.h>

#include "ca.h"
#include "common/buf.h"
#include "journal.h"
#include "store.h"

typedef struct {
    gds_store *store; /* read-only */
    gds_ca *ca;
    gds_journal *journal; /* NULL: no journal (tests); opengds-signer always has one */
} gds_signer;

/* Every SIGN_CSR answer is journalled before it is returned. When the
 * journal cannot be written, the certificate is dropped and the request is
 * refused with GDS_EIO: nothing leaves the signer unrecorded. */
/* Handle one request datagram and build the reply datagram. Always produces
 * a reply when it returns GDS_OK, even when the request was refused (the
 * refusal is the reply's status). */
GDS_MUST_CHECK gds_status gds_signer_handle(gds_signer *s, const uint8_t *msg, size_t len,
                                            gds_buf *reply);

/* Serve requests on a connected SOCK_SEQPACKET socket until the peer
 * closes it. Returns GDS_OK on a clean close. */
GDS_MUST_CHECK gds_status gds_signer_serve(gds_signer *s, int fd);

#endif
