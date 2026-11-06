/* OpenGDS - CA slot client for opengds-signer (src/ca/ca_ipc.c).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_CA_IPC_H
#define OPENGDS_CA_IPC_H

#include "ca.h"

/* fd: a connected SOCK_SEQPACKET socket to the signer; ownership passes to
 * the CA (closed on error too). timeoutMs bounds every reply. */
GDS_MUST_CHECK gds_status gds_ca_ipc_open(int fd, int timeoutMs, gds_ca **out);

#endif
