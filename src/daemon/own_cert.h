/* OpenGDS - the GDS's own application instance certificate (own_cert.c).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_DAEMON_OWN_CERT_H
#define OPENGDS_DAEMON_OWN_CERT_H

#include <stdint.h>

#include "ca.h"
#include "common/buf.h"
#include "store.h"

typedef struct {
    const char *dataDir;
    const char *applicationUri, *applicationName, *productUri;
    const char *host; /* in the DiscoveryUrl, and so in the certificate SAN */
    uint16_t port;
} gdsd_own_params;

/* DER certificate and key from data_dir/own/, issued by the CA on first
 * start or when it expires within 30 days. */
GDS_MUST_CHECK gds_status gdsd_own_cert(const gdsd_own_params *p, gds_store *st, gds_ca *ca,
                                        gds_buf *cert, gds_buf *key);

#endif
