/* OpenGDS Auditor client profile - the probe server (Auditor plan, client
 * profile fixtures). An OPC UA server the client under test is asked to
 * connect to, to see what it really installed: which certificate it
 * presents and which server certificates it trusts.
 *
 * TEST FIXTURE: one instance per process, loopback only, accepts any
 * client certificate (it records it, it does not judge it).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_PROBE_H
#define GDSAUDIT_PROBE_H

#include <stdbool.h>

#include "common/buf.h"
#include "fake_gds.h"

#define PROBE_APP_URI "urn:opengds:auditor:probe"

/* Start the probe with a fresh identity issued by `issuer`. */
GDS_MUST_CHECK gds_status probe_start(long port, fg_ca_id issuer);
/* The same with a given identity (e.g. one a CRL revokes) */
GDS_MUST_CHECK gds_status probe_start_identity(long port, const gds_buf *cert, const gds_buf *key);
/* Serve pending network events (no-op when stopped). */
void probe_iterate(void);
void probe_stop(void);
const char *probe_url(void);

/* After a connection attempt: did a session get activated, and with which
 * client certificate (as sent on the SecureChannel, chain included)? */
bool probe_connected(void);
const gds_buf *probe_client_cert(void);

#endif
