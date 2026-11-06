/* OpenGDS libgdsclient - an administrator's session to a GDS (OpenGDS plan,
 * src/client/gdsc_connect.c): SignAndEncrypt, a UserName identity token,
 * and the GDS's certificate checked against an explicit trust list (its CA
 * and CRL): never trust on first use.
 *
 * The channel uses a fresh self-signed certificate per call: an
 * administrator is identified by the user name, not by an application
 * instance certificate (OPC 10000-12 §7.2 roles come from the users file).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_CLIENT_GDSC_CONNECT_H
#define OPENGDS_CLIENT_GDSC_CONNECT_H

#include <open62541/client.h>

#include "common/buf.h"
#include "common/compiler.h"

typedef struct {
    const char *url;          /* opc.tcp://host:port of the GDS */
    const char *user;         /* user name in the GDS users file */
    const gds_buf *password;  /* borrowed; never on argv */
    const gds_buf *trust;     /* certificates that may vouch for the GDS: its CA */
    size_t trustN;
    const gds_buf *crls;
    size_t crlN;
    UA_UInt32 timeoutMs;      /* per request; 0 = 10 s */
} gdsc_admin_cfg;

/* Connect and activate the session. *out is freed with gdsc_admin_close. */
GDS_MUST_CHECK UA_StatusCode gdsc_admin_connect(const gdsc_admin_cfg *cfg, UA_Client **out);
void gdsc_admin_close(UA_Client *c);

#endif
