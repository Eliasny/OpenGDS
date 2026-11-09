/* OpenGDS - announce the GDS on the MulticastSubnet (OPC 10000-12 §4.3.4,
 * §5, Annex C; OpenGDS plan W5, src/disc/disc_mdns.c).
 *
 * opengdsd is a DiscoveryServer (ApplicationType, §6.3) and with mDNS on it
 * is its own LDS-ME (§3.1.14): open62541's mDNS responder announces each
 * DiscoveryUrl as an SRV record `_opcua-tcp._tcp` (Annex C.1) with the TXT
 * record `caps=GDS` (Annex C.2, Annex D "Supports the Global Discovery
 * Server information model"), keeps a cache of the other servers it hears
 * on the subnet, and answers FindServersOnNetwork (OPC 10000-4 §5.5.3) from
 * it, its own record included. ServerConfiguration.MulticastDnsEnabled
 * (§7.10.3) reads TRUE while it announces.
 *
 * Off unless configured: mDNS is insecure by nature and "should be
 * disabled in environments where an attacker could cause problems by
 * impersonating another host" (§5.2); clients still check the GDS
 * certificate against their trust list before they use it.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_DISC_MDNS_H
#define OPENGDS_DISC_MDNS_H

#include <open62541/server.h>

#include <stdbool.h>

#include "common/compiler.h"
#include "common/errors.h"

/* The mDNS service instance name is one DNS label (RFC 6763 §4.1.1, at most
 * 63 bytes); open62541 appends "-<host>" to it, within the same label. */
#define GDS_MDNS_MAX_NAME 63
/* Annex C.2: capabilities are "short (<=8 character) strings" */
#define GDS_MDNS_CAPABILITY "GDS"

typedef struct {
    bool enabled;
    /* Service instance name; NULL or "" uses the ApplicationName. 1..63
     * bytes of printable UTF-8 without '.' (a label separator). */
    const char *serverName;
    /* IPv4 address of the interface to announce on; NULL: all. */
    const char *interfaceIp;
} gds_mdns_config;

/* true when this build carries mDNS (OPENGDS_WITH_MDNS and an open62541
 * built with UA_ENABLE_DISCOVERY_MULTICAST). */
bool gds_disc_mdns_built(void);

/* Check m without touching a config: GDS_EINVAL for a bad name or address,
 * GDS_EUNSUPPORTED for enabled in a build without mDNS. */
GDS_MUST_CHECK gds_status gds_disc_mdns_check(const gds_mdns_config *m);

/* Set up the announce in c before UA_Server_newWithConfig; the multicast
 * sockets open when the server starts. applicationName is the fallback
 * instance name. Disabled: c is left as it is. */
GDS_MUST_CHECK gds_status gds_disc_mdns_configure(UA_ServerConfig *c, const gds_mdns_config *m,
                                                  const char *applicationName);

#endif
