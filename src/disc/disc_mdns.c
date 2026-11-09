/* OpenGDS - announce the GDS on the MulticastSubnet (see disc_mdns.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include "disc_mdns.h"

#include <arpa/inet.h>
#include <string.h>

#include "common/banned.h"

bool gds_disc_mdns_built(void) {
#if defined(OPENGDS_WITH_MDNS) && defined(UA_ENABLE_DISCOVERY_MULTICAST)
    return true;
#else
    return false;
#endif
}

/* Well-formed UTF-8 without control characters or '.'. */
static bool name_ok(const char *s) {
    size_t n = strlen(s);
    if(n == 0 || n > GDS_MDNS_MAX_NAME)
        return false;
    const unsigned char *p = (const unsigned char *)s, *end = p + n;
    while(p < end) {
        unsigned char c = *p;
        size_t len = c < 0x80 ? 1 : (c & 0xe0) == 0xc0 ? 2 : (c & 0xf0) == 0xe0 ? 3
                                  : (c & 0xf8) == 0xf0 ? 4 : 0;
        if(len == 0 || (size_t)(end - p) < len)
            return false;
        if(len == 1 && (c < 0x20 || c == 0x7f || c == '.'))
            return false;
        if(len == 2 && c < 0xc2)
            return false; /* overlong */
        for(size_t i = 1; i < len; i++)
            if((p[i] & 0xc0) != 0x80)
                return false;
        p += len;
    }
    return true;
}

gds_status gds_disc_mdns_check(const gds_mdns_config *m) {
    if(!m)
        return GDS_EINVAL;
    if(m->serverName && m->serverName[0] && !name_ok(m->serverName))
        return GDS_EINVAL;
    if(m->interfaceIp) {
        struct in_addr a;
        if(inet_pton(AF_INET, m->interfaceIp, &a) != 1)
            return GDS_EINVAL;
    }
    if(m->enabled && !gds_disc_mdns_built())
        return GDS_EUNSUPPORTED;
    return GDS_OK;
}

gds_status gds_disc_mdns_configure(UA_ServerConfig *c, const gds_mdns_config *m,
                                   const char *applicationName) {
    if(!c || !m)
        return GDS_EINVAL;
    gds_status st = gds_disc_mdns_check(m);
    if(st != GDS_OK || !m->enabled)
        return st;
#if defined(OPENGDS_WITH_MDNS) && defined(UA_ENABLE_DISCOVERY_MULTICAST)
    const char *name = m->serverName && m->serverName[0] ? m->serverName : applicationName;
    if(!name || !name_ok(name))
        return GDS_EINVAL; /* the ApplicationName is no DNS label: set mdns_server_name */
    UA_MdnsDiscoveryConfiguration *mc = &c->mdnsConfig;
    UA_MdnsDiscoveryConfiguration_clear(mc);
    mc->mdnsServerName = UA_String_fromChars(name);
    mc->serverCapabilities = UA_String_new();
    if(!mc->mdnsServerName.data || !mc->serverCapabilities) {
        UA_MdnsDiscoveryConfiguration_clear(mc);
        return GDS_ENOMEM;
    }
    mc->serverCapabilitiesSize = 1;
    mc->serverCapabilities[0] = UA_String_fromChars(GDS_MDNS_CAPABILITY);
    if(!mc->serverCapabilities[0].data) {
        UA_MdnsDiscoveryConfiguration_clear(mc);
        return GDS_ENOMEM;
    }
#ifdef UA_ENABLE_DISCOVERY_MULTICAST_MDNSD
    UA_String_clear(&c->mdnsInterfaceIP);
    if(m->interfaceIp) {
        c->mdnsInterfaceIP = UA_String_fromChars(m->interfaceIp);
        if(!c->mdnsInterfaceIP.data)
            return GDS_ENOMEM;
    }
#endif
    c->mdnsEnabled = true;
    return GDS_OK;
#else
    (void)applicationName;
    return GDS_EUNSUPPORTED; /* not reached: check refused it */
#endif
}
