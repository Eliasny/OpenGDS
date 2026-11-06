/* OpenGDS Auditor - "gdsaudit discover": find servers and their endpoints
 * for the desktop UI's Targets screen (Auditor plan avm/avm_target.c:
 * discovery, endpoint and security policy choice).
 *
 * gdsaudit discover --url URL [--network] [--certs DIR]
 *   FindServers (4 §5.5.2) on URL, then GetEndpoints (4 §5.5.4) on URL and
 *   on each opc.tcp DiscoveryUrl the servers name; with --network also
 *   FindServersOnNetwork (4 §5.5.3). With --certs every server certificate
 *   seen is written as DIR/<thumbprint>.der, ready to pin with
 *   --server-cert.
 *
 * Output on stdout, one record per line, fields separated by tabs. Text from
 * the target has tabs and control characters replaced by spaces and is cut
 * at GA_DISCOVER_MAX_TEXT bytes:
 *   server   uri name type discoveryUrls(space-separated)
 *   endpoint url policyUri mode level thumbprint userTokens(comma) certFile cert
 *   network  recordId serverName discoveryUrl capabilities(comma)
 *   error    step url status
 * type: server, client, clientandserver, discoveryserver; mode: none, sign,
 * signandencrypt; thumbprint: SHA-1 hex (empty if no certificate); step:
 * findservers, getendpoints, network. Exit 0 if any endpoint was found,
 * 1 if none, 2 on a usage error.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_DISCOVER_H
#define GDSAUDIT_DISCOVER_H

#define GA_DISCOVER_MAX_TEXT 512
#define GA_DISCOVER_MAX_URLS 16  /* DiscoveryUrls followed, besides --url */
#define GA_DISCOVER_MAX_ITEMS 256 /* servers or endpoints read per reply */

int discover_main(int argc, char **argv);

#endif
