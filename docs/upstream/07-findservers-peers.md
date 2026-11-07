# Gap 7: FindServers cannot return the other servers of a redundant set

**Status (2026-11-06):** found by the UASM spec tests (RED-002), which drive FindServers on one node of a non-transparent redundant server set. This is present on our pinned v1.5.10. It has not been searched upstream yet; do that before posting. Elias posts it (O5).

**Patch:** [patches/v1.5.10/0005-findservers-peers.patch](patches/v1.5.10/0005-findservers-peers.patch). It is authored by Elias (O4) and is **carried** on our build (UASM ask A15).

## What the spec requires

- OPC 10000-4 §6.6.2.4.5.1: in non-transparent redundancy, FindServers on any server of the set returns every server of the set, each with its own DiscoveryUrls.
- OPC 10000-4 §5.5.2.2: the request's EndpointUrl decides which DiscoveryUrls the server returns *for itself*. Other servers in the response keep their own.

## What goes wrong

`Service_FindServers` (src/server/ua_services_discovery.c) has two problems:

1. It can add servers only through RegisterServer. That needs a remote registration as a DISCOVERYSERVER, and the entries expire. A server cannot name its redundancy peers itself.
2. When the request carries an EndpointUrl, the "mirror back" loop replaces the DiscoveryUrls of **every** entry in the response with that URL, not only the server's own entry.

## The fix

- `UA_ServerConfig.findServersPeers` / `findServersPeersContext`: a callback whose servers FindServers appends after the server itself. They are filtered by the request's serverUris, and the server takes ownership of the array.
- The EndpointUrl is mirrored back into the server's own entry only.

OpenGDS fills the callback with `gds_server_set_peer_servers` (gds_server.h). `tests/unit/test_peers.c` covers the order, the filter, the DiscoveryUrls of each peer and replacing the list.
