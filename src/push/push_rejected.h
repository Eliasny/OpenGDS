/* OpenGDS push engine - the rejected-list harvest (OpenGDS plan W3,
 * push_rejected.c; "Where Part 12 is silent": unknown clients knocking on
 * servers).
 *
 * A managed Server keeps the certificates of the clients it refused (OPC
 * 10000-12 §7.10.12 GetRejectedList, §7.8.3.2). The push engine reads that
 * list and offers each unknown application instance certificate here. Each
 * becomes one Part 9 DialogCondition (OPC 10000-9 §5.6) on the Push object
 * in OpenGDS's push namespace: "Register and trust this client?". A
 * DiscoveryAdmin (OPC 10000-12 §6.2) answers it with Respond or Respond2
 * over SignAndEncrypt:
 *   0 "Register and trust": the client is registered in the Directory as a
 *     Client (RegisterApplication rules, §6.5.6; idempotent per
 *     ApplicationUri) and its certificate goes into the Trusted list of the
 *     DefaultApplicationGroup TrustList (§7.8.2.6), which the engine then
 *     pushes to every managed Server;
 *   1 "Ignore": nothing changes.
 * Either way the certificate is not offered again while opengdsd runs.
 * Unknown means: an application instance certificate (not a CA) with an
 * ApplicationUri, not already in the trust list and not issued by a CA in
 * it. At most maxOpen dialogs are open at once; later ones wait for the
 * next harvest.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_PUSH_REJECTED_H
#define OPENGDS_PUSH_REJECTED_H

#include <open62541/types.h>
#include <open62541/types_gds_generated.h>

#include "common/compiler.h"
#include "common/errors.h"
#include "gds_server.h"

#define PUSH_NS_URI "urn:opengds:push"
#define PUSH_NODE_PUSH 1 /* the Push object (BaseObjectType) under Objects */
#define PUSH_REJECTED_ACTOR "opengds-push"

typedef struct push_rejected push_rejected;

typedef struct {
    gds_server *server;
    uint32_t maxOpen;        /* open dialogs at once; 0: 64 */
    uint32_t trustTimeoutMs; /* gds_server_trust_certificate; 0: 10 s */
} push_rejected_cfg;

/* Adds the namespace and the Push object (once per server). */
GDS_MUST_CHECK gds_status push_rejected_new(const push_rejected_cfg *cfg, push_rejected **out);
/* Removes its open dialogs. */
void push_rejected_free(push_rejected *r);
/* The certificates serverUri refused; tl is the GDS's current trust list.
 * Returns how many dialogs were opened. Any thread but the server thread. */
size_t push_rejected_offer(push_rejected *r, const char *serverUri, const UA_ByteString *certs,
                           size_t n, const UA_TrustListDataType *tl);
/* Removes the dialogs that were answered. Any thread but the server thread. */
void push_rejected_tick(push_rejected *r);
/* Open dialogs (tests). */
size_t push_rejected_open(push_rejected *r);

#endif
