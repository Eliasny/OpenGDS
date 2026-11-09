/* OpenGDS push engine - the scheduler (OpenGDS plan W3, push_engine.c).
 *
 * Keeps every Server in the push target list (gds_server_push_targets)
 * managed with the push model of OPC 10000-12 v1.05.07 §7.7, from inside
 * opengdsd, as the CertificateManager:
 *   - connects with the GDS's own application instance certificate, which
 *     the Server maps to SecurityAdmin (Annex G.3), over SignAndEncrypt
 *     (§7.4); the Server must present a certificate a CA in the GDS's
 *     trust list issued (no trust on first use: the first push to a
 *     self-signed device is `gdsadm push now --server-cert`);
 *   - renews the Server's certificate (CreateSigningRequest, signed by the
 *     GDS CA through gds_server_sign_request, UpdateCertificate,
 *     ApplyChanges, §7.7.2, §7.7.4) when a third of its lifetime is left,
 *     or at once when it is not one the GDS CA issued;
 *   - writes the DefaultApplicationGroup trust list again (§7.7.3) when
 *     it or one of its CRLs changes, always before a new certificate;
 *   - reads the Server's rejected list (§7.10.12) every rejectedS seconds
 *     and offers unknown clients as "Register and trust?" dialogs
 *     (push_rejected.h);
 *   - backs off exponentially after a failure, adds random jitter to every
 *     job, and runs at most `concurrency` jobs at once, in the order the
 *     push-scheduling slot picks (gds_plugin.h gds_push_scheduler);
 *   - does nothing on a STANDBY node (gds_server_set_role); after a node
 *     becomes primary it looks at every Server again. Nothing the engine
 *     knows is persisted: a job first looks at what the Server holds, so
 *     every job is idempotent and a restarted or new primary resumes.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_PUSH_ENGINE_H
#define OPENGDS_PUSH_ENGINE_H

#include <open62541/types.h>

#include <stdbool.h>
#include <stdint.h>

#include "common/buf.h"
#include "common/compiler.h"
#include "common/errors.h"
#include "gds_server.h"

#define PUSH_ACTOR "opengds-push" /* ClientUserId of the engine's audit events */
#define PUSH_MAX_CONCURRENCY 64u

typedef struct {
    gds_server *server;
    gds_buf cert, key;          /* the GDS's own certificate and key (borrowed) */
    /* The GDS's issuing CA certificates (borrowed): a Server certificate
     * one of them issued is the GDS's; any other is replaced at once.
     * None: every CA in the trust list counts as the GDS's. */
    const gds_buf *issuers;
    size_t issuersN;
    uint32_t tickMs;            /* how often due jobs are looked for; 0: 60 s */
    uint32_t concurrency;       /* jobs at once, 1..PUSH_MAX_CONCURRENCY; 0: 4 */
    uint32_t jitterS;           /* random delay of every job, 0..jitterS */
    uint32_t backoffMinS;       /* 0: 60 */
    uint32_t backoffMaxS;       /* 0: 6 h */
    uint32_t rejectedS;         /* GetRejectedList period; 0: never */
    uint32_t timeoutMs;         /* per request on the Server; 0: 10 s */
    uint32_t signTimeoutMs;     /* gds_server_sign_request; 0: 60 s */
    uint32_t presentTimeoutMs;  /* new certificate on the endpoints; 0: 30 s */
} push_engine_cfg;

typedef struct push_engine push_engine;

/* Starts the engine thread and its workers; the first tick runs at once.
 * With rejectedS the Push object and its dialogs are added to the server.
 * Call before or after gds_server_run, never from the server thread. */
GDS_MUST_CHECK gds_status push_engine_start(const push_engine_cfg *cfg, push_engine **out);
/* Waits for running jobs, then stops. */
void push_engine_stop(push_engine *e);
/* Tick now (tests, SIGHUP). */
void push_engine_kick(push_engine *e);

/* What the engine knows about one target (tests, logs). */
typedef struct {
    bool known;              /* a job looked at the Server */
    bool certOurs;
    UA_DateTime certNotAfter;
    bool trustListCurrent;   /* the Server holds the current list */
    uint32_t failures;
    UA_StatusCode lastResult;
    uint64_t jobs, trustListPushes, certificatePushes, rejectedHarvests;
} push_target_status;
/* GDS_ENOTFOUND: not a target (yet). */
GDS_MUST_CHECK gds_status push_engine_status(push_engine *e, const char *applicationUri,
                                             push_target_status *out);
/* Open "Register and trust?" dialogs (tests). */
size_t push_engine_open_dialogs(push_engine *e);

#endif
