/* OpenGDS libgdsclient - an application's pull agent: application setup and
 * renewal with PullManagement (OPC 10000-12 v1.05.07 Annex G.1, §7.6
 * Table 21; OpenGDS plan W3, gdsc_pull_agent.c). A vendor embeds it in an
 * OPC UA application so that the application gets its certificate and trust
 * list from a GDS and keeps them fresh.
 * SPDX-License-Identifier: MPL-2.0
 *
 * One run of gdsc_pull_agent_run:
 *   Connect      SignAndEncrypt, our ApplicationInstance Certificate, an
 *                Anonymous token (§7.6 "Connect"). The GDS is trusted only
 *                through the configured trust list: Annex G.1 allows a
 *                connection to an untrusted CertificateManager, but this
 *                agent never does one, so it never sends a secret to one.
 *                Before the first issued certificate, user credentials with
 *                ApplicationAdmin rights may be given (Annex G.1); they are
 *                used for that run only and never persisted (the agent does
 *                not store them; the embedder must not either).
 *   FindApplications, RegisterApplication when the ApplicationUri is not
 *                registered yet (§6.5.4, §6.5.6; Annex G.1).
 *   GetCertificateGroups (§7.9.7): the DefaultApplicationGroup must be
 *                among them; it is the group this agent manages.
 *   SigningRequestPending: FinishRequest at once for a request left pending
 *                by an earlier run (§7.6 Table 21, repeat count 0).
 *   GetCertificateStatus (§7.9.10); when an update is required: a NEW key
 *                pair and CSR (Table 21 "strongly recommended"),
 *                StartSigningRequest (§7.9.3), FinishRequest (§7.9.5)
 *                repeated finishRepeat times (default 2) while
 *                Bad_NothingToDo; then the RequestId is persisted and the next
 *                run continues it.
 *   GetTrustList (§7.9.9): LastUpdateTime is read first and the TrustList is
 *                downloaded only when it changed (Table 21 "GetTrustList").
 *   Persist      a new certificate, key and trust list are handed to the
 *                persist callback together (Table 21 "Persist TrustList":
 *                "persisted at the same time to ensure a consistent setup").
 *   Disconnect.
 * The next run is due after the TrustList's UpdateFrequency (Table 21,
 * option 2); gdsc_pull_result.nextRunMs carries it. */
#ifndef OPENGDS_CLIENT_GDSC_PULL_AGENT_H
#define OPENGDS_CLIENT_GDSC_PULL_AGENT_H

#include <open62541/client.h>
#include <open62541/types_gds_generated.h>

#include <stdbool.h>

#include "common/buf.h"
#include "common/compiler.h"
#include "common/limits.h"

/* What the application keeps between runs (the embedder stores it, e.g. in
 * its PKI directory). Start with the application's own self-signed
 * certificate and key and everything else empty. gdsc_pull_state_clear frees
 * it. */
typedef struct {
    gds_buf cert;                        /* ApplicationInstance Certificate, DER */
    gds_buf key;                         /* its private key, DER */
    gds_buf issuers[GDS_MAX_CHAIN_LEN];  /* issuer chain of an issued certificate */
    size_t issuersN;                     /* 0 = cert was not issued by the GDS */
    UA_NodeId applicationId;             /* null until registered */
    UA_NodeId pendingRequest;            /* null when no request is pending */
    gds_buf pendingKey;                  /* the key pair of the pending request */
    UA_TrustListDataType trustList;      /* the last downloaded TrustList */
    UA_DateTime trustListTime;           /* its LastUpdateTime; 0 = unknown */
} gdsc_pull_state;

void gdsc_pull_state_clear(gdsc_pull_state *st);

/* Persist the whole state at once; GDS_OK when it is durable */
typedef gds_status (*gdsc_pull_persist_fn)(void *ctx, const gdsc_pull_state *st);

typedef struct {
    const char *gdsUrl;   /* opc.tcp://host:port of the GDS */
    const char *gdsUri;   /* expected ApplicationUri of the GDS; NULL = no check */
    const gds_buf *trust; /* certificates that may vouch for the GDS (its CA); required */
    size_t trustN;
    const gds_buf *crls;
    size_t crlN;
    /* The application as it registers itself: ApplicationUri, names, type,
     * ProductUri, DiscoveryUrls (a Server needs at least one) */
    const UA_ApplicationRecordDataType *record;
    /* Optional, before the first issued certificate only (Annex G.1) */
    const char *userName;
    const gds_buf *password;
    UA_NodeId certificateType; /* null = RsaSha256ApplicationCertificateType */
    unsigned finishRepeat;     /* FinishRequest repeats after the first; 0 = 2 */
    UA_UInt32 finishDelayMs;   /* between them; 0 = 1000 */
    UA_UInt32 timeoutMs;       /* per request; 0 = 10 s */
    gdsc_pull_persist_fn persist;
    void *persistCtx;
} gdsc_pull_cfg;

typedef enum {
    GDSC_PULL_STEP_NONE = 0,
    GDSC_PULL_STEP_CONNECT,
    GDSC_PULL_STEP_REGISTER,
    GDSC_PULL_STEP_GROUPS,
    GDSC_PULL_STEP_STATUS,
    GDSC_PULL_STEP_CSR,
    GDSC_PULL_STEP_SIGN,      /* StartSigningRequest / FinishRequest */
    GDSC_PULL_STEP_TRUSTLIST,
    GDSC_PULL_STEP_PERSIST
} gdsc_pull_step;

typedef struct {
    gdsc_pull_step failedStep;
    UA_StatusCode failedCode;
    bool registered;          /* RegisterApplication ran in this run */
    bool updateRequired;      /* GetCertificateStatus said so */
    bool certificateIssued;   /* a new certificate is in the state */
    bool pending;             /* a signing request is still pending */
    bool trustListDownloaded; /* the TrustList changed and was read */
    UA_Double nextRunMs;      /* the TrustList's UpdateFrequency; 0 = unknown */
} gdsc_pull_result;

const char *gdsc_pull_step_name(gdsc_pull_step s);

/* A new key pair for the certificate type (RSA 2048 for the RSA types, the
 * named curve for the NIST ECC types) and a CSR signed with it, naming
 * applicationUri in the SubjectAltName and commonName in the subject. */
GDS_MUST_CHECK gds_status gdsc_make_csr(const UA_NodeId *certType, const char *applicationUri,
                                        const char *commonName, gds_buf *keyOut,
                                        gds_buf *csrOut);

/* One run. The state is updated in place and persisted through the callback
 * whenever it changed. Good when every step succeeded, including a request
 * that is still pending (result.pending). */
GDS_MUST_CHECK UA_StatusCode gdsc_pull_agent_run(const gdsc_pull_cfg *cfg, gdsc_pull_state *st,
                                                 gdsc_pull_result *res);

#endif
