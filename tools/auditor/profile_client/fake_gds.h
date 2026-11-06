/* OpenGDS Auditor client profile - the fake GDS (Auditor plan profile_client/fake_gds.c).
 *
 * A minimal GDS of its own, not OpenGDS: it has to break the rules on cue,
 * which a correct GDS never does. It runs inside gdsaudit on the Auditor's
 * thread (no server thread), records every method call the client makes and
 * answers according to the current fg_behaviour (faults.c).
 *
 * TEST FIXTURE: in-memory records, a test CA marked "OpenGDS Auditor TEST",
 * loopback only unless listenAny. One instance per process.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_FAKE_GDS_H
#define GDSAUDIT_FAKE_GDS_H

#include <open62541/types.h>

#include <stdbool.h>
#include <stddef.h>

#include "common/buf.h"

typedef enum {
    FG_M_FIND = 0,
    FG_M_REGISTER,
    FG_M_GROUPS,
    FG_M_STATUS,
    FG_M_SIGN,        /* StartSigningRequest */
    FG_M_NEWKEYPAIR,  /* StartNewKeyPairRequest */
    FG_M_FINISH,
    FG_M_TRUSTLIST,   /* GetTrustList */
    FG_M_TL_OPEN,
    FG_M_TL_READ,
    FG_M_TL_CLOSE,
    FG_M_COUNT
} fg_method;

const char *fg_method_name(fg_method m);

#define FG_MAX_URI 256
#define FG_NO_SESSION ((size_t)-1)

typedef enum { FG_TOKEN_ANONYMOUS = 0, FG_TOKEN_USERNAME, FG_TOKEN_X509, FG_TOKEN_OTHER } fg_token;

/* One session the client activated (12 §6.3, Annex G.1). */
typedef struct {
    UA_NodeId id;
    UA_MessageSecurityMode mode;  /* of the SecureChannel it runs on */
    fg_token token;
    char certUri[FG_MAX_URI];     /* SAN URI of the channel's client certificate */
    double tOpen, tClose;         /* monotonic ms */
    bool closed;                  /* CloseSession or timeout */
} fg_session;

/* One method call as the client made it. Owned by the fake GDS. */
typedef struct {
    fg_method method;
    UA_StatusCode result;   /* what the fake GDS answered */
    double tMs;             /* monotonic time of the call */
    char appUri[FG_MAX_URI]; /* ApplicationUri of the record the call names ("" if none) */
    UA_ApplicationType appType;
    size_t discoveryUrlsN;
    char discoveryUrl0[FG_MAX_URI];
    gds_buf csr;            /* StartSigningRequest: CertificateRequest exactly as sent */
    UA_NodeId group;        /* CertificateGroupId argument (Sign, NewKeyPair) */
    UA_NodeId certType;     /* CertificateTypeId argument (Sign, NewKeyPair) */
    gds_buf args;           /* every ByteString/String input, concatenated (leak scans) */
    size_t session;         /* index for fg_session_at, FG_NO_SESSION if unknown */
    UA_NodeId requestId;    /* StartSigningRequest result, FinishRequest argument */
    size_t bytes;           /* TrustList.Read: bytes returned */
} fg_event;

/* How the fake GDS answers. Set per cycle by faults.c. */
typedef struct {
    long approveAfter;          /* FinishRequest answers Bad_NothingToDo this many times */
    bool forceUpdateRequired;   /* GetCertificateStatus always returns TRUE */
    UA_StatusCode signResult;   /* not Good: StartSigningRequest answers with this code */
    UA_StatusCode finishResult; /* not Good: FinishRequest rejects the request for good */
    size_t tlReadMax;           /* not 0: TrustList.Read returns at most this many bytes */
    bool tlChanged;             /* the trust list changes (new LastUpdateTime) for this cycle */
} fg_behaviour;

typedef struct {
    const char *workDir;   /* CA, identity and client files go below it */
    long port;
    bool listenAny;
    const char *user;      /* registrar credentials the client is given */
    const char *password;
} fg_config;

/* Start the server (listening, not yet iterating). */
GDS_MUST_CHECK gds_status fg_start(const fg_config *cfg);
/* Serve pending network events; returns quickly. */
void fg_iterate(void);
void fg_stop(void);

void fg_set_behaviour(const fg_behaviour *b);
/* Events recorded so far. Indices stay valid until fg_stop. */
size_t fg_event_count(void);
const fg_event *fg_event_at(size_t i);
size_t fg_session_count(void);
const fg_session *fg_session_at(size_t i);
/* Size of the encoded TrustListDataType the TrustList file serves */
size_t fg_trustlist_size(void);

/* Files the trigger hands to the client */
const char *fg_url(void);
const char *fg_ca_path(void);
const char *fg_crl_path(void);
const char *fg_password_path(void);

/* The NodeIds the fake GDS offers (GDS namespace bound at start) */
UA_NodeId fg_default_group(void);
UA_NodeId fg_listed_cert_type(void); /* RsaSha256ApplicationCertificateType */

#endif
