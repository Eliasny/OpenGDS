/* OpenGDS Auditor client profile - fault catalogue (Auditor plan faults.c).
 * Each fault is a named way for the fake GDS to answer one pull cycle.
 * The catalogue grows with the test groups (docs/auditor/client-profile.md).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_FAULTS_H
#define GDSAUDIT_FAULTS_H

#include "fake_gds.h"

typedef enum {
    FAULT_NONE = 0,       /* a correct GDS: approve at once, issue, serve the trust list */
    FAULT_RENEW,          /* GetCertificateStatus says UpdateRequired TRUE (12 §7.9.10) */
    FAULT_SIGN_URI_INVALID, /* StartSigningRequest answers Bad_CertificateUriInvalid (12 §7.9.3) */
    FAULT_PENDING,        /* a new request; FinishRequest says Bad_NothingToDo 3 times (12 §7.9.5) */
    FAULT_REJECT,         /* a new request; FinishRequest says Bad_RequestNotAllowed (12 §7.9.5) */
    FAULT_TL_SHORT_READS, /* the trust list changed; Read returns at most 256 bytes (10000-20 §4.2.4) */
    FAULT_TL_WITH_X,      /* the trust list changed: CA X added to TrustedCertificates */
    FAULT_TL_MAIN,        /* the trust list changed back: X removed (12 §7.8.2.8 replaces) */
    FAULT_TL_ISSUER_Y,    /* the trust list changed: CA Y in IssuerCertificates only */
    FAULT_ISSUE_UNTRUSTED, /* a new request; the certificate is from a CA no list holds */
    FAULT_ISSUE_WRONG_KEY, /* a new request; the certificate is for another key */
    FAULT_ISSUE_WRONG_URI, /* a new request; the certificate names another ApplicationUri */
    FAULT_ISSUE_EXPIRED,  /* a new request; the certificate has expired */
    FAULT_GDS_ROGUE,      /* gds-rogue: a GDS cert from ca-rogue, which also issues and lists ca-rogue */
    FAULT_GDS_REVOKED,    /* gds-revoked: the GDS cert is on the GDS CA's CRL */
    FAULT_GDS_EXPIRED,    /* gds-expired: the GDS cert has expired */
    FAULT_GDS_WRONG_URI,  /* gds-wronguri: the GDS cert names another ApplicationUri */
    FAULT_TL_REVOKING,    /* the trust list changed: the CA's CRL revokes the probe's certificate */
    FAULT_TL_GARBAGE,     /* the trust list changed: a truncated, malformed TrustListDataType */
    FAULT_HUGE_ISSUERS,   /* a new request; FinishRequest returns 10 000 IssuerCertificates */
    FAULT_TL_OVER_READ,   /* the trust list changed; Read returns more than Length (a rogue list) */
    FAULT_CLOSE_SESSIONS, /* the GDS closes each session after its first call */
    FAULT_DROP_AFTER_SIGN, /* a new request; then the session is closed and the request forgotten */
    FAULT_TL_DROP,        /* the trust list changed; the session is closed after the first Read */
    FAULT_FINISH_HANG,    /* a new request; FinishRequest does not answer */
    FAULT_ISSUE_INTERMEDIATE, /* a new request; issued by ca-int, chain ca-int, ca */
    FAULT_PENDING_HOLD,   /* a new request; FinishRequest says Bad_NothingToDo all cycle */
    FAULT_UPDATE_FREQUENCY, /* TrustList UpdateFrequency set (the run sets the value) */
    FAULT_ISSUE_SHORT,    /* a new request; a certificate that expires soon (the run sets when) */
    FAULT_REFUSE_ANONYMOUS, /* ActivateSession refuses Anonymous: the client needs credentials */
    FAULT_COUNT
} fault_id;

const char *fault_name(fault_id f);
/* The behaviour of the fake GDS for one cycle with this fault. */
fg_behaviour fault_behaviour(fault_id f);

#endif
