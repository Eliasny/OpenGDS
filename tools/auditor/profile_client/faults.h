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
    FAULT_COUNT
} fault_id;

const char *fault_name(fault_id f);
/* The behaviour of the fake GDS for one cycle with this fault. */
fg_behaviour fault_behaviour(fault_id f);

#endif
