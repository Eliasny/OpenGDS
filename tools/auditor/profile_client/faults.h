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
    FAULT_COUNT
} fault_id;

const char *fault_name(fault_id f);
/* The behaviour of the fake GDS for one cycle with this fault. */
fg_behaviour fault_behaviour(fault_id f);

#endif
