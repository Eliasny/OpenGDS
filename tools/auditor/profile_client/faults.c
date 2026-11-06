/* OpenGDS Auditor client profile - fault catalogue. See faults.h.
 * SPDX-License-Identifier: MPL-2.0 */
#include "faults.h"

#include <string.h>

#include "common/banned.h"

static const char *const names[FAULT_COUNT] = {"none", "renew", "sign-uri-invalid", "pending", "reject", "tl-short-reads",
    "tl-with-x", "tl-main", "tl-issuer-y", "issue-untrusted", "issue-wrong-key", "issue-wrong-uri",
    "issue-expired", "gds-rogue", "gds-revoked", "gds-expired", "gds-wronguri"};

const char *fault_name(fault_id f) {
    return (unsigned)f < FAULT_COUNT ? names[f] : "?";
}

fg_behaviour fault_behaviour(fault_id f) {
    fg_behaviour b;
    memset(&b, 0, sizeof(b)); /* Good status codes, no caps */
    switch(f) {
    case FAULT_RENEW:
        b.forceUpdateRequired = true;
        break;
    case FAULT_SIGN_URI_INVALID:
        b.forceUpdateRequired = true;
        b.signResult = UA_STATUSCODE_BADCERTIFICATEURIINVALID;
        break;
    case FAULT_PENDING:
        b.forceUpdateRequired = true;
        b.approveAfter = 3;
        break;
    case FAULT_REJECT:
        b.forceUpdateRequired = true;
        b.finishResult = UA_STATUSCODE_BADREQUESTNOTALLOWED;
        break;
    case FAULT_TL_SHORT_READS:
        b.tlReadMax = 256;
        b.tlChanged = true;
        break;
    case FAULT_TL_WITH_X:
        b.tlChanged = true;
        b.tl = FG_TL_WITH_X;
        break;
    case FAULT_TL_MAIN:
        b.tlChanged = true;
        break;
    case FAULT_TL_ISSUER_Y:
        b.tlChanged = true;
        b.tl = FG_TL_ISSUER_Y;
        break;
    case FAULT_ISSUE_UNTRUSTED:
        b.forceUpdateRequired = true;
        b.issue = FG_ISSUE_UNTRUSTED;
        break;
    case FAULT_ISSUE_WRONG_KEY:
        b.forceUpdateRequired = true;
        b.issue = FG_ISSUE_WRONG_KEY;
        break;
    case FAULT_ISSUE_WRONG_URI:
        b.forceUpdateRequired = true;
        b.issue = FG_ISSUE_WRONG_URI;
        break;
    case FAULT_ISSUE_EXPIRED:
        b.forceUpdateRequired = true;
        b.issue = FG_ISSUE_EXPIRED;
        break;
    case FAULT_GDS_ROGUE:
        b.identity = FG_ID_ROGUE;
        b.forceUpdateRequired = true;
        b.issue = FG_ISSUE_ROGUE;
        b.tl = FG_TL_ROGUE;
        b.tlChanged = true;
        break;
    case FAULT_GDS_REVOKED:
        b.identity = FG_ID_REVOKED;
        break;
    case FAULT_GDS_EXPIRED:
        b.identity = FG_ID_EXPIRED;
        break;
    case FAULT_GDS_WRONG_URI:
        b.identity = FG_ID_WRONGURI;
        break;
    case FAULT_NONE:
    case FAULT_COUNT:
        break;
    }
    return b;
}
