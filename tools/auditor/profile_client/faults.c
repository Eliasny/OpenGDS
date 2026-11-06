/* OpenGDS Auditor client profile - fault catalogue. See faults.h.
 * SPDX-License-Identifier: MPL-2.0 */
#include "faults.h"

#include <string.h>

#include "common/banned.h"

static const char *const names[FAULT_COUNT] = {"none", "renew", "sign-uri-invalid", "pending", "reject", "tl-short-reads"};

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
    case FAULT_NONE:
    case FAULT_COUNT:
        break;
    }
    return b;
}
