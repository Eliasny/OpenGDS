/* OpenGDS Auditor client profile - fault catalogue. See faults.h.
 * SPDX-License-Identifier: MPL-2.0 */
#include "faults.h"

#include "common/banned.h"

static const char *const names[FAULT_COUNT] = {"none", "renew", "sign-uri-invalid"};

const char *fault_name(fault_id f) {
    return (unsigned)f < FAULT_COUNT ? names[f] : "?";
}

fg_behaviour fault_behaviour(fault_id f) {
    fg_behaviour b = {0, false, UA_STATUSCODE_GOOD};
    switch(f) {
    case FAULT_RENEW:
        b.forceUpdateRequired = true;
        break;
    case FAULT_SIGN_URI_INVALID:
        b.forceUpdateRequired = true;
        b.signResult = UA_STATUSCODE_BADCERTIFICATEURIINVALID;
        break;
    case FAULT_NONE:
    case FAULT_COUNT:
        break;
    }
    return b;
}
