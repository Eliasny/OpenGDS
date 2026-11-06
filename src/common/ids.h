/* OpenGDS - identifiers handed to clients (ApplicationId, RequestId, file
 * handles) come from the OpenSSL CSPRNG, never from UA_Guid_random (which is
 * not cryptographic), so they cannot be guessed.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_COMMON_IDS_H
#define OPENGDS_COMMON_IDS_H

#include <open62541/types.h>

#include "compiler.h"
#include "errors.h"

GDS_MUST_CHECK gds_status gds_guid_random(UA_Guid *out);
/* Non-zero random 32-bit handle */
GDS_MUST_CHECK gds_status gds_handle_random(UA_UInt32 *out);

#endif
