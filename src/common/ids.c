/* OpenGDS - unguessable identifiers.
 * SPDX-License-Identifier: MPL-2.0 */
#include "ids.h"

#include <openssl/rand.h>

#include "banned.h"

gds_status gds_guid_random(UA_Guid *out) {
    unsigned char b[16];
    if(RAND_bytes(b, sizeof(b)) != 1)
        return GDS_ECRYPTO;
    out->data1 = (UA_UInt32)b[0] << 24 | (UA_UInt32)b[1] << 16 | (UA_UInt32)b[2] << 8 | b[3];
    out->data2 = (UA_UInt16)((unsigned)b[4] << 8 | b[5]);
    /* RFC 9562 version 4, variant 1 */
    out->data3 = (UA_UInt16)(((unsigned)b[6] << 8 | b[7]) & 0x0FFFu) | 0x4000u;
    for(size_t i = 0; i < 8; i++)
        out->data4[i] = b[8 + i];
    out->data4[0] = (UA_Byte)((out->data4[0] & 0x3Fu) | 0x80u);
    return GDS_OK;
}

gds_status gds_handle_random(UA_UInt32 *out) {
    UA_UInt32 h = 0;
    while(h == 0)
        if(RAND_bytes((unsigned char *)&h, sizeof(h)) != 1)
            return GDS_ECRYPTO;
    *out = h;
    return GDS_OK;
}
