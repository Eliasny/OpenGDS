/* OpenGDS fuzz target: TrustListDataType decode and limits on the client
 * side (docs/architecture.md, fuzz_trustlist.c): a TrustList file read
 * from a managed Server, which may be hostile, through
 * gdsc_trustlist_decode. A file it accepts must be within the entry limits
 * and survive an encode/decode round trip unchanged.
 * The server side only encodes its own TrustList (gds_trustlist.c); there
 * is no server-side decode to fuzz yet.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/types.h>

#include "common/limits.h"
#include "fuzz.h"
#include "client/gdsc_push.h"
#include "common/banned.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc, (void)argv;
    return 0;
}

static void check_round_trip(const UA_TrustListDataType *tl) {
    const UA_DataType *t = &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE];
    GDS_ASSERT(tl->trustedCertificatesSize <= GDS_MAX_TRUSTLIST_ENTRIES &&
               tl->trustedCrlsSize <= GDS_MAX_TRUSTLIST_ENTRIES &&
               tl->issuerCertificatesSize <= GDS_MAX_TRUSTLIST_ENTRIES &&
               tl->issuerCrlsSize <= GDS_MAX_TRUSTLIST_ENTRIES);
    UA_ByteString enc = UA_BYTESTRING_NULL;
    GDS_ASSERT(UA_encodeBinary(tl, t, &enc, NULL) == UA_STATUSCODE_GOOD);
    UA_TrustListDataType again;
    GDS_ASSERT(gdsc_trustlist_decode(&enc, &again) == UA_STATUSCODE_GOOD);
    GDS_ASSERT(UA_order(tl, &again, t) == UA_ORDER_EQ);
    UA_TrustListDataType_clear(&again);
    UA_ByteString_clear(&enc);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    UA_ByteString file = {size, (UA_Byte *)(uintptr_t)data};
    UA_TrustListDataType tl;
    if(gdsc_trustlist_decode(&file, &tl) == UA_STATUSCODE_GOOD)
        check_round_trip(&tl);
    UA_TrustListDataType_clear(&tl);
    return 0;
}
