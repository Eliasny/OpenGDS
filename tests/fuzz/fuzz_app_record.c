/* OpenGDS fuzz target: ApplicationRecordDataType validation in
 * RegisterApplication / UpdateApplication (docs/architecture.md,
 * fuzz_app_record.c). The input is a binary-encoded record, decoded by
 * open62541 as the method argument would be, then checked by
 * gds_validate_record. A record it accepts must also give the certificate
 * subjectAltName the CA builds from it (cax_add_san), and the subject name
 * is built as the CA would.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/types.h>
#include <open62541/types_gds_generated.h>
#include <openssl/x509.h>

#include "ca_x509.h"
#include "common/limits.h"
#include "fuzz.h"
#include "gds_internal.h"
#include "common/banned.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc, (void)argv;
    return 0;
}

static void check_valid(const UA_ApplicationRecordDataType *rec) {
    X509 *x = X509_new();
    GDS_ASSERT(x);
    /* every record the GDS accepts can be put into a certificate */
    GDS_ASSERT(cax_add_san(x, rec) == GDS_OK);
    X509_free(x);
    X509_NAME *n = NULL;
    if(cax_make_name(&rec->applicationNames[0].text, "OpenGDS fuzz", &n) == GDS_OK)
        X509_NAME_free(n);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if(size > GDS_MAX_RECORD_SIZE)
        return 0;
    UA_ByteString in = {size, (UA_Byte *)(uintptr_t)data};
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    if(UA_decodeBinary(&in, &rec, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE], NULL) ==
           UA_STATUSCODE_GOOD &&
       gds_validate_record(&rec) == UA_STATUSCODE_GOOD)
        check_valid(&rec);
    UA_ApplicationRecordDataType_clear(&rec);
    return 0;
}
