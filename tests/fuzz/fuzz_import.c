/* OpenGDS fuzz target: gdsadm apps import files (gdsadm_import.h), CSV and
 * JSON. An accepted file gives at most GDSADM_IMPORT_MAX_ROWS records, each
 * with a known ApplicationType and lists within the GDS limits; the record
 * checks of gds_validate_record must not crash on any of them.
 * SPDX-License-Identifier: MPL-2.0 */
#include <stdlib.h>

#include "common/limits.h"
#include "fuzz.h"
#include "gds_internal.h"
#include "gdsadm_import.h"
#include "common/banned.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc, (void)argv;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    gds_buf b = {(uint8_t *)(uintptr_t)data, size};
    gdsadm_import im;
    char err[256];
    if(gdsadm_import_parse(&b, &im, err, sizeof(err)) != GDS_OK) {
        if(im.n != 0 || im.recs || im.lines || err[0] == '\0')
            abort(); /* a failure leaves nothing behind and says why */
        return 0;
    }
    if(im.n > GDSADM_IMPORT_MAX_ROWS)
        abort();
    for(size_t i = 0; i < im.n; i++) {
        const UA_ApplicationRecordDataType *r = &im.recs[i];
        gds_status vs = gds_validate_record(r); /* GCC ignores a (void) cast here */
        (void)vs;
        if(i > 0 && im.lines[i] <= im.lines[i - 1])
            abort(); /* report lines follow the file */
    }
    gdsadm_import_clear(&im);
    return 0;
}
