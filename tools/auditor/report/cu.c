/* OpenGDS Auditor - ConformanceUnit lookup (cu.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include "cu.h"

#include <string.h>

#include "common/banned.h"

const char *ga_conformance_unit(const char *id) {
    if(!id)
        return NULL;
    for(size_t i = 0; i < ga_cu_table_len; i++)
        if(strcmp(ga_cu_table[i].id, id) == 0)
            return ga_cu_table[i].cu;
    return NULL;
}
