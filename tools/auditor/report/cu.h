/* OpenGDS Auditor - the ConformanceUnit each test belongs to, from the test
 * catalogue (docs/auditor/catalogue.csv; the table is generated at build
 * time by cu_table.cmake). ConformanceUnit names are those of the OPC
 * Foundation profile reporting site; a result per ConformanceUnit in an
 * Auditor report is a self-test result, not certification.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_CU_H
#define GDSAUDIT_CU_H

#include <stddef.h>

typedef struct {
    const char *id, *cu;
} ga_cu_row;

extern const ga_cu_row ga_cu_table[];
extern const size_t ga_cu_table_len;

/* "TBD" in the catalogue: the unit is not named yet */
#define GA_CU_TBD "TBD"

/* The catalogue's unit for test id, GA_CU_TBD if not named yet, or NULL if
 * the test is not in the catalogue. */
const char *ga_conformance_unit(const char *id);

#endif
