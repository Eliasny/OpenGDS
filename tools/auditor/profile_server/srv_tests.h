/* OpenGDS Auditor server profile: the SRV-* tests of
 * docs/auditor/server-profile.md, one array per catalogue group.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_SRV_TESTS_H
#define GDSAUDIT_SRV_TESTS_H

#include "harness.h"

extern const ga_test srv_security_tests[];
extern const size_t srv_security_count;
extern const ga_test srv_capabilities_tests[];
extern const size_t srv_capabilities_count;
extern const ga_test srv_trustlist_tests[];
extern const size_t srv_trustlist_count;
extern const ga_test srv_csr_tests[];
extern const size_t srv_csr_count;
extern const ga_test srv_update_tests[];
extern const size_t srv_update_count;
extern const ga_test srv_transaction_tests[];
extern const size_t srv_transaction_count;
extern const ga_test srv_wire_tests[];
extern const size_t srv_wire_count;
extern const ga_test srv_rejected_tests[];
extern const size_t srv_rejected_count;
extern const ga_test srv_persistence_tests[];
extern const size_t srv_persistence_count;
extern const ga_test srv_restore_tests[];
extern const size_t srv_restore_count;

#endif
