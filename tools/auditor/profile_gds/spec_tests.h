/* OpenGDS T0 spec test programs: the GDS profile of the Auditor.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_SPEC_TESTS_H
#define GDSAUDIT_SPEC_TESTS_H

#include "gds_target.h"
#include "harness.h"

extern const ga_test spec_access_tests[];
extern const size_t spec_access_count;
extern const ga_test spec_directory_tests[];
extern const size_t spec_directory_count;
extern const ga_test spec_certmgr_tests[];
extern const size_t spec_certmgr_count;
extern const ga_test spec_trustlist_tests[];
extern const size_t spec_trustlist_count;
extern const ga_test spec_query_tests[];
extern const size_t spec_query_count;
extern const ga_test spec_revoke_tests[];
extern const size_t spec_revoke_count;
extern const ga_test spec_keypair_tests[];
extern const size_t spec_keypair_count;
extern const ga_test spec_tlwrite_tests[];
extern const size_t spec_tlwrite_count;
extern const ga_test spec_keycred_tests[];
extern const size_t spec_keycred_count;
extern const ga_test spec_authz_tests[];
extern const size_t spec_authz_count;
extern const ga_test spec_events_tests[];
extern const size_t spec_events_count;
extern const ga_test spec_roles_tests[];
extern const size_t spec_roles_count;
extern const ga_test spec_part18_tests[];
extern const size_t spec_part18_count;
extern const ga_test spec_model_tests[];
extern const size_t spec_model_count;

/* For the KeyCredential audit tests (test_spec_events.c): on the first
 * KeyCredentialService (test_spec_keycred.c) one StartRequest refused
 * (unknown ApplicationUri) and one full request flow for a new
 * application, then, with revoke, Revoke of the credential. False when
 * there is no service or the setup failed (the verdict is then given). */
typedef struct {
    char resourceUri[1024];
    UA_StatusCode refused, flow, revoke;
} spec_kc_run;
bool spec_kc_exercise(ga_ctx *ctx, gds_target *t, bool revoke, spec_kc_run *out);

#endif
