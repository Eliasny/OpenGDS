# Server profile: the Auditor plays the CertificateManager of a push-managed
# Server (docs/auditor/server-profile.md)
# SPDX-License-Identifier: MPL-2.0
add_library(gdsaudit_profile_server STATIC
    srv_target.c
    srv_security.c
    srv_capabilities.c
    srv_trustlist.c
    srv_csr.c
    srv_update.c
    srv_transaction.c
    srv_wire.c
    srv_rejected.c
    srv_persistence.c
    srv_setup.c
    srv_audit.c
    srv_restore.c)
target_include_directories(gdsaudit_profile_server PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(gdsaudit_profile_server PUBLIC gdsaudit_core)

# The server profile against push_test_server: every test against the good
# target with pinned verdicts, then each --break mutant must be caught by
# the test it was written for (expected/mutants.csv).
# Four shards, each under its own timeout (sanitizer builds are slow); the
# good-target runs are in the first.
foreach(k RANGE 1 4)
  math(EXPR port "4861 + 200 * ${k}")
  add_test(NAME srv_profile_vs_push_test_server_${k}
           COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/run_vs_push.sh"
                   "$<TARGET_FILE_DIR:push_test_server>" "${CMAKE_CURRENT_BINARY_DIR}/push-run-${k}"
                   "${CMAKE_CURRENT_SOURCE_DIR}/expected")
  set_tests_properties(srv_profile_vs_push_test_server_${k} PROPERTIES
                       TIMEOUT 1500 ENVIRONMENT "SHARD=${k}/4;PUSH_PORT=${port}")
endforeach()

# A target with a CA-issued certificate: --target-trust and --target-crl
add_test(NAME srv_profile_ca_issued_target
         COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/run_ca_issued.sh"
                 "$<TARGET_FILE_DIR:push_test_server>" "${CMAKE_CURRENT_BINARY_DIR}/ca-issued-run" 5871)
set_tests_properties(srv_profile_ca_issued_target PROPERTIES TIMEOUT 300)
