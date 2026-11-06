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
    srv_restore.c)
target_include_directories(gdsaudit_profile_server PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(gdsaudit_profile_server PUBLIC gdsaudit_core)

# The server profile against push_test_server: every test against the good
# target with pinned verdicts, then each --break mutant must be caught by
# the test it was written for (expected/mutants.csv).
add_test(NAME srv_profile_vs_push_test_server
         COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/run_vs_push.sh"
                 "$<TARGET_FILE_DIR:push_test_server>" "${CMAKE_CURRENT_BINARY_DIR}/push-run"
                 "${CMAKE_CURRENT_SOURCE_DIR}/expected")
set_tests_properties(srv_profile_vs_push_test_server PROPERTIES TIMEOUT 1500)
