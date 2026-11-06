# Client profile: the fake GDS, its faults and the CLI-* tests
# SPDX-License-Identifier: MPL-2.0
add_library(gdsaudit_profile_client STATIC
    fake_gds.c
    faults.c
    trigger.c
    csr_check.c
    cli_csr.c
    cli_register.c
    cli_pending.c
    cli_renew.c
    cli_trustlist.c
    client_main.c)
target_include_directories(gdsaudit_profile_client PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(gdsaudit_profile_client PUBLIC gdsaudit_core)

# The client profile against the good pull test client (pinned verdicts) and
# against each of its --break mutants (each must trip its own test).
add_test(NAME client_profile_vs_pull_test_client
         COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/run_client_profile.sh"
                 "$<TARGET_FILE_DIR:gdsaudit>" "${CMAKE_CURRENT_BINARY_DIR}/good-run"
                 "${CMAKE_CURRENT_SOURCE_DIR}/expected" good)
add_test(NAME client_profile_mutants
         COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/run_client_profile.sh"
                 "$<TARGET_FILE_DIR:gdsaudit>" "${CMAKE_CURRENT_BINARY_DIR}/mutant-run"
                 "${CMAKE_CURRENT_SOURCE_DIR}/expected" mutants)
set_tests_properties(client_profile_vs_pull_test_client client_profile_mutants
                     PROPERTIES TIMEOUT 900)
set_tests_properties(client_profile_vs_pull_test_client PROPERTIES ENVIRONMENT GDS_PORT=4853)
set_tests_properties(client_profile_mutants PROPERTIES ENVIRONMENT GDS_PORT=4854)
