# Client profile: the fake GDS, its faults and the CLI-* tests
# SPDX-License-Identifier: MPL-2.0
add_library(gdsaudit_profile_client STATIC
    fake_gds.c
    faults.c
    trigger.c
    probe.c
    csr_check.c
    cli_csr.c
    cli_register.c
    cli_pending.c
    cli_renew.c
    cli_trustlist.c
    cli_install.c
    cli_faults.c cli_trust.c
    client_main.c)
target_include_directories(gdsaudit_profile_client PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(gdsaudit_profile_client PUBLIC gdsaudit_core)
if(NOT GDSAUDIT_SELFTESTS) # tests and self-test targets: full Linux builds only
    return()
endif()

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
# The slow tests (about 6 minutes): ctest -L slow
add_test(NAME client_profile_slow
         COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/run_client_profile.sh"
                 "$<TARGET_FILE_DIR:gdsaudit>" "${CMAKE_CURRENT_BINARY_DIR}/slow-run"
                 "${CMAKE_CURRENT_SOURCE_DIR}/expected" slow)
set_tests_properties(client_profile_vs_pull_test_client client_profile_mutants client_profile_slow
                     PROPERTIES TIMEOUT 1500)
set_tests_properties(client_profile_slow PROPERTIES ENVIRONMENT GDS_PORT=4861 LABELS slow)
set_tests_properties(client_profile_vs_pull_test_client PROPERTIES ENVIRONMENT GDS_PORT=4853)
set_tests_properties(client_profile_mutants PROPERTIES ENVIRONMENT GDS_PORT=4855)
