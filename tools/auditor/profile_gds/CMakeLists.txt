# GDS profile: the OpenGDS T0 spec test programs and the gdsaudit CLI
# SPDX-License-Identifier: MPL-2.0
add_library(gdsaudit_profile_gds STATIC
    gds_target.c
    test_spec_access.c
    test_spec_directory.c
    test_spec_certmgr.c
    test_spec_trustlist.c)
target_include_directories(gdsaudit_profile_gds PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(gdsaudit_profile_gds PUBLIC gdsaudit_core)

add_executable(gdsaudit ../cli/main.c)
target_link_libraries(gdsaudit PRIVATE gdsaudit_profile_gds)
# next to mock_gds and the self-test targets
set_target_properties(gdsaudit PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/..")

# The spec tests against the mock GDS. The expected verdicts are pinned in
# expected/mock_gds.csv: a verdict that changes (also to Pass) fails CI.
add_test(NAME gds_spec_vs_mock_gds
         COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/run_vs_mock.sh"
                 "$<TARGET_FILE_DIR:gdsaudit>" "${CMAKE_CURRENT_BINARY_DIR}/mock-run"
                 "${CMAKE_CURRENT_SOURCE_DIR}/expected/mock_gds.csv")
set_tests_properties(gds_spec_vs_mock_gds PROPERTIES TIMEOUT 180)
