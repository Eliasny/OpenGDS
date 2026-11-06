# OpenGDS Auditor (gdsaudit) - build
# SPDX-License-Identifier: MPL-2.0

# Engine core shared by every profile and self-test target
add_library(gdsaudit_core STATIC
    core/x509util.c
    core/test_ca.c
    core/uaclient.c
    core/harness.c)
target_include_directories(gdsaudit_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/core")
target_link_libraries(gdsaudit_core PUBLIC gds_common)

# Self-test targets: known-good reference implementations (Auditor plan, selftest/)
add_executable(push_test_server selftest/push_test_server.c)
add_executable(pull_test_client selftest/pull_test_client.c)
# Seeds of the server and client profiles (push_driver plays the
# CertificateManager, mock_gds plays a GDS)
add_executable(push_driver profile_server/push_driver.c)
add_executable(mock_gds profile_client/mock_gds.c)

foreach(t push_test_server pull_test_client push_driver mock_gds)
    target_link_libraries(${t} PRIVATE gdsaudit_core)
endforeach()

# End-to-end self-test: pull, push, restart persistence, non-admin refused
add_test(NAME selftest_demo_flow
         COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/selftest/run_demo.sh"
                 "$<TARGET_FILE_DIR:push_test_server>" "${CMAKE_CURRENT_BINARY_DIR}/demo-run")
set_tests_properties(selftest_demo_flow PROPERTIES TIMEOUT 180)

add_subdirectory(profile_client)
add_subdirectory(profile_gds)
