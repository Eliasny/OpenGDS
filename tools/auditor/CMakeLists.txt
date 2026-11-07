# OpenGDS Auditor (gdsaudit) - build
# SPDX-License-Identifier: MPL-2.0

# Engine API and result list: events as JSON Lines, HTML and JUnit reports.
# libc only, so the desktop UI links it without open62541.
include(cu_table.cmake)
add_library(gdsaudit_report STATIC
    report/results.c
    report/jsonl.c
    report/report.c
    report/cu.c
    "${GA_CU_TABLE_C}")
target_include_directories(gdsaudit_report PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/report"
    PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(gdsaudit_report PRIVATE gds_hardening)

# Plan files (TOML subset): libc only, linked by the headless binary and
# the desktop UI
add_library(gdsaudit_plan STATIC core/plan.c)
target_include_directories(gdsaudit_plan PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(gdsaudit_plan PRIVATE gds_hardening)
add_executable(test_plan core/test_plan.c)
target_include_directories(test_plan PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(test_plan PRIVATE gdsaudit_plan gds_hardening)
add_test(NAME auditor_plan_files COMMAND test_plan)
# gdsaudit run PLAN gives the run of the command line it stands for
add_test(NAME auditor_run_plan
         COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/cli/test_run_plan.sh"
                 "$<TARGET_FILE_DIR:push_test_server>" "${CMAKE_CURRENT_BINARY_DIR}/plan-run")
set_tests_properties(auditor_run_plan PROPERTIES TIMEOUT 600 ENVIRONMENT "PUSH_PORT=4995")

# Engine core shared by every profile and self-test target
add_library(gdsaudit_core STATIC
    core/x509util.c
    core/test_ca.c
    core/uaclient.c
    core/harness.c)
target_include_directories(gdsaudit_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/core")
target_link_libraries(gdsaudit_core PUBLIC gds_common gdsaudit_report)

# Self-test targets: known-good reference implementations (Auditor plan, selftest/)
add_executable(push_test_server selftest/push_test_server.c selftest/push_mgmt.c
               selftest/push_csr.c)
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
add_subdirectory(profile_server)
target_link_libraries(gdsaudit PRIVATE gdsaudit_profile_server gdsaudit_plan)

# The event stream round trip, the parser's refusals and the report writers
add_executable(test_report report/test_report.c)
target_include_directories(test_report PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(test_report PRIVATE gdsaudit_report gds_hardening)
add_test(NAME auditor_report_events COMMAND test_report)
# Pause and resume between tests (SIGUSR1/SIGUSR2) against push_test_server.
add_test(NAME auditor_pause_resume
         COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/cli/test_pause.sh"
                 "$<TARGET_FILE_DIR:push_test_server>" "${CMAKE_CURRENT_BINARY_DIR}/pause-run")
set_tests_properties(auditor_pause_resume PROPERTIES TIMEOUT 600 ENVIRONMENT "PUSH_PORT=4991")

# Desktop UI (GTK4): view-model in avm/, window in ui/. Built when GTK 4.12+
# is found (AUTO), always (ON) or never (OFF); the headless gdsaudit never
# depends on it.
set(OPENGDS_BUILD_AUDITOR_GUI AUTO CACHE STRING "Build gdsaudit-gui (AUTO, ON, OFF)")
set_property(CACHE OPENGDS_BUILD_AUDITOR_GUI PROPERTY STRINGS AUTO ON OFF)
if(NOT OPENGDS_BUILD_AUDITOR_GUI STREQUAL "OFF")
    find_package(PkgConfig)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(GDSAUDIT_GTK4 IMPORTED_TARGET gtk4>=4.12)
        pkg_check_modules(GDSAUDIT_GIO IMPORTED_TARGET gio-unix-2.0>=2.76)
    endif()
    if(GDSAUDIT_GTK4_FOUND AND GDSAUDIT_GIO_FOUND)
        add_subdirectory(avm)
        add_subdirectory(ui)
    elseif(OPENGDS_BUILD_AUDITOR_GUI STREQUAL "ON")
        message(FATAL_ERROR "gdsaudit-gui needs gtk4 >= 4.12 and gio-unix-2.0 (libgtk-4-dev)")
    else()
        message(STATUS "gdsaudit-gui: gtk4 not found, desktop UI not built")
    endif()
endif()
