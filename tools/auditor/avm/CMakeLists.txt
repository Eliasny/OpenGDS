# View-model of the desktop UI (Auditor plan avm/): GLib and GIO only, no
# GTK, so it is tested without a display.
# SPDX-License-Identifier: MPL-2.0
add_library(gdsaudit_avm STATIC avm_plan.c avm_planfile.c avm_run.c avm_history.c avm_target.c)
target_include_directories(gdsaudit_avm PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}"
                           PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(gdsaudit_avm PUBLIC gdsaudit_report gdsaudit_plan PkgConfig::GDSAUDIT_GIO
                      PRIVATE gds_hardening)

add_executable(test_avm_plan test_avm_plan.c)
target_include_directories(test_avm_plan PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(test_avm_plan PRIVATE gdsaudit_avm gds_hardening)
add_test(NAME avm_plan COMMAND test_avm_plan)

add_executable(test_avm_history test_avm_history.c)
target_include_directories(test_avm_history PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(test_avm_history PRIVATE gdsaudit_avm gds_hardening)
add_test(NAME avm_history COMMAND test_avm_history)

# The real engine through avm_run: events, output, pause, resume and abort,
# with no target (Linux here; Windows in the installer job, where avm_run
# uses named pipes and the engine's --control events).
add_executable(test_avm_engine test_avm_engine.c)
target_include_directories(test_avm_engine PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(test_avm_engine PRIVATE gdsaudit_avm gds_hardening)

# The rest drives sh scripts and the self-test targets: full Linux builds only
if(GDSAUDIT_SELFTESTS)
add_test(NAME avm_engine
         COMMAND test_avm_engine "$<TARGET_FILE:gdsaudit>" "${CMAKE_CURRENT_BINARY_DIR}/engine-run")
set_tests_properties(avm_engine PROPERTIES TIMEOUT 300)

# Saved targets and discovery parsing, then discovery through the engine
# against push_test_server.
add_executable(test_avm_target test_avm_target.c)
target_include_directories(test_avm_target PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(test_avm_target PRIVATE gdsaudit_avm gds_hardening)
add_test(NAME avm_target
         COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/../cli/test_discover.sh"
                 "$<TARGET_FILE_DIR:push_test_server>" "${CMAKE_CURRENT_BINARY_DIR}/target-run"
                 "$<TARGET_FILE:test_avm_target>")
set_tests_properties(avm_target PROPERTIES TIMEOUT 120 ENVIRONMENT "PUSH_PORT=4997")

# The UI's way of running the engine against push_test_server must give the
# verdicts pinned for the headless run.
add_executable(avm_selftest avm_selftest.c)
target_include_directories(avm_selftest PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(avm_selftest PRIVATE gdsaudit_avm gds_hardening)
set_target_properties(avm_selftest PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/..")
add_test(NAME avm_run_vs_push_test_server
         COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/run_avm_vs_push.sh"
                 "$<TARGET_FILE_DIR:push_test_server>" "${CMAKE_CURRENT_BINARY_DIR}/avm-run"
                 "${CMAKE_CURRENT_SOURCE_DIR}/../profile_server/expected/push_test_server.csv")
set_tests_properties(avm_run_vs_push_test_server PROPERTIES TIMEOUT 300)

# Plan files (AT5 gate): a plan opened in the UI runs to the verdicts of the
# same plan run headless with gdsaudit run.
add_test(NAME avm_plan_vs_headless
         COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/run_avm_plan.sh"
                 "$<TARGET_FILE_DIR:push_test_server>" "$<TARGET_FILE_DIR:avm_selftest>"
                 "${CMAKE_CURRENT_BINARY_DIR}/plan-gate")
set_tests_properties(avm_plan_vs_headless PROPERTIES TIMEOUT 300 ENVIRONMENT "PUSH_PORT=4989")

# Operator prompts through avm_run: the answer pipe and the answer line, with
# a stand-in engine (fake_prompt_engine.sh).
add_executable(test_avm_prompt test_avm_prompt.c)
target_include_directories(test_avm_prompt PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(test_avm_prompt PRIVATE gdsaudit_avm gds_hardening)
add_test(NAME avm_prompt
         COMMAND test_avm_prompt "${CMAKE_CURRENT_SOURCE_DIR}/fake_prompt_engine.sh"
                 "${CMAKE_CURRENT_BINARY_DIR}/prompt-run")
set_tests_properties(avm_prompt PROPERTIES TIMEOUT 30)
endif()
