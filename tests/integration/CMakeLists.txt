# OpenGDS integration tests (OpenGDS plan, tests/integration/)
# SPDX-License-Identifier: MPL-2.0

# T2 push tracer gate: the push engine against the Auditor's push_test_server.
# Signing uses the Auditor's test CA (gdsaudit_core) until the daemon hook.
add_executable(test_push_flow test_push_flow.c)
target_link_libraries(test_push_flow PRIVATE gds_push gdsaudit_core)

set(PUSH_FLOW_WORK "${CMAKE_CURRENT_BINARY_DIR}/push-flow-run")
add_test(NAME integration_push_flow_clean
         COMMAND "${CMAKE_COMMAND}" -E rm -rf "${PUSH_FLOW_WORK}")
set_tests_properties(integration_push_flow_clean PROPERTIES FIXTURES_SETUP push_flow_work)
add_test(NAME integration_push_flow
         COMMAND test_push_flow "$<TARGET_FILE:push_test_server>" "${PUSH_FLOW_WORK}" 4871)
set_tests_properties(integration_push_flow PROPERTIES TIMEOUT 120 FIXTURES_REQUIRED push_flow_work)

# W3 push scheduler: push_engine.c in an in-process GDS against
# push_test_server (renewal, trust-list re-push, rejected-list dialogs,
# back-off, standby, the scheduler slot)
add_executable(test_push_engine test_push_engine.c)
target_link_libraries(test_push_engine PRIVATE gds_push_engine gds_daemon gdsaudit_core)
set(PUSH_ENGINE_WORK "${CMAKE_CURRENT_BINARY_DIR}/push-engine-run")
add_test(NAME integration_push_engine_clean
         COMMAND "${CMAKE_COMMAND}" -E rm -rf "${PUSH_ENGINE_WORK}")
set_tests_properties(integration_push_engine_clean PROPERTIES FIXTURES_SETUP push_engine_work)
add_test(NAME integration_push_engine
         COMMAND test_push_engine "$<TARGET_FILE:push_test_server>" "${PUSH_ENGINE_WORK}" 4881)
set_tests_properties(integration_push_engine PROPERTIES TIMEOUT 600 FIXTURES_REQUIRED push_engine_work)

# T1 pull tracer: gdsaudit and pull_test_client against opengdsd + opengds-signer
add_subdirectory(pull)

# T2 push tracer: gdsadm push now through opengdsd to push_test_server
add_subdirectory(push)
