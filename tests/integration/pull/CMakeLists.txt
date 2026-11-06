# OpenGDS - T1 pull tracer: gdsaudit and pull_test_client against opengdsd
# SPDX-License-Identifier: MPL-2.0
add_test(NAME integration_pull_vs_opengdsd
         COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/run_pull_vs_opengdsd.sh" "${CMAKE_BINARY_DIR}"
                 "${CMAKE_CURRENT_BINARY_DIR}/run" "${CMAKE_CURRENT_SOURCE_DIR}/expected/opengds.csv")
set_tests_properties(integration_pull_vs_opengdsd PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
