# OpenGDS - T2 push tracer: gdsadm push now through opengdsd to push_test_server
# SPDX-License-Identifier: MPL-2.0
add_test(NAME integration_push_vs_opengdsd
         COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/run_push_vs_opengdsd.sh" "${CMAKE_BINARY_DIR}"
                 "${CMAKE_CURRENT_BINARY_DIR}/run")
set_tests_properties(integration_push_vs_opengdsd PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
