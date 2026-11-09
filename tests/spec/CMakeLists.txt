# OpenGDS spec tests against the Auditor's test targets (OpenGDS plan,
# tests/spec/): OPC 10000-12 Annex G application setup, pull and push, with
# Reverse Connect
# SPDX-License-Identifier: MPL-2.0
add_executable(test_spec_annex_g test_spec_annex_g.c)
target_link_libraries(test_spec_annex_g PRIVATE gds_push gdsaudit_core)

set(ANNEX_G_WORK "${CMAKE_CURRENT_BINARY_DIR}/annex-g-run")
add_test(NAME spec_annex_g_clean COMMAND "${CMAKE_COMMAND}" -E rm -rf "${ANNEX_G_WORK}")
set_tests_properties(spec_annex_g_clean PROPERTIES FIXTURES_SETUP annex_g_work)
add_test(NAME spec_annex_g
         COMMAND test_spec_annex_g "$<TARGET_FILE:push_test_server>" "$<TARGET_FILE:mock_gds>"
                 "${ANNEX_G_WORK}" 4900)
set_tests_properties(spec_annex_g PROPERTIES TIMEOUT 240 FIXTURES_REQUIRED annex_g_work)

# The same flows end to end with opengdsd: gdsadm push setup (also over
# Reverse Connect) and examples/pull_agent (built with OPENGDS_BUILD_TESTS)
if(TARGET pull_agent)
    add_test(NAME spec_annex_g_vs_opengdsd
             COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/run_annex_g_vs_opengdsd.sh"
                     "${CMAKE_BINARY_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/opengdsd-run")
    set_tests_properties(spec_annex_g_vs_opengdsd PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
endif()
