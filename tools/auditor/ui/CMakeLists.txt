# Desktop UI: gdsaudit-gui (Auditor plan ui/)
# SPDX-License-Identifier: MPL-2.0
add_executable(gdsaudit-gui app.c win_main.c dlg_allow_changes.c)
target_include_directories(gdsaudit-gui PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(gdsaudit-gui PRIVATE gdsaudit_avm PkgConfig::GDSAUDIT_GTK4 gds_hardening)
# next to gdsaudit, where the UI looks for its engine
set_target_properties(gdsaudit-gui PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/..")

# One smoke run of the real window (Auditor plan, "Shared rules"), on a
# virtual display when xvfb-run is there.
# GTK keeps allocations until exit, so the sanitizer builds suppress leaks
# inside GTK and the graphics stack (lsan.supp); under TSan, GLib's own
# threads are not instrumented, so the test is left out there.
find_program(XVFB_RUN xvfb-run)
if(XVFB_RUN AND NOT OPENGDS_SANITIZE MATCHES "thread")
    add_test(NAME gui_smoke COMMAND "${XVFB_RUN}" -a "$<TARGET_FILE:gdsaudit-gui>" --smoke)
    set_tests_properties(gui_smoke PROPERTIES TIMEOUT 60
                         ENVIRONMENT "GSETTINGS_BACKEND=memory;GTK_A11Y=none;NO_AT_BRIDGE=1;LSAN_OPTIONS=suppressions=${CMAKE_CURRENT_SOURCE_DIR}/lsan.supp:print_suppressions=0")
else()
    message(STATUS "gdsaudit-gui: xvfb-run not found, gui_smoke test skipped")
endif()
