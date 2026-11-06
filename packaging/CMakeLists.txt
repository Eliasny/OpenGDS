# OpenGDS - install rules and packages (.deb, .rpm, .tar.gz) through CPack.
# SPDX-License-Identifier: MPL-2.0
#
#   cmake --install build --prefix /usr --component opengds
#   cpack --config build/CPackConfig.cmake -G "DEB;RPM;TGZ"
#
# scripts/release/build-release.sh drives this for releases; docs/packaging.md
# lists what goes where. The packages only depend on glibc and SQLite:
# OpenSSL 3.5 and open62541 v1.5.10 are linked statically (decision G2).
include(GNUInstallDirs)

# Components:
#   opengds   opengdsd, opengds-signer, gdsadm, systemd units, sysusers entries
#   gdsaudit  the OpenGDS Auditor command-line tool
set(OPENGDS_LIBEXECDIR "${CMAKE_INSTALL_LIBEXECDIR}/opengds")
set(OPENGDS_UNITDIR "lib/systemd/system" CACHE STRING "systemd system unit directory (relative to the prefix)")
set(OPENGDS_SYSUSERSDIR "lib/sysusers.d" CACHE STRING "sysusers.d directory (relative to the prefix)")
set(OPENGDS_DOCDIR "${CMAKE_INSTALL_DATADIR}/doc/opengds")

if(TARGET opengdsd)
    install(TARGETS opengdsd gdsadm RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT opengds)
    install(TARGETS opengds-signer RUNTIME DESTINATION "${OPENGDS_LIBEXECDIR}" COMPONENT opengds)

    # The unit and the example configuration name /usr/bin and
    # /usr/libexec/opengds: packages always install under /usr.
    install(FILES systemd/opengds.service systemd/opengds-signer.socket
                  systemd/opengds-signer@.service
            DESTINATION "${OPENGDS_UNITDIR}" COMPONENT opengds)
    install(FILES sysusers/opengds.conf DESTINATION "${OPENGDS_SYSUSERSDIR}" COMPONENT opengds)
    install(FILES opengds.conf.example
                  "${CMAKE_SOURCE_DIR}/docs/opengdsd.md"
                  "${CMAKE_SOURCE_DIR}/docs/packaging.md"
            DESTINATION "${OPENGDS_DOCDIR}" COMPONENT opengds)
    install(FILES "${CMAKE_SOURCE_DIR}/LICENSE" DESTINATION "${OPENGDS_DOCDIR}" COMPONENT opengds)
endif()

if(TARGET gdsaudit)
    install(TARGETS gdsaudit RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT gdsaudit)
    install(FILES "${CMAKE_SOURCE_DIR}/LICENSE"
            DESTINATION "${CMAKE_INSTALL_DATADIR}/doc/gdsaudit" COMPONENT gdsaudit)
endif()

# The units' sandbox is part of the product: systemd-analyze must rate each
# service below 2.0 (docs/architecture.md, "Around the process"). Skipped where
# systemd-analyze cannot check unit files offline (systemd < 252).
find_program(SYSTEMD_ANALYZE systemd-analyze)
if(SYSTEMD_ANALYZE AND TARGET opengdsd)
    foreach(unit opengds.service opengds-signer@.service)
        add_test(NAME packaging_exposure_${unit}
                 COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tests/check_unit_exposure.sh"
                         "${SYSTEMD_ANALYZE}" "${CMAKE_CURRENT_SOURCE_DIR}/systemd/${unit}" 2.0)
        set_tests_properties(packaging_exposure_${unit} PROPERTIES SKIP_RETURN_CODE 77)
    endforeach()
endif()
add_test(NAME packaging_install_layout
         COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tests/check_install_layout.sh"
                 "${CMAKE_BINARY_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/layout-run")

include(cpack.cmake)
