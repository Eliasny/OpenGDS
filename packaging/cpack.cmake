# OpenGDS - CPack settings for the .deb, .rpm and .tar.gz packages.
# SPDX-License-Identifier: MPL-2.0
#
# One package per component: `opengds` (server) and `gdsaudit` (Auditor CLI).
# Reproducible: scripts/release/build-release.sh sets SOURCE_DATE_EPOCH from
# the release commit, and every timestamp below derives from it.

set(CPACK_PACKAGE_NAME "opengds")
set(CPACK_PACKAGE_VENDOR "OpenGDS project")
set(CPACK_PACKAGE_CONTACT "OpenGDS maintainers <https://github.com/Eliasny/OpenGDS/issues>")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/Eliasny/OpenGDS")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "OPC UA Global Discovery Server (OPC 10000-12)")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
set(CPACK_STRIP_FILES ON)
set(CPACK_SOURCE_GENERATOR "")
# Package release number (the "-1" in 0.1.0-1); bump it to re-package the
# same source.
set(OPENGDS_PACKAGE_RELEASE "1" CACHE STRING "Package release number")

set(CPACK_COMPONENTS_ALL)
if(TARGET opengdsd)
    list(APPEND CPACK_COMPONENTS_ALL opengds)
endif()
if(TARGET gdsaudit)
    list(APPEND CPACK_COMPONENTS_ALL gdsaudit)
endif()
if(TARGET gdsaudit-gui)
    list(APPEND CPACK_COMPONENTS_ALL gdsaudit-gui)
endif()
set(CPACK_COMPONENT_OPENGDS_DISPLAY_NAME "OpenGDS server")
set(CPACK_COMPONENT_OPENGDS_DESCRIPTION
    "opengdsd serves the OPC UA Global Discovery Server information model of\nOPC 10000-12: application directory, pull and push certificate management\nand trust lists. The CA key is held by a separate opengds-signer process.")
set(CPACK_COMPONENT_GDSAUDIT_DISPLAY_NAME "OpenGDS Auditor")
set(CPACK_COMPONENT_GDSAUDIT_DESCRIPTION
    "gdsaudit tests GDSs, GDS-ready servers and pull clients against\nOPC 10000-12. Its results are a self-test, not OPC Foundation certification.")
set(CPACK_COMPONENT_GDSAUDIT-GUI_DISPLAY_NAME "OpenGDS Auditor desktop UI")
set(CPACK_COMPONENT_GDSAUDIT-GUI_DESCRIPTION
    "gdsaudit-gui runs the OpenGDS Auditor from a GTK 4 window: targets,\nplans, live results, history and reports. Its results are a self-test,\nnot OPC Foundation certification.")

# --- Debian -----------------------------------------------------------------
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_RELEASE "${OPENGDS_PACKAGE_RELEASE}")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
# dpkg-shlibdeps derives the real runtime dependencies (libc6, libsqlite3-0).
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_OPENGDS_PACKAGE_NAME "opengds")
# libseccomp 2.5: the signer's seccomp filter (src/common/sandbox.c).
set(CPACK_DEBIAN_OPENGDS_PACKAGE_DEPENDS "systemd (>= 252), libseccomp2 (>= 2.5)")
set(CPACK_DEBIAN_OPENGDS_PACKAGE_CONTROL_EXTRA
    "${CMAKE_CURRENT_SOURCE_DIR}/debian/postinst;${CMAKE_CURRENT_SOURCE_DIR}/debian/prerm;${CMAKE_CURRENT_SOURCE_DIR}/debian/postrm")
set(CPACK_DEBIAN_OPENGDS_PACKAGE_CONTROL_STRICT_PERMISSION ON)
set(CPACK_DEBIAN_GDSAUDIT_PACKAGE_NAME "gdsaudit")
set(CPACK_DEBIAN_GDSAUDIT_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_GDSAUDIT-GUI_PACKAGE_NAME "gdsaudit-gui")
set(CPACK_DEBIAN_GDSAUDIT-GUI_PACKAGE_SECTION "net")
# dpkg-shlibdeps adds GTK 4; the engine is the gdsaudit package
set(CPACK_DEBIAN_GDSAUDIT-GUI_PACKAGE_DEPENDS
    "gdsaudit (= ${PROJECT_VERSION}-${OPENGDS_PACKAGE_RELEASE})")

# --- RPM --------------------------------------------------------------------
set(CPACK_RPM_COMPONENT_INSTALL ON)
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_RPM_PACKAGE_RELEASE "${OPENGDS_PACKAGE_RELEASE}")
set(CPACK_RPM_PACKAGE_LICENSE "MPL-2.0")
set(CPACK_RPM_PACKAGE_GROUP "System Environment/Daemons")
set(CPACK_RPM_PACKAGE_URL "${CPACK_PACKAGE_HOMEPAGE_URL}")
set(CPACK_RPM_PACKAGE_RELOCATABLE OFF)
set(CPACK_RPM_OPENGDS_PACKAGE_NAME "opengds")
set(CPACK_RPM_OPENGDS_PACKAGE_SUMMARY "${CPACK_PACKAGE_DESCRIPTION_SUMMARY}")
set(CPACK_RPM_OPENGDS_PACKAGE_REQUIRES "systemd >= 252, libseccomp >= 2.5")
set(CPACK_RPM_OPENGDS_POST_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/rpm/post")
set(CPACK_RPM_OPENGDS_PRE_UNINSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/rpm/preun")
set(CPACK_RPM_OPENGDS_POST_UNINSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/rpm/postun")
set(CPACK_RPM_GDSAUDIT_PACKAGE_NAME "gdsaudit")
set(CPACK_RPM_GDSAUDIT_PACKAGE_SUMMARY "OPC 10000-12 test tool for GDSs, GDS-ready servers and clients")
set(CPACK_RPM_GDSAUDIT_PACKAGE_GROUP "Applications/System")
set(CPACK_RPM_GDSAUDIT-GUI_PACKAGE_NAME "gdsaudit-gui")
set(CPACK_RPM_GDSAUDIT-GUI_PACKAGE_SUMMARY "Desktop UI of the OpenGDS Auditor")
set(CPACK_RPM_GDSAUDIT-GUI_PACKAGE_GROUP "Applications/System")
set(CPACK_RPM_GDSAUDIT-GUI_PACKAGE_REQUIRES "gdsaudit = ${PROJECT_VERSION}-${OPENGDS_PACKAGE_RELEASE}")
# Directories owned by the system (filesystem, systemd) are not ours to own.
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
    /usr/lib/systemd /usr/lib/systemd/system /usr/lib/sysusers.d /usr/libexec
    /usr/share/doc)
# Stripped binaries: no separate debuginfo package, and no build-id links
# that differ between rpm versions.
set(CPACK_RPM_SPEC_MORE_DEFINE
"%define _build_id_links none
%define debug_package %{nil}
%define _buildhost reproducible
%define use_source_date_epoch_as_buildtime 1
%define clamp_mtime_to_source_date_epoch 1")

# --- tar.gz -----------------------------------------------------------------
# The plain archive holds every component under one prefix, for
# distributions without .deb or .rpm.
set(CPACK_ARCHIVE_COMPONENT_INSTALL OFF)

include(CPack)
