# OpenGDS - top-level build
# SPDX-License-Identifier: MPL-2.0
cmake_minimum_required(VERSION 3.20)
project(OpenGDS VERSION 0.0.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

option(OPENGDS_WERROR "Treat warnings as errors" ON)
# An embedder (UASM) may build OpenGDS as a subproject with add_subdirectory:
# it then gets the libraries and the signer, without OpenGDS's tests,
# examples and Auditor unless it asks for them.
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(_gds_top ON)
else()
    set(_gds_top OFF)
endif()
option(OPENGDS_BUILD_TESTS "Build OpenGDS's tests and examples" ${_gds_top})
option(OPENGDS_BUILD_AUDITOR "Build the OpenGDS Auditor (tools/auditor)" ${_gds_top})
# tests/fuzz as libFuzzer targets (clang). Off: the same targets replay their
# seed corpus as plain tests.
option(OPENGDS_FUZZ "Build tests/fuzz with libFuzzer (clang, ASan + UBSan)" OFF)
if(OPENGDS_FUZZ)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "OPENGDS_FUZZ needs clang (libFuzzer)")
    endif()
    if(NOT OPENGDS_SANITIZE)
        set(OPENGDS_SANITIZE "address,undefined" CACHE STRING
            "Comma-separated sanitizers (address,undefined | thread)" FORCE)
    endif()
    if(NOT OPENGDS_SANITIZE MATCHES "address")
        message(FATAL_ERROR "OPENGDS_FUZZ runs under ASan: OPENGDS_SANITIZE must include address")
    endif()
    # Coverage feedback for all our code; the fuzz targets link -fsanitize=fuzzer
    add_compile_options(-fsanitize=fuzzer-no-link)
endif()

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
include(sanitizers)
include(hardening)
include(open62541)

enable_testing()

# Shared rule code (docs/architecture.md, "Files"). Grows into libopengds's
# src/common/ in T1.
add_library(gds_common STATIC
    src/common/buf.c
    src/common/ids.c
    src/common/safeint.c
    src/common/ua_args.c
    src/common/enc_secret.c)
if(NOT WIN32)
    target_sources(gds_common PRIVATE src/common/sandbox.c)
endif()
target_include_directories(gds_common PUBLIC "${PROJECT_SOURCE_DIR}/src")
target_compile_definitions(gds_common PUBLIC _DEFAULT_SOURCE)
target_link_libraries(gds_common PUBLIC gds_hardening open62541::open62541)

# seccomp in the sandbox (src/common/sandbox.c) needs libseccomp (LGPL 2.1).
# Optional: without it only Landlock applies. ON makes it required.
# Only the headless Auditor: the Windows build and the static Linux build
# (Auditor plan AT5, packaging/windows/, packaging/static/). The GDS, its
# signer and store are Linux services built in the full tree; so are the
# Auditor's tests and self-test targets.
if(WIN32)
    set(_gds_auditor_only ON)
else()
    set(_gds_auditor_only OFF)
endif()
option(OPENGDS_AUDITOR_ONLY "Build only the headless Auditor, without tests" ${_gds_auditor_only})
if(WIN32 AND NOT OPENGDS_AUDITOR_ONLY)
    message(FATAL_ERROR "On Windows only the Auditor is built: set OPENGDS_AUDITOR_ONLY=ON")
endif()
if(OPENGDS_AUDITOR_ONLY)
    set(GDSAUDIT_SELFTESTS OFF)
    if(WIN32)
        # MinGW-w64: C99 printf (%zu), Windows 10 APIs
        add_compile_definitions(__USE_MINGW_ANSI_STDIO=1 _WIN32_WINNT=0x0A00 WIN32_LEAN_AND_MEAN)
    endif()
    add_subdirectory(tools/auditor)
    return()
endif()
set(GDSAUDIT_SELFTESTS ON)

set(OPENGDS_SECCOMP AUTO CACHE STRING "Use libseccomp for the seccomp filter (AUTO, ON, OFF)")
if(NOT OPENGDS_SECCOMP STREQUAL "OFF")
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(LIBSECCOMP IMPORTED_TARGET libseccomp>=2.5)
    endif()
    if(LIBSECCOMP_FOUND)
        target_compile_definitions(gds_common PRIVATE GDS_HAVE_SECCOMP)
        target_link_libraries(gds_common PRIVATE PkgConfig::LIBSECCOMP)
    elseif(OPENGDS_SECCOMP STREQUAL "ON")
        message(FATAL_ERROR "OPENGDS_SECCOMP=ON but libseccomp >= 2.5 was not found")
    else()
        message(STATUS "libseccomp not found: the sandbox applies Landlock only")
    endif()
endif()

# The mDNS announce of the GDS (OPC 10000-12 Annex C, src/disc/). On by
# default (OpenGDS plan W5: mDNS ships); it needs an open62541 built with
# UA_ENABLE_DISCOVERY_MULTICAST (scripts/build_open62541.sh, MDNS=MDNSD).
# opengdsd announces only when its config says `mdns = true`.
option(OPENGDS_WITH_MDNS "Build the mDNS announce (needs open62541 with multicast discovery)" ON)
if(OPENGDS_WITH_MDNS AND NOT OPEN62541_HAS_MULTICAST)
    message(FATAL_ERROR "OPENGDS_WITH_MDNS needs open62541 built with UA_ENABLE_DISCOVERY_MULTICAST: "
                        "rebuild it with scripts/build_open62541.sh, or set -DOPENGDS_WITH_MDNS=OFF")
endif()

add_subdirectory(src/store)
add_subdirectory(src/disc)
add_subdirectory(src/ca)
add_subdirectory(src/signer)
add_subdirectory(src/server)
add_subdirectory(src/daemon)
add_subdirectory(src/client)
add_subdirectory(src/push)
add_subdirectory(src/gdsctl)
if(OPENGDS_BUILD_TESTS)
    add_subdirectory(tests/unit)
    add_subdirectory(tests/fuzz)
    add_subdirectory(examples)
endif()

if(OPENGDS_BUILD_AUDITOR)
    add_subdirectory(tools/auditor)
    # The push tracer gate drives the Auditor's push_test_server; the pull
    # tracer drives gdsaudit and pull_test_client against opengdsd
    add_subdirectory(tests/integration)
    # Spec tests that drive the Auditor's test targets (Annex G setup)
    add_subdirectory(tests/spec)
endif()

# Install rules and packages (.deb, .rpm, .tar.gz; docs/packaging.md), only
# for an OpenGDS build of its own: a project that embeds OpenGDS with
# add_subdirectory (UASM) packages itself.
if(_gds_top)
    add_subdirectory(packaging)
endif()
