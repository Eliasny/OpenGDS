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
    src/common/ua_args.c)
target_include_directories(gds_common PUBLIC "${PROJECT_SOURCE_DIR}/src")
target_compile_definitions(gds_common PUBLIC _DEFAULT_SOURCE)
target_link_libraries(gds_common PUBLIC gds_hardening open62541::open62541)

add_subdirectory(src/store)
add_subdirectory(src/ca)
add_subdirectory(src/signer)
add_subdirectory(src/server)
add_subdirectory(src/daemon)
add_subdirectory(src/client)
add_subdirectory(src/push)
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
endif()
