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
add_subdirectory(src/gdsctl)
if(OPENGDS_BUILD_TESTS)
    add_subdirectory(tests/unit)
    add_subdirectory(examples)
endif()

if(OPENGDS_BUILD_AUDITOR)
    add_subdirectory(tools/auditor)
    # The push tracer gate drives the Auditor's push_test_server; the pull
    # tracer drives gdsaudit and pull_test_client against opengdsd
    add_subdirectory(tests/integration)
endif()
