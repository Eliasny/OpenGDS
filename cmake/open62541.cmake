# OpenGDS - the pinned open62541 v1.5.10 (decision: pinned; F2 in docs/architecture.md).
# SPDX-License-Identifier: MPL-2.0
#
# The library is built once by scripts/build_open62541.sh into a prefix (CI
# caches it) and found here with -DOPEN62541_PREFIX=<prefix>. This file
# refuses any other version, and any build without the features OpenGDS needs.

set(OPEN62541_PREFIX "" CACHE PATH "Install prefix of the pinned open62541 build")
if(NOT OPEN62541_PREFIX)
    message(FATAL_ERROR "Set -DOPEN62541_PREFIX=<dir> (build it with scripts/build_open62541.sh <dir>)")
endif()

set(_o6_inc "${OPEN62541_PREFIX}/include")
set(_o6_cfg "${_o6_inc}/open62541/config.h")
find_library(OPEN62541_LIBRARY NAMES open62541 PATHS "${OPEN62541_PREFIX}/lib"
             "${OPEN62541_PREFIX}/lib64" NO_DEFAULT_PATH REQUIRED)
if(NOT EXISTS "${_o6_cfg}")
    message(FATAL_ERROR "open62541 headers not found in ${_o6_inc}")
endif()

file(READ "${_o6_cfg}" _o6_config)
string(REGEX MATCH "#define UA_OPEN62541_VERSION \"([^\"]+)\"" _ "${_o6_config}")
if(NOT CMAKE_MATCH_1 STREQUAL "v1.5.10")
    message(FATAL_ERROR "open62541 must be v1.5.10 (pinned), found '${CMAKE_MATCH_1}'")
endif()
foreach(feature UA_ENABLE_ENCRYPTION_OPENSSL UA_ENABLE_GDS_PUSHMANAGEMENT)
    if(NOT _o6_config MATCHES "#define ${feature}")
        message(FATAL_ERROR "open62541 was built without ${feature}")
    endif()
endforeach()
if(NOT EXISTS "${_o6_inc}/open62541/nodeids_gds.h")
    message(FATAL_ERROR "GDS headers missing (scripts/build_open62541.sh installs them)")
endif()

find_package(OpenSSL 3.0 REQUIRED)
if(OPENSSL_VERSION VERSION_LESS 3.5)
    message(WARNING "OpenSSL ${OPENSSL_VERSION}: OpenGDS requires 3.5 for production "
                    "builds (3.0 LTS ended 7 Sep 2026). Test tools still build.")
endif()
find_package(Threads REQUIRED)

add_library(open62541::open62541 STATIC IMPORTED GLOBAL)
set_target_properties(open62541::open62541 PROPERTIES
    IMPORTED_LOCATION "${OPEN62541_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${_o6_inc}"
    INTERFACE_LINK_LIBRARIES "OpenSSL::SSL;OpenSSL::Crypto;Threads::Threads;m")
message(STATUS "open62541 v1.5.10 from ${OPEN62541_PREFIX}")
