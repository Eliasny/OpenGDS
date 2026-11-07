# OpenGDS - the pinned open62541 v1.5.10 (decision: pinned; F2 in docs/architecture.md).
# SPDX-License-Identifier: MPL-2.0
#
# The library is built once by scripts/build_open62541.sh into a prefix (CI
# caches it) and found here with -DOPEN62541_PREFIX=<prefix>. This file
# refuses any other version, and any build without the features OpenGDS needs.

# Included by OpenGDS and by embedders that build it as a subproject (UASM).
include_guard(GLOBAL)

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
if(CMAKE_MATCH_1 STREQUAL "v1.5.10-dirty")
    # Pinned v1.5.10 plus our carried patches (docs/upstream/README.md). Accept
    # it only if exactly the patches in this repository were applied.
    set(_o6_want "")
    file(GLOB _o6_patches "${CMAKE_CURRENT_LIST_DIR}/../docs/upstream/patches/v1.5.10/*.patch")
    list(SORT _o6_patches)
    foreach(p ${_o6_patches})
        file(SHA256 "${p}" _h)
        string(APPEND _o6_want "${_h}\n")
    endforeach()
    set(_o6_marker "${OPEN62541_PREFIX}/share/opengds/open62541-patches.sha256")
    if(NOT EXISTS "${_o6_marker}")
        message(FATAL_ERROR "open62541 v1.5.10-dirty without ${_o6_marker}: rebuild with scripts/build_open62541.sh")
    endif()
    file(READ "${_o6_marker}" _o6_have)
    if(NOT _o6_have STREQUAL _o6_want)
        message(FATAL_ERROR "open62541 was built with other patches than docs/upstream/patches/v1.5.10: rebuild with scripts/build_open62541.sh")
    endif()
elseif(NOT CMAKE_MATCH_1 STREQUAL "v1.5.10")
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

# Decision G2: OpenSSL 3.5 LTS from the start (3.0 LTS ended 7 Sep 2026).
# Ubuntu 24.04 ships 3.0, so build it with scripts/build_openssl.sh <dir> and
# pass -DOPENSSL_ROOT_DIR=<dir>; static libraries are preferred.
if(NOT DEFINED OPENSSL_USE_STATIC_LIBS)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()
find_package(OpenSSL 3.5 REQUIRED)
find_package(Threads REQUIRED)

add_library(open62541::open62541 STATIC IMPORTED GLOBAL)
set_target_properties(open62541::open62541 PROPERTIES
    IMPORTED_LOCATION "${OPEN62541_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${_o6_inc}"
    INTERFACE_LINK_LIBRARIES "OpenSSL::SSL;OpenSSL::Crypto;Threads::Threads;m")
if(WIN32)
    # Winsock and the adapter list (open62541's event loop), the crypto
    # APIs OpenSSL uses on Windows
    set_property(TARGET open62541::open62541 APPEND PROPERTY INTERFACE_LINK_LIBRARIES
        ws2_32 iphlpapi crypt32 bcrypt advapi32 user32)
endif()
message(STATUS "open62541 v1.5.10 from ${OPEN62541_PREFIX}")
