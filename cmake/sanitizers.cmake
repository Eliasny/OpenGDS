# OpenGDS - sanitizer presets (docs/architecture.md, "Analysis and testing").
# SPDX-License-Identifier: MPL-2.0
#
#   -DOPENGDS_SANITIZE=address,undefined   ASan + UBSan (CI on every push)
#   -DOPENGDS_SANITIZE=thread              TSan (CI on every push)
# Sanitizer reports are fatal: -fno-sanitize-recover=all.

# Included by OpenGDS and by embedders that build it as a subproject (UASM).
include_guard(GLOBAL)

set(OPENGDS_SANITIZE "" CACHE STRING "Comma-separated sanitizers (address,undefined | thread)")
if(OPENGDS_SANITIZE)
    if(OPENGDS_SANITIZE MATCHES "thread" AND OPENGDS_SANITIZE MATCHES "address")
        message(FATAL_ERROR "TSan and ASan cannot be combined")
    endif()
    add_compile_options(-fsanitize=${OPENGDS_SANITIZE} -fno-sanitize-recover=all
                        -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=${OPENGDS_SANITIZE})
    # Clang's UBSan "function" check fires on open62541's EventLoop
    # function-pointer casts (v1.5.10); our own code is held to the rest.
    if(OPENGDS_SANITIZE MATCHES "undefined" AND CMAKE_C_COMPILER_ID MATCHES "Clang")
        add_compile_options(-fno-sanitize=function)
    endif()
endif()
