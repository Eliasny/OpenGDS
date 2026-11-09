# OpenGDS - hardening flags (docs/architecture.md, "Build hardening").
# SPDX-License-Identifier: MPL-2.0
#
# Defines the interface target gds_hardening. Every OpenGDS and Auditor
# target links it. Flags a compiler does not know are skipped with a message,
# so an old compiler builds but CI (GCC 13+, Clang 18+) always has the full set.

# Included by OpenGDS and by embedders that build it as a subproject (UASM).
include_guard(GLOBAL)

include(CheckCCompilerFlag)
add_library(gds_hardening INTERFACE)

function(gds_try_flag flag)
    string(MAKE_C_IDENTIFIER "HAVE_${flag}" var)
    check_c_compiler_flag("${flag}" ${var})
    if(${var})
        target_compile_options(gds_hardening INTERFACE ${flag})
    else()
        message(STATUS "hardening: ${flag} not supported by this compiler")
    endif()
endfunction()

# Warnings (errors in our code)
set(GDS_WARNINGS
    -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security -Wconversion -Wsign-conversion
    -Wimplicit-fallthrough -Wshadow -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes
    -Wvla -Wnull-dereference -Wswitch-enum
    -Werror=implicit -Werror=incompatible-pointer-types -Werror=int-conversion
    -Werror=format-security -Werror=vla)
foreach(f ${GDS_WARNINGS})
    gds_try_flag(${f})
endforeach()
if(OPENGDS_WERROR)
    target_compile_options(gds_hardening INTERFACE -Werror)
endif()

# Code generation
foreach(f -fstack-protector-strong -fstack-clash-protection -ftrivial-auto-var-init=zero
          -fstrict-flex-arrays=3 -fno-delete-null-pointer-checks -fno-strict-overflow
          -fno-strict-aliasing)
    gds_try_flag(${f})
endforeach()
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    gds_try_flag(-fcf-protection=full)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    gds_try_flag(-mbranch-protection=standard)
endif()

# _FORTIFY_SOURCE needs optimisation and conflicts with ASan; set it only
# for optimised, non-sanitized builds.
# MinGW: its fortify wrappers need libssp and check snprintf as MSVCRT
# printf (no %zu), so Windows builds go without.
if(NOT WIN32 AND NOT OPENGDS_SANITIZE AND NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(gds_hardening INTERFACE -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)
endif()

if(WIN32)
    # PE: ASLR (64-bit), DEP; static so the .exe needs no MinGW DLLs
    target_link_options(gds_hardening INTERFACE
        -Wl,--dynamicbase -Wl,--high-entropy-va -Wl,--nxcompat -static)
else()
    # OPENGDS_STATIC: one self-contained binary (packaging/static/, musl):
    # a static PIE keeps ASLR
    option(OPENGDS_STATIC "Link static PIE executables (the static gdsaudit)" OFF)
    if(OPENGDS_STATIC)
        set(_gds_pie -static-pie)
    else()
        set(_gds_pie -pie)
    endif()
    target_link_options(gds_hardening INTERFACE
        ${_gds_pie} -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
        -Wl,--as-needed -Wl,--no-copy-dt-needed-entries)
endif()
