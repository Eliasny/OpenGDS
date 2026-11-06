# OpenGDS fuzz targets (docs/architecture.md, "Fuzz targets")
# SPDX-License-Identifier: MPL-2.0
#
# -DOPENGDS_FUZZ=ON (clang): libFuzzer binaries, with the whole build under
#   ASan + UBSan and coverage instrumentation (top-level CMakeLists.txt).
# Default: the same targets linked with fuzz_main.c, a driver that replays
#   corpus files. Either way one CTest per target replays its seed corpus.
add_library(gds_fuzz_util STATIC fuzz_util.c)
target_include_directories(gds_fuzz_util PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(gds_fuzz_util PUBLIC gds_common)

set(_fuzz_corpus "${CMAKE_CURRENT_SOURCE_DIR}/corpus")

function(gds_fuzz_target name)
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} PRIVATE gds_fuzz_util ${ARGN})
    if(OPENGDS_FUZZ)
        target_link_options(${name} PRIVATE -fsanitize=fuzzer)
        # -runs=0: run every corpus file once, then stop
        add_test(NAME ${name}_corpus COMMAND ${name} -runs=0 "${_fuzz_corpus}/${name}")
    else()
        target_sources(${name} PRIVATE fuzz_main.c)
        add_test(NAME ${name}_corpus COMMAND ${name} "${_fuzz_corpus}/${name}")
    endif()
endfunction()

gds_fuzz_target(fuzz_csr gds_ca)
gds_fuzz_target(fuzz_app_record gds_server)
gds_fuzz_target(fuzz_signer_msg gds_signer)
gds_fuzz_target(fuzz_daemon_config gds_daemon)
gds_fuzz_target(fuzz_users gds_server)
gds_fuzz_target(fuzz_trustlist gds_client)

# Writes the binary seeds; run by hand (see gen_seeds.c), not by the tests
add_executable(fuzz_gen_seeds gen_seeds.c)
target_link_libraries(fuzz_gen_seeds PRIVATE gds_fuzz_util gds_sigproto)
