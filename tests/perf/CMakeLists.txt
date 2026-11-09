# OpenGDS performance tests (OpenGDS plan "Performance design and targets";
# docs/perf.md). Not registered with ctest: they take minutes and their
# numbers depend on the host. Run them all with
#   cmake --build <build> --target perf
# which writes <build>/tests/perf/run/results.txt.
# SPDX-License-Identifier: MPL-2.0
add_library(gds_perf_common STATIC perf_common.c)
target_include_directories(gds_perf_common PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(gds_perf_common PUBLIC gds_client Threads::Threads)

# Signing in the CA slot against the bare OpenSSL signature
add_executable(bench_sign bench_sign.c)
target_link_libraries(bench_sign PRIVATE gds_ca Threads::Threads)

# RegisterApplication throughput over OPC UA; fills the store to 50,000
add_executable(bench_register bench_register.c)
target_link_libraries(bench_register PRIVATE gds_perf_common)

# N concurrent pull agents: sessions held at once, then register, sign, trust list
add_executable(load_pull load_pull.c)
target_link_libraries(load_pull PRIVATE gds_perf_common)

# Push coverage: P parallel push sessions against push_test_server devices
add_executable(load_push load_push.c)
target_link_libraries(load_push PRIVATE gds_perf_common gds_push)

add_custom_target(perf
    COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/run_perf.sh" "${CMAKE_BINARY_DIR}"
            "${CMAKE_CURRENT_BINARY_DIR}/run"
    DEPENDS bench_sign bench_register load_pull load_push opengdsd opengds-signer gdsadm
            pull_test_client push_test_server
    USES_TERMINAL)
