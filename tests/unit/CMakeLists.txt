# OpenGDS unit tests
# SPDX-License-Identifier: MPL-2.0
add_executable(test_store test_store.c)
target_link_libraries(test_store PRIVATE gds_store)
add_test(NAME unit_store COMMAND test_store "${CMAKE_CURRENT_BINARY_DIR}/store-run")
