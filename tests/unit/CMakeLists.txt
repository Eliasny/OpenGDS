# OpenGDS unit tests
# SPDX-License-Identifier: MPL-2.0
add_executable(test_store test_store.c)
target_link_libraries(test_store PRIVATE gds_store)
add_test(NAME unit_store COMMAND test_store "${CMAKE_CURRENT_BINARY_DIR}/store-run")
add_executable(test_ca test_ca.c)
target_link_libraries(test_ca PRIVATE gds_ca)
add_test(NAME unit_ca COMMAND test_ca "${CMAKE_CURRENT_BINARY_DIR}/ca-run")

add_executable(test_push_select test_push_select.c)
target_link_libraries(test_push_select PRIVATE gds_push)
add_test(NAME unit_push_select COMMAND test_push_select)
