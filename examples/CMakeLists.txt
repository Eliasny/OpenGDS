# OpenGDS examples
# SPDX-License-Identifier: MPL-2.0
add_executable(embed_method embed_method.c)
target_link_libraries(embed_method PRIVATE gds_server)
# empty users file: the example only checks its setup here
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/users" "# no users\n")
file(CHMOD "${CMAKE_CURRENT_BINARY_DIR}/users" PERMISSIONS OWNER_READ OWNER_WRITE)
add_test(NAME example_embed_method
         COMMAND embed_method "${CMAKE_CURRENT_BINARY_DIR}/embed-run"
                 "${CMAKE_CURRENT_BINARY_DIR}/users" --check)
