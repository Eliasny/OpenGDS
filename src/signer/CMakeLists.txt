# OpenGDS - opengds-signer and its protocol
# SPDX-License-Identifier: MPL-2.0
add_library(gds_sigproto STATIC proto.c)
target_include_directories(gds_sigproto PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(gds_sigproto PUBLIC gds_ca)

add_library(gds_signer STATIC journal.c signer.c)
target_link_libraries(gds_signer PUBLIC gds_sigproto gds_ca gds_store)

# The signer program as a library: opengds-signer, and an embedder's own
# signer executable with a store of its own (signer_main.h, UASM ask A21).
add_library(gds_signer_main STATIC signer_main.c)
target_link_libraries(gds_signer_main PUBLIC gds_signer PRIVATE gds_common)

add_executable(opengds-signer main.c)
target_link_libraries(opengds-signer PRIVATE gds_signer_main)
