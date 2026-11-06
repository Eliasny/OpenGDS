# OpenGDS - opengds-signer and its protocol
# SPDX-License-Identifier: MPL-2.0
add_library(gds_sigproto STATIC proto.c)
target_include_directories(gds_sigproto PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(gds_sigproto PUBLIC gds_ca)

add_library(gds_signer STATIC signer.c)
target_link_libraries(gds_signer PUBLIC gds_sigproto gds_ca gds_store)

add_executable(opengds-signer main.c)
target_link_libraries(opengds-signer PRIVATE gds_signer)
