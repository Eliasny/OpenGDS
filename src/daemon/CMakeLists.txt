# OpenGDS - opengdsd and gdsadm
# SPDX-License-Identifier: MPL-2.0
add_library(gds_daemon STATIC config.c own_cert.c)
target_include_directories(gds_daemon PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(gds_daemon PUBLIC gds_server gds_ca_ipc)

add_executable(opengdsd main.c)
target_link_libraries(opengdsd PRIVATE gds_daemon gds_push_engine)

add_executable(gdsadm gdsadm.c gdsadm_push.c gdsadm_import.c)
target_link_libraries(gdsadm PRIVATE gds_server gds_push gds_client)
