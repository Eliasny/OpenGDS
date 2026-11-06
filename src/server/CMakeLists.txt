# OpenGDS - the GDS server (Directory, CertificateManager, TrustList, access)
# SPDX-License-Identifier: MPL-2.0
add_library(gds_server STATIC
    gds_access.c
    gds_caller.c
    gds_certmgr.c
    gds_directory.c
    gds_embed.c
    gds_server.c
    gds_trustlist.c
    gds_validate.c)
target_include_directories(gds_server PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(gds_server PUBLIC gds_ca gds_store gds_common Threads::Threads)
