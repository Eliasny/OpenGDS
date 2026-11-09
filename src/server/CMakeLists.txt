# OpenGDS - the GDS server (Directory, CertificateManager, TrustList, access)
# SPDX-License-Identifier: MPL-2.0
add_library(gds_server STATIC
    gds_access.c
    gds_alarms.c
    gds_dialogs.c
    gds_approvals.c
    gds_audit.c
    gds_authz.c
    gds_caller.c
    gds_certmgr.c
    gds_directory.c
    gds_embed.c
    gds_keycred.c
    gds_jwt.c
    gds_keypair.c
    gds_nodes.c
    gds_plugin_tl.c
    gds_policy.c
    gds_push_slot.c
    gds_registrar.c
    gds_revoke.c
    gds_server.c
    gds_tlcheck.c
    gds_trustlist.c
    gds_validate.c)
target_include_directories(gds_server PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(gds_server PUBLIC gds_ca gds_store gds_common Threads::Threads)
