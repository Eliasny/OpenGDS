# OpenGDS unit tests
# SPDX-License-Identifier: MPL-2.0
add_executable(test_store test_store.c)
target_link_libraries(test_store PRIVATE gds_store)
add_test(NAME unit_store COMMAND test_store "${CMAKE_CURRENT_BINARY_DIR}/store-run")
add_executable(test_ca test_ca.c)
target_link_libraries(test_ca PRIVATE gds_ca)
add_test(NAME unit_ca COMMAND test_ca "${CMAKE_CURRENT_BINARY_DIR}/ca-run")
add_executable(test_signer test_signer.c)
target_link_libraries(test_signer PRIVATE gds_signer gds_ca_ipc)
add_test(NAME unit_signer COMMAND test_signer "${CMAKE_CURRENT_BINARY_DIR}/signer-run")
add_test(NAME signer_refuses_bad_args COMMAND opengds-signer --fd 0)
set_tests_properties(signer_refuses_bad_args PROPERTIES WILL_FAIL TRUE)
# --fd and --listen are exclusive; --listen takes an absolute path
add_test(NAME signer_refuses_fd_and_listen
         COMMAND opengds-signer --fd 0 --listen /tmp/x.sock --store /x --ca-dir /x)
add_test(NAME signer_refuses_relative_listen
         COMMAND opengds-signer --listen x.sock --store /x --ca-dir /x)
set_tests_properties(signer_refuses_fd_and_listen signer_refuses_relative_listen
                     PROPERTIES PASS_REGULAR_EXPRESSION "usage: opengds-signer")

add_executable(test_signer_hooks test_signer_hooks.c)
target_link_libraries(test_signer_hooks PRIVATE gds_signer_main gds_ca_ipc)
add_test(NAME unit_signer_hooks COMMAND test_signer_hooks "${CMAKE_CURRENT_BINARY_DIR}/signer-hooks-run")
set_tests_properties(unit_signer_hooks PROPERTIES TIMEOUT 120)
add_executable(test_server test_server.c)
target_link_libraries(test_server PRIVATE gds_server)
add_test(NAME unit_server COMMAND test_server "${CMAKE_CURRENT_BINARY_DIR}/server-run")
add_executable(test_directory_query test_directory_query.c)
target_link_libraries(test_directory_query PRIVATE gds_server)
add_test(NAME unit_directory_query COMMAND test_directory_query
         "${CMAKE_CURRENT_BINARY_DIR}/directory-query-run")
add_executable(test_daemon_config test_daemon_config.c)
target_link_libraries(test_daemon_config PRIVATE gds_daemon)
add_test(NAME unit_daemon_config COMMAND test_daemon_config)
add_test(NAME gdsadm_refuses_bad_args COMMAND gdsadm apps list)
set_tests_properties(gdsadm_refuses_bad_args PROPERTIES WILL_FAIL TRUE)
# approve without the request id, and with a request id that is not a GUID
add_test(NAME gdsadm_approve_refuses_bad_args
         COMMAND gdsadm approvals approve --url opc.tcp://localhost:1 --user u
                 --password-file /x --trust /x)
add_test(NAME gdsadm_approve_refuses_bad_id
         COMMAND gdsadm approvals approve --url opc.tcp://localhost:1 --user u
                 --password-file /x --trust /x not-a-guid)
set_tests_properties(gdsadm_approve_refuses_bad_args PROPERTIES PASS_REGULAR_EXPRESSION "usage: gdsadm")
set_tests_properties(gdsadm_approve_refuses_bad_id PROPERTIES PASS_REGULAR_EXPRESSION "not a request id")
add_test(NAME opengdsd_refuses_bad_args COMMAND opengdsd)
set_tests_properties(opengdsd_refuses_bad_args PROPERTIES WILL_FAIL TRUE)
add_executable(test_plugin_abi test_plugin_abi.c)
target_link_libraries(test_plugin_abi PRIVATE gds_server)
add_test(NAME unit_plugin_abi COMMAND test_plugin_abi "${CMAKE_CURRENT_BINARY_DIR}/plugin-run")

add_executable(test_push_select test_push_select.c)
target_link_libraries(test_push_select PRIVATE gds_push)
add_test(NAME unit_push_select COMMAND test_push_select)
add_executable(test_embed test_embed.c)
target_link_libraries(test_embed PRIVATE gds_server)
add_test(NAME unit_embed COMMAND test_embed "${CMAKE_CURRENT_BINARY_DIR}/embed-run")
add_executable(test_store_slot test_store_slot.c)
target_link_libraries(test_store_slot PRIVATE gds_server)
add_test(NAME unit_store_slot COMMAND test_store_slot "${CMAKE_CURRENT_BINARY_DIR}/slot-run")
add_executable(test_approvals test_approvals.c)
target_link_libraries(test_approvals PRIVATE gds_server)
add_test(NAME unit_approvals COMMAND test_approvals "${CMAKE_CURRENT_BINARY_DIR}/approvals-run")
set_tests_properties(unit_approvals PROPERTIES TIMEOUT 120)

add_executable(test_audit test_audit.c)
target_link_libraries(test_audit PRIVATE gds_server)
add_test(NAME unit_audit COMMAND test_audit "${CMAKE_CURRENT_BINARY_DIR}/audit-run")
set_tests_properties(unit_audit PROPERTIES TIMEOUT 120)

add_executable(test_runtime_nodes test_runtime_nodes.c)
target_link_libraries(test_runtime_nodes PRIVATE gds_server)
add_test(NAME unit_runtime_nodes COMMAND test_runtime_nodes "${CMAKE_CURRENT_BINARY_DIR}/runtime-run")

add_executable(test_verify_audit test_verify_audit.c)
target_link_libraries(test_verify_audit PRIVATE gds_verify_audit)
add_test(NAME unit_verify_audit
         COMMAND test_verify_audit "${CMAKE_CURRENT_BINARY_DIR}/verify-audit-run" "$<TARGET_FILE:gdsctl>")

add_executable(test_revoke test_revoke.c)
target_link_libraries(test_revoke PRIVATE gds_server)
add_test(NAME unit_revoke COMMAND test_revoke "${CMAKE_CURRENT_BINARY_DIR}/revoke-run")
set_tests_properties(unit_revoke PROPERTIES TIMEOUT 120)
add_executable(test_sandbox test_sandbox.c)
target_link_libraries(test_sandbox PRIVATE gds_common Threads::Threads)
add_test(NAME unit_sandbox COMMAND test_sandbox "${CMAKE_CURRENT_BINARY_DIR}/sandbox-run")

add_executable(test_embed_roles test_embed_roles.c)
target_link_libraries(test_embed_roles PRIVATE gds_server)
add_test(NAME unit_embed_roles COMMAND test_embed_roles "${CMAKE_CURRENT_BINARY_DIR}/roles-run")

add_executable(test_x509_users test_x509_users.c)
target_link_libraries(test_x509_users PRIVATE gds_server gds_client)
add_test(NAME unit_x509_users COMMAND test_x509_users "${CMAKE_CURRENT_BINARY_DIR}/x509-users-run")

add_executable(test_backup test_backup.c)
target_link_libraries(test_backup PRIVATE gds_backup)
add_test(NAME unit_backup
         COMMAND test_backup "${CMAKE_CURRENT_BINARY_DIR}/backup-run" "$<TARGET_FILE:gdsctl>")

add_executable(test_alarms test_alarms.c)
target_link_libraries(test_alarms PRIVATE gds_server)
add_test(NAME unit_alarms COMMAND test_alarms "${CMAKE_CURRENT_BINARY_DIR}/alarms-run")
set_tests_properties(unit_alarms PROPERTIES TIMEOUT 120)

add_executable(test_gdsadm_import test_gdsadm_import.c
               "${PROJECT_SOURCE_DIR}/src/daemon/gdsadm_import.c")
target_include_directories(test_gdsadm_import PRIVATE "${PROJECT_SOURCE_DIR}/src/daemon")
target_link_libraries(test_gdsadm_import PRIVATE gds_server)
add_test(NAME unit_gdsadm_import COMMAND test_gdsadm_import)

add_executable(test_registrar test_registrar.c)
target_link_libraries(test_registrar PRIVATE gds_server)
add_test(NAME unit_registrar COMMAND test_registrar "${CMAKE_CURRENT_BINARY_DIR}/registrar-run")
set_tests_properties(unit_registrar PROPERTIES TIMEOUT 120)

add_executable(test_role_boolean test_role_boolean.c)
target_link_libraries(test_role_boolean PRIVATE gds_server)
add_test(NAME unit_role_boolean COMMAND test_role_boolean "${CMAKE_CURRENT_BINARY_DIR}/role-boolean-run")

add_executable(test_peers test_peers.c)
target_link_libraries(test_peers PRIVATE gds_server)
add_test(NAME unit_peers COMMAND test_peers "${CMAKE_CURRENT_BINARY_DIR}/peers-run")

add_executable(test_dca_rights test_dca_rights.c)
target_link_libraries(test_dca_rights PRIVATE gds_server)
add_test(NAME unit_dca_rights COMMAND test_dca_rights "${CMAKE_CURRENT_BINARY_DIR}/dca-run")
set_tests_properties(unit_dca_rights PROPERTIES TIMEOUT 120)
add_executable(test_trustlist_write test_trustlist_write.c)
target_link_libraries(test_trustlist_write PRIVATE gds_server)
add_test(NAME unit_trustlist_write COMMAND test_trustlist_write
         "${CMAKE_CURRENT_BINARY_DIR}/tlwrite-run")
set_tests_properties(unit_trustlist_write PROPERTIES TIMEOUT 120)

add_executable(test_plugin_tl test_plugin_tl.c)
target_link_libraries(test_plugin_tl PRIVATE gds_server OpenSSL::Crypto)
add_test(NAME unit_plugin_tl COMMAND test_plugin_tl "${CMAKE_CURRENT_BINARY_DIR}/plugin-tl-run")
set_tests_properties(unit_plugin_tl PROPERTIES TIMEOUT 120)

add_executable(test_dialogs test_dialogs.c)
target_link_libraries(test_dialogs PRIVATE gds_server)
add_test(NAME unit_dialogs COMMAND test_dialogs "${CMAKE_CURRENT_BINARY_DIR}/dialogs-run")
set_tests_properties(unit_dialogs PROPERTIES TIMEOUT 120)
add_executable(test_keypair_map test_keypair_map.c)
target_link_libraries(test_keypair_map PRIVATE gds_server)
add_test(NAME unit_keypair_map COMMAND test_keypair_map)

# OpenGDS W3: the push engine's timing rules, the push target list and the
# push-scheduling slot
add_executable(test_push_sched test_push_sched.c)
target_link_libraries(test_push_sched PRIVATE gds_push_engine)
add_test(NAME unit_push_sched COMMAND test_push_sched)
add_executable(test_push_targets test_push_targets.c)
target_link_libraries(test_push_targets PRIVATE gds_push_engine)
add_test(NAME unit_push_targets COMMAND test_push_targets "${CMAKE_CURRENT_BINARY_DIR}/push-targets-run")
add_executable(test_keycred test_keycred.c)
target_link_libraries(test_keycred PRIVATE gds_server)
add_test(NAME unit_keycred COMMAND test_keycred "${CMAKE_CURRENT_BINARY_DIR}/keycred-run")
set_tests_properties(unit_keycred PROPERTIES TIMEOUT 120)

add_executable(test_keycred_source test_keycred_source.c)
target_link_libraries(test_keycred_source PRIVATE gds_server)
add_test(NAME unit_keycred_source COMMAND test_keycred_source "${CMAKE_CURRENT_BINARY_DIR}/keycred-source-run")
set_tests_properties(unit_keycred_source PROPERTIES TIMEOUT 120)

# OpenGDS O5: the AuthorizationService (Part 12 §9.6)
add_executable(test_authz test_authz.c)
target_link_libraries(test_authz PRIVATE gds_server)
add_test(NAME unit_authz COMMAND test_authz "${CMAKE_CURRENT_BINARY_DIR}/authz-run")
set_tests_properties(unit_authz PROPERTIES TIMEOUT 120)
# mDNS announce (OPC 10000-12 Annex C; src/disc/)
if(OPENGDS_WITH_MDNS)
    add_executable(test_disc_mdns test_disc_mdns.c)
    target_link_libraries(test_disc_mdns PRIVATE gds_server)
    add_test(NAME unit_disc_mdns COMMAND test_disc_mdns "${CMAKE_CURRENT_BINARY_DIR}/disc-mdns-run")
    # 77: the host cannot open the mDNS multicast socket
    set_tests_properties(unit_disc_mdns PROPERTIES SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
endif()

# gdsadm watch output (src/daemon/gdsadm_watch.c)
add_executable(test_gdsadm_watch test_gdsadm_watch.c "${PROJECT_SOURCE_DIR}/src/daemon/gdsadm_watch.c")
target_include_directories(test_gdsadm_watch PRIVATE "${PROJECT_SOURCE_DIR}/src/daemon")
target_link_libraries(test_gdsadm_watch PRIVATE gds_client)
add_test(NAME unit_gdsadm_watch COMMAND test_gdsadm_watch)
add_test(NAME gdsadm_watch_refuses_bad_args COMMAND gdsadm watch --url opc.tcp://localhost:1 --count 0)
set_tests_properties(gdsadm_watch_refuses_bad_args PROPERTIES PASS_REGULAR_EXPRESSION "usage: gdsadm watch")
