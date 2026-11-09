# OpenGDS - mDNS announce and gdsadm watch against opengdsd (plan W5)
# SPDX-License-Identifier: MPL-2.0
if(OPENGDS_WITH_MDNS)
    add_test(NAME integration_mdns_watch
             COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/run_mdns_watch.sh" "${CMAKE_BINARY_DIR}"
                     "${CMAKE_CURRENT_BINARY_DIR}/run")
    set_tests_properties(integration_mdns_watch PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
endif()
