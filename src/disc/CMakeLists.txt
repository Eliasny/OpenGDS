# OpenGDS - discovery: the mDNS announce (OPC 10000-12 Annex C)
# SPDX-License-Identifier: MPL-2.0
add_library(gds_disc STATIC disc_mdns.c)
target_include_directories(gds_disc PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(gds_disc PUBLIC gds_common)
if(OPENGDS_WITH_MDNS)
    target_compile_definitions(gds_disc PRIVATE OPENGDS_WITH_MDNS)
endif()
