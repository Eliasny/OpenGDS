# libgdsclient: typed wrappers over the standard Part 12 methods
# SPDX-License-Identifier: MPL-2.0
add_library(gds_client STATIC gdsc_connect.c gdsc_push.c gdsc_session.c gdsc_gds.c
            gdsc_pull_agent.c gdsc_keycred.c)
target_link_libraries(gds_client PUBLIC gds_common)
