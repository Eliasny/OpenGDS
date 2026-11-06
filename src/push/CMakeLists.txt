# Push engine: sessions to managed Servers and the Part 12 push workflows
# SPDX-License-Identifier: MPL-2.0
add_library(gds_push STATIC push_workflows.c)
target_link_libraries(gds_push PUBLIC gds_client)
