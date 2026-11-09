# Push engine: sessions to managed Servers and the Part 12 push workflows
# SPDX-License-Identifier: MPL-2.0
add_library(gds_push STATIC push_workflows.c push_setup.c push_keycred.c)
target_link_libraries(gds_push PUBLIC gds_client)

# The scheduler inside opengdsd (OpenGDS plan W3): push_engine.c, its
# timing rules (push_sched.c) and the rejected-list harvest
add_library(gds_push_engine STATIC push_engine.c push_sched.c push_rejected.c)
target_include_directories(gds_push_engine PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(gds_push_engine PUBLIC gds_push gds_server)
