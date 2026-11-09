# OpenGDS - gdsctl, the offline host tool
# SPDX-License-Identifier: MPL-2.0
add_library(gds_verify_audit STATIC verify_audit.c)
target_include_directories(gds_verify_audit PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(gds_verify_audit PUBLIC gds_signer gds_store)

add_library(gds_backup STATIC backup.c)
target_include_directories(gds_backup PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(gds_backup PUBLIC gds_verify_audit)

add_executable(gdsctl main.c push_targets.c)
target_link_libraries(gdsctl PRIVATE gds_backup)
