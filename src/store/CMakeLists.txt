# OpenGDS store: SQLite backend and schema migrations
# SPDX-License-Identifier: MPL-2.0
find_package(SQLite3 3.37 REQUIRED)

# Compile migrations/*.sql into a header of byte arrays (NUL-terminated)
file(GLOB GDS_MIGRATIONS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/migrations/*.sql")
list(SORT GDS_MIGRATIONS)
set(GDS_MIGRATIONS_H "${CMAKE_CURRENT_BINARY_DIR}/migrations_sql.h")
set(_content "/* generated from src/store/migrations - do not edit */\n#pragma once\n")
foreach(f ${GDS_MIGRATIONS})
    get_filename_component(stem "${f}" NAME_WE)
    file(READ "${f}" hex HEX)
    string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," hex "${hex}")
    string(APPEND _content "static const unsigned char gds_sql_${stem}[] = {${hex}0x00};\n")
endforeach()
file(CONFIGURE OUTPUT "${GDS_MIGRATIONS_H}" CONTENT "${_content}" @ONLY)

add_library(gds_store STATIC store_sqlite.c migrate.c)
target_include_directories(gds_store PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}"
                                     PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(gds_store PUBLIC gds_common SQLite::SQLite3)
