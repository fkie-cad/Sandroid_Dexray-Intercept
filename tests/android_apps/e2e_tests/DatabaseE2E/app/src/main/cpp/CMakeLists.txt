cmake_minimum_required(VERSION 3.22.1)

project("databasee2e")

add_library(
        native_db_tests
        SHARED
        sqlite_native_tests.c
        sqlite3.c
)

find_library(log-lib log)

target_link_libraries(
        native_db_tests
        ${log-lib}
)

# Suppress warnings from the SQLite amalgamation
set_source_files_properties(
        sqlite3.c
        PROPERTIES COMPILE_FLAGS "-w"
)