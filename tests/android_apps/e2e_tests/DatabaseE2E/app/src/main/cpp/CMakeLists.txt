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

# Hide SQLite from the dynamic export table while retaining local symbol names
# for symbol-table based hook discovery.
set_source_files_properties(
        sqlite3.c
        PROPERTIES COMPILE_FLAGS "-w -fvisibility=hidden"
)