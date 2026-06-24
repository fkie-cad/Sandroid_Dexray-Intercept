cmake_minimum_required(VERSION 3.22.1)

project("filee2e")

# Native trigger for unlink() hook in file_system_hooks.ts
add_library(
        file_delete_native
        SHARED
        file_delete_native.c
)

find_library(log-lib log)

target_link_libraries(
        file_delete_native
        ${log-lib}
        android
)