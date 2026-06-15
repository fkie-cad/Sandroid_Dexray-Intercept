# tests/android_apps/e2e_tests/ProcessE2E/app/src/main/cpp/CMakeLists.txt
cmake_minimum_required(VERSION 3.22.1)

project("processe2e")

add_library(
        processnative
        SHARED
        processnative.c
)

add_library(
        processchild
        SHARED
        processchild.c
)

find_library(log-lib log)
find_library(dl-lib dl)

target_link_libraries(
        processnative
        ${log-lib}
        ${dl-lib}
        android
)

target_link_libraries(
        processchild
        ${log-lib}
        android
)
