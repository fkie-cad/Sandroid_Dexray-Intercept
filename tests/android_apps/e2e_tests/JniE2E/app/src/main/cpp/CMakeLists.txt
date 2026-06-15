cmake_minimum_required(VERSION 3.22.1)

project("jnie2e")

# Core JNI env tests
add_library(
        jni_env_core
        SHARED
        jni_env_core.c
)

find_library(log-lib log)

target_link_libraries(
        jni_env_core
        ${log-lib}
        android
)