cmake_minimum_required(VERSION 3.22.1)

project("jnie2e")

# Core JNI env tests
add_library(
        jni_env_core
        SHARED
        jni_env_core.c
)

# Methods / fields JNI env tests
add_library(
        jni_env_methods_fields
        SHARED
        jni_env_methods_fields.c
)

# Instance / static method call tests
add_library(
        jni_env_calls
        SHARED
        jni_env_calls.c
)

# String API tests
add_library(
        jni_env_strings
        SHARED
        jni_env_strings.c
)

# Array tests
add_library(
        jni_env_arrays
        SHARED
        jni_env_arrays.c
)

# Reference / frame / weak-ref tests
add_library(
        jni_env_refs
        SHARED
        jni_env_refs.c
)

# Exception / monitor tests
add_library(
        jni_env_exceptions
        SHARED
        jni_env_exceptions.c
)

find_library(log-lib log)

target_link_libraries(
        jni_env_core
        ${log-lib}
        android
)

target_link_libraries(
        jni_env_methods_fields
        ${log-lib}
        android
)

target_link_libraries(
        jni_env_calls
        ${log-lib}
        android
)

target_link_libraries(
        jni_env_strings
        ${log-lib}
        android
)

target_link_libraries(
        jni_env_arrays
        ${log-lib}
        android
)

target_link_libraries(
        jni_env_refs
        ${log-lib}
        android
)

target_link_libraries(
        jni_env_exceptions
        ${log-lib}
        android
)