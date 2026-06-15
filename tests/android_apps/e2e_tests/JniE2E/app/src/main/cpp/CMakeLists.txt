cmake_minimum_required(VERSION 3.22.1)

project("jnie2e")

# Core JNI env tests: GetVersion, FindClass, GetSuperclass, IsAssignableFrom,
# IsInstanceOf, FromReflectedMethod/Field, ToReflectedMethod/Field.
add_library(
        jni_env_core
        SHARED
        jni_env_core.c
)

# Methods / fields JNI env tests: GetObjectClass, GetFieldID / GetStaticFieldID,
# Get<Type>Field / Set<Type>Field, GetStatic<Type>Field / SetStatic<Type>Field.
add_library(
        jni_env_methods_fields
        SHARED
        jni_env_methods_fields.c
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