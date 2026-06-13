// tests/android_apps/e2e_tests/ProcessRuntimeE2E/app/src/main/cpp/processchild.c
#include <jni.h>
#include <android/log.h>

#define LOG_TAG "PROCESS_CHILD"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGI("processchild JNI_OnLoad called");
    return JNI_VERSION_1_6;
}