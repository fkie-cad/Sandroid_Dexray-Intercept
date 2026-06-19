#include <jni.h>
#include <android/log.h>

#define LOG_TAG "DEX_E2E_NATIVE"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * Minimal native library for SystemLoadLibraryTests and RuntimeLoadLibraryTests.
 *
 * This library has no exported JNI methods - it exists solely as a load target
 * so that System.load(path), System.loadLibrary(name), Runtime.load(path), and
 * Runtime.loadLibrary(name) each have a real .so to act on, ensuring the
 * load_library.ts hooks fire in a meaningful context.
 *
 * Loading the same library multiple times on Android is safe (no-op after
 * first load), so all four test calls can target this single library.
 */

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) vm;
    (void) reserved;
    LOGI("dexe2e_native loaded - JNI_OnLoad called");
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    (void) vm;
    (void) reserved;
    LOGI("dexe2e_native unloaded - JNI_OnUnload called");
}