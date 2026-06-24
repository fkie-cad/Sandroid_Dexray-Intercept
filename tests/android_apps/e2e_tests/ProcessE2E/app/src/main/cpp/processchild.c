#include <jni.h>
#include <android/log.h>

#define LOG_TAG "PROCESS_CHILD"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/*
 * Library loaded as a dlopen() target by processnative test_dlopen().
 * JNI_OnLoad is not called for C-side dlopen - the dynamic linker does not
 * invoke it; only the JVM does when loading via System.loadLibrary/Runtime.load.
 * The constructor attribute fires when the dynamic linker maps the library,
 * providing logcat confirmation of a successful load independent of the JVM.
 */

__attribute__((constructor))
static void on_library_load(void) {
    LOGI("processchild loaded via dlopen - constructor fired");
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    /* Called only when loaded via JVM (System.loadLibrary/Runtime.load).
     * Not called for C-side dlopen. Present for completeness. */
    LOGI("processchild JNI_OnLoad called (JVM path)");
    return JNI_VERSION_1_6;
}