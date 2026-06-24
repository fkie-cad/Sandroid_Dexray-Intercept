#include <jni.h>
#include <android/log.h>
#include <unistd.h>

#define LOG_TAG "FS_E2E_NATIVE"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * Native trigger for unlink() hook in file_system_hooks.ts.
 * Hook: safeAttach on libc export "unlink".
 * Called from FileDeleteTests via FileDeleteNative.unlinkFile(path).
 */

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, name) do { \
    if (cond) { \
        LOGI("  PASS: %s", name); \
        tests_passed++; \
    } else { \
        LOGE("  FAIL: %s", name); \
        tests_failed++; \
    } \
} while (0)

JNIEXPORT void JNICALL
Java_com_test_filee2e_FileDeleteNative_unlinkFile(JNIEnv *env, jclass clazz, jstring path) {
    (void)clazz;

    tests_passed = 0;
    tests_failed = 0;

    LOGI("========================================");
    LOGI("FileDeleteNative: starting");
    LOGI("========================================");

    const char *c_path = (*env)->GetStringUTFChars(env, path, NULL);
    if (c_path == NULL) {
        LOGE("GetStringUTFChars returned NULL");
        TEST_ASSERT(0, "GetStringUTFChars non-NULL");
        LOGI("FileDeleteNative summary: %d passed, %d failed", tests_passed, tests_failed);
        return;
    }

    LOGI("calling unlink(\"%s\")", c_path);
    int result = unlink(c_path);
    TEST_ASSERT(result == 0, "unlink() returns 0");

    (*env)->ReleaseStringUTFChars(env, path, c_path);

    LOGI("========================================");
    LOGI("FileDeleteNative summary: %d passed, %d failed", tests_passed, tests_failed);
    LOGI("========================================");
}