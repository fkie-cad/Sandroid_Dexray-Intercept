#include <jni.h>
#include <android/log.h>

#define LOG_TAG "JNI_ENV_EXCEPT"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * EnvExceptionTests for jni_trace.ts hooks:
 *
 *  Exceptions:
 *    - Throw
 *    - ThrowNew
 *    - ExceptionOccurred
 *    - ExceptionDescribe
 *    - ExceptionClear
 *    - ExceptionCheck
 *
 *  Monitors:
 *    - MonitorEnter
 *    - MonitorExit
 *
 *  NOTE: FatalError is intentionally not called (it aborts the VM).
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

static void test_throw_new(JNIEnv *env) {
    LOGI("");
    LOGI("=== Exception tests: ThrowNew / Exception* ===");

    jclass rte = (*env)->FindClass(env, "java/lang/RuntimeException");
    if (rte == NULL) {
        LOGE("FindClass(java/lang/RuntimeException) failed");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return;
    }

    // ThrowNew
    jint rc = (*env)->ThrowNew(env, rte, "Test exception from native ThrowNew");
    TEST_ASSERT(rc == 0, "ThrowNew returned JNI_OK");

    jthrowable ex = (*env)->ExceptionOccurred(env);
    TEST_ASSERT(ex != NULL, "ExceptionOccurred after ThrowNew != NULL");

    // ExceptionCheck should report true
    jboolean hasEx = (*env)->ExceptionCheck(env);
    TEST_ASSERT(hasEx == JNI_TRUE, "ExceptionCheck reports true after ThrowNew");

    // For coverage, call ExceptionDescribe
    (*env)->ExceptionDescribe(env);

    // Clear
    (*env)->ExceptionClear(env);
    hasEx = (*env)->ExceptionCheck(env);
    TEST_ASSERT(hasEx == JNI_FALSE, "ExceptionCheck reports false after ExceptionClear");
}

static void test_throw_existing(JNIEnv *env) {
    LOGI("");
    LOGI("=== Exception tests: Throw(existing object) ===");

    jclass rte = (*env)->FindClass(env, "java/lang/RuntimeException");
    if (rte == NULL) {
        LOGE("FindClass(java/lang/RuntimeException) failed");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return;
    }

    jmethodID ctor = (*env)->GetMethodID(env, rte,
                                         "<init>",
                                         "(Ljava/lang/String;)V");
    if (ctor == NULL) {
        LOGE("GetMethodID(RuntimeException.<init>(String)) failed");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return;
    }

    jstring msg = (*env)->NewStringUTF(env, "Test exception from Throw");
    if (msg == NULL) {
        LOGE("NewStringUTF for Throw message failed");
        (*env)->ExceptionClear(env);
        return;
    }

    jobject exObj = (*env)->NewObject(env, rte, ctor, msg);
    if (exObj == NULL) {
        LOGE("NewObject(RuntimeException) failed");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return;
    }

    // Throw existing exception object
    jint rc = (*env)->Throw(env, (jthrowable)exObj);
    TEST_ASSERT(rc == 0, "Throw(existing RuntimeException) returned JNI_OK");

    jthrowable ex = (*env)->ExceptionOccurred(env);
    TEST_ASSERT(ex != NULL, "ExceptionOccurred after Throw != NULL");

    jboolean hasEx = (*env)->ExceptionCheck(env);
    TEST_ASSERT(hasEx == JNI_TRUE, "ExceptionCheck reports true after Throw");

    (*env)->ExceptionDescribe(env);
    (*env)->ExceptionClear(env);

    hasEx = (*env)->ExceptionCheck(env);
    TEST_ASSERT(hasEx == JNI_FALSE, "ExceptionCheck reports false after clear (Throw)");
}

static void test_monitors(JNIEnv *env) {
    LOGI("");
    LOGI("=== Monitor tests: MonitorEnter / MonitorExit ===");

    jclass objCls = (*env)->FindClass(env, "java/lang/Object");
    if (objCls == NULL) {
        LOGE("FindClass(java/lang/Object) failed");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return;
    }

    jmethodID ctor = (*env)->GetMethodID(env, objCls, "<init>", "()V");
    if (ctor == NULL) {
        LOGE("GetMethodID(Object.<init>) failed");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return;
    }

    jobject lockObj = (*env)->NewObject(env, objCls, ctor);
    if (lockObj == NULL) {
        LOGE("NewObject(Object) failed");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return;
    }

    jint rc = (*env)->MonitorEnter(env, lockObj);
    TEST_ASSERT(rc == 0, "MonitorEnter returned JNI_OK");

    rc = (*env)->MonitorExit(env, lockObj);
    TEST_ASSERT(rc == 0, "MonitorExit returned JNI_OK");

    // If we wanted, we could trigger an error by mismatched enter/exit,
    // but we keep it balanced for safety.
}

JNIEXPORT void JNICALL
Java_com_test_jnie2e_EnvExceptionTests_runTests(JNIEnv *env, jclass clazz) {
    (void) clazz;

    tests_passed = 0;
    tests_failed = 0;

    LOGI("========================================");
    LOGI("EnvExceptionTests: starting");
    LOGI("========================================");

    test_throw_new(env);
    test_throw_existing(env);
    test_monitors(env);

    LOGI("========================================");
    LOGI("EnvExceptionTests summary: %d passed, %d failed", tests_passed, tests_failed);
    LOGI("========================================");
}