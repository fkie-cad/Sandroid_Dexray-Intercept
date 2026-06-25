#include <jni.h>
#include <android/log.h>

#define LOG_TAG "JNI_ENV_REFS"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * EnvRefTests for jni_trace.ts hooks:
 *
 *  Frames / local capacity:
 *    - PushLocalFrame
 *    - PopLocalFrame
 *    - EnsureLocalCapacity
 *
 *  Local/global/weak refs:
 *    - NewLocalRef
 *    - DeleteLocalRef
 *    - NewGlobalRef
 *    - DeleteGlobalRef
 *    - NewWeakGlobalRef
 *    - DeleteWeakGlobalRef
 *
 *  Identity:
 *    - IsSameObject
 *
 *  Ref type:
 *    - GetObjectRefType
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

/* Test 1: PushLocalFrame / PopLocalFrame / NewLocalRef / DeleteLocalRef / IsSameObject */

static void test_local_frame_and_local_refs(JNIEnv *env) {
    LOGI("");
    LOGI("=== Ref tests: Local frames / local refs ===");

    jint rc = (*env)->PushLocalFrame(env, 10);
    TEST_ASSERT(rc == 0, "PushLocalFrame(10) returns JNI_OK");

    jstring s = (*env)->NewStringUTF(env, "local");
    if (s == NULL) {
        LOGE("NewStringUTF(\"local\") failed");
        (*env)->ExceptionClear(env);
        (*env)->PopLocalFrame(env, NULL);
        return;
    }

    rc = (*env)->EnsureLocalCapacity(env, 5);
    TEST_ASSERT(rc == 0, "EnsureLocalCapacity(5) returns JNI_OK");

    jobject localRef = (*env)->NewLocalRef(env, s);
    TEST_ASSERT(localRef != NULL, "NewLocalRef(s) returned non-NULL");

    jboolean same1 = (*env)->IsSameObject(env, s, localRef);
    TEST_ASSERT(same1 == JNI_TRUE, "IsSameObject(s, localRef) == true");

    (*env)->DeleteLocalRef(env, localRef);

    jobject sOut = (*env)->PopLocalFrame(env, s);
    TEST_ASSERT(sOut != NULL, "PopLocalFrame(s) returned non-NULL");
}

/* Test 2: NewGlobalRef / DeleteGlobalRef / NewWeakGlobalRef / DeleteWeakGlobalRef / IsSameObject */

static void test_global_and_weak_refs(JNIEnv *env) {
    LOGI("");
    LOGI("=== Ref tests: Global / weak-global refs ===");

    jstring s = (*env)->NewStringUTF(env, "global-weak");
    if (s == NULL) {
        LOGE("NewStringUTF(\"global-weak\") failed");
        (*env)->ExceptionClear(env);
        return;
    }

    jobject gref = (*env)->NewGlobalRef(env, s);
    TEST_ASSERT(gref != NULL, "NewGlobalRef(s) returned non-NULL");

    jobject wref = (*env)->NewWeakGlobalRef(env, s);
    TEST_ASSERT(wref != NULL, "NewWeakGlobalRef(s) returned non-NULL");

    // Identity checks using global / weak refs
    jboolean same_global = (*env)->IsSameObject(env, s, gref);
    jboolean same_weak   = (*env)->IsSameObject(env, s, wref);
    TEST_ASSERT(same_global == JNI_TRUE, "IsSameObject(s, gref) == true");
    TEST_ASSERT(same_weak   == JNI_TRUE, "IsSameObject(s, wref) == true");

    // Clean up refs so DeleteGlobalRef / DeleteWeakGlobalRef are exercised
    (*env)->DeleteGlobalRef(env, gref);
    (*env)->DeleteWeakGlobalRef(env, wref);
}

/* Test 3: GetObjectRefType */

static void test_get_object_ref_type(JNIEnv *env) {
    LOGI("");
    LOGI("=== Ref tests: GetObjectRefType ===");

    /*
     * GetObjectRefType should return:
     *   JNILocalRefType  = 1  for local references
     *   JNIGlobalRefType = 2  for global references
     *   JNIWeakGlobalRefType = 3  for weak global references
     *
     * NOTE: Earlier attempts reported a hook crash when calling this.
     * The app-side code is correct; if the hook crashes, that is a hook bug.
     * This test validates that the app can call the function without error.
     */

    jstring s = (*env)->NewStringUTF(env, "reftype-test");
    if (s == NULL) {
        LOGE("NewStringUTF failed in test_get_object_ref_type");
        (*env)->ExceptionClear(env);
        TEST_ASSERT(0, "NewStringUTF for GetObjectRefType");
        return;
    }

    // Test local ref type
    jobjectRefType localType = (*env)->GetObjectRefType(env, s);
    LOGI("GetObjectRefType(local jstring) -> %d (expect 1=JNILocalRefType)", (int)localType);
    TEST_ASSERT(localType == JNILocalRefType, "GetObjectRefType(local) == JNILocalRefType");

    // Test global ref type
    jobject gref = (*env)->NewGlobalRef(env, s);
    if (gref != NULL) {
        jobjectRefType globalType = (*env)->GetObjectRefType(env, gref);
        LOGI("GetObjectRefType(global ref) -> %d (expect 2=JNIGlobalRefType)", (int)globalType);
        TEST_ASSERT(globalType == JNIGlobalRefType, "GetObjectRefType(global) == JNIGlobalRefType");
        (*env)->DeleteGlobalRef(env, gref);
    } else {
        TEST_ASSERT(0, "NewGlobalRef for GetObjectRefType non-NULL");
    }

    // Test weak global ref type
    jweak wref = (*env)->NewWeakGlobalRef(env, s);
    if (wref != NULL) {
        jobjectRefType weakType = (*env)->GetObjectRefType(env, wref);
        LOGI("GetObjectRefType(weak ref) -> %d (expect 3=JNIWeakGlobalRefType)", (int)weakType);
        TEST_ASSERT(weakType == JNIWeakGlobalRefType, "GetObjectRefType(weak) == JNIWeakGlobalRefType");
        (*env)->DeleteWeakGlobalRef(env, wref);
    } else {
        TEST_ASSERT(0, "NewWeakGlobalRef for GetObjectRefType non-NULL");
    }
}

JNIEXPORT void JNICALL
Java_com_test_jnie2e_EnvRefTests_runTests(JNIEnv *env, jclass clazz) {
    (void) clazz;

    tests_passed = 0;
    tests_failed = 0;

    LOGI("========================================");
    LOGI("EnvRefTests: starting");
    LOGI("========================================");

    LOGI("");
    LOGI(">> Running test_local_frame_and_local_refs...");
    test_local_frame_and_local_refs(env);

    LOGI("");
    LOGI(">> Running test_global_and_weak_refs...");
    test_global_and_weak_refs(env);

    LOGI("");
    LOGI(">> Running test_get_object_ref_type...");
    test_get_object_ref_type(env);

    LOGI("========================================");
    LOGI("EnvRefTests summary: %d passed, %d failed", tests_passed, tests_failed);
    LOGI("========================================");
}