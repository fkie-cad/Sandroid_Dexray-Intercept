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
 *  Identity / type:
 *    - IsSameObject
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

/* Helper to log GetObjectRefType result */
static const char *ref_type_str(jobjectRefType t) {
    switch (t) {
        case JNILocalRefType:      return "JNILocalRefType";
        case JNIGlobalRefType:     return "JNIGlobalRefType";
        case JNIWeakGlobalRefType: return "JNIWeakGlobalRefType";
        case JNIInvalidRefType:
        default:                   return "JNIInvalidRefType";
    }
}

/* Test 1: PushLocalFrame / PopLocalFrame / NewLocalRef / DeleteLocalRef / IsSameObject */

static void test_local_frame_and_local_refs(JNIEnv *env) {
    LOGI("");
    LOGI("=== Ref tests: Local frames / local refs ===");

    // Push a local frame with capacity for several locals
    jint rc = (*env)->PushLocalFrame(env, 10);
    TEST_ASSERT(rc == 0, "PushLocalFrame(10) returns JNI_OK");

    // Create a local jstring
    jstring s = (*env)->NewStringUTF(env, "local");
    if (s == NULL) {
        LOGE("NewStringUTF(\"local\") failed");
        (*env)->ExceptionClear(env);
        (*env)->PopLocalFrame(env, NULL);
        return;
    }

    // EnsureLocalCapacity (no-op if already enough space)
    rc = (*env)->EnsureLocalCapacity(env, 5);
    TEST_ASSERT(rc == 0, "EnsureLocalCapacity(5) returns JNI_OK");

    // NewLocalRef on the string
    jobject localRef = (*env)->NewLocalRef(env, s);
    TEST_ASSERT(localRef != NULL, "NewLocalRef(s) returned non-NULL");

    // IsSameObject
    jboolean same1 = (*env)->IsSameObject(env, s, localRef);
    TEST_ASSERT(same1 == JNI_TRUE, "IsSameObject(s, localRef) == true");

    // DeleteLocalRef
    (*env)->DeleteLocalRef(env, localRef);

    // PopLocalFrame: returns a local reference that remains valid in the previous frame
    jobject sOut = (*env)->PopLocalFrame(env, s);
    TEST_ASSERT(sOut != NULL, "PopLocalFrame(s) returned non-NULL");
}

/* Test 2: NewGlobalRef / DeleteGlobalRef / NewWeakGlobalRef / DeleteWeakGlobalRef / GetObjectRefType */

static void test_global_and_weak_refs(JNIEnv *env) {
    LOGI("");
    LOGI("=== Ref tests: Global / weak-global refs ===");

    // Create a base String instance
    jstring s = (*env)->NewStringUTF(env, "global-weak");
    if (s == NULL) {
        LOGE("NewStringUTF(\"global-weak\") failed");
        (*env)->ExceptionClear(env);
        return;
    }

    // NewGlobalRef
    jobject gref = (*env)->NewGlobalRef(env, s);
    TEST_ASSERT(gref != NULL, "NewGlobalRef(s) returned non-NULL");

    // NewWeakGlobalRef
    jobject wref = (*env)->NewWeakGlobalRef(env, s);
    TEST_ASSERT(wref != NULL, "NewWeakGlobalRef(s) returned non-NULL");

    // GetObjectRefType for local/global/weak
    jobjectRefType t_local = (*env)->GetObjectRefType(env, s);
    jobjectRefType t_global = (*env)->GetObjectRefType(env, gref);
    jobjectRefType t_weak = (*env)->GetObjectRefType(env, wref);

    LOGI("  GetObjectRefType(local)  -> %s", ref_type_str(t_local));
    LOGI("  GetObjectRefType(global) -> %s", ref_type_str(t_global));
    LOGI("  GetObjectRefType(weak)   -> %s", ref_type_str(t_weak));

    TEST_ASSERT(t_local == JNILocalRefType, "GetObjectRefType(local) == JNILocalRefType");
    TEST_ASSERT(t_global == JNIGlobalRefType, "GetObjectRefType(global) == JNIGlobalRefType");
    TEST_ASSERT(t_weak == JNIWeakGlobalRefType, "GetObjectRefType(weak) == JNIWeakGlobalRefType");

    // IsSameObject checks
    jboolean same2 = (*env)->IsSameObject(env, s, gref);
    jboolean same3 = (*env)->IsSameObject(env, s, wref);
    TEST_ASSERT(same2 == JNI_TRUE, "IsSameObject(s, gref) == true");
    TEST_ASSERT(same3 == JNI_TRUE, "IsSameObject(s, wref) == true");

    // Delete refs
    (*env)->DeleteGlobalRef(env, gref);
    (*env)->DeleteWeakGlobalRef(env, wref);

    // After deletion, type is unspecified; we do not assert on it, but hooks see Delete* calls.
}

/* Entry point */

JNIEXPORT void JNICALL
Java_com_test_jnie2e_EnvRefTests_runTests(JNIEnv *env, jclass clazz) {
    (void) clazz;

    tests_passed = 0;
    tests_failed = 0;

    LOGI("========================================");
    LOGI("EnvRefTests: starting");
    LOGI("========================================");

    test_local_frame_and_local_refs(env);
    test_global_and_weak_refs(env);

    LOGI("========================================");
    LOGI("EnvRefTests summary: %d passed, %d failed", tests_passed, tests_failed);
    LOGI("========================================");
}