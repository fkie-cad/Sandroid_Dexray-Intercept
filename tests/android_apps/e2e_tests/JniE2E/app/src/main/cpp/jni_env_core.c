#include <jni.h>
#include <android/log.h>

#define LOG_TAG "JNI_ENV_CORE"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * EnvCoreTests for jni_trace.ts hooks:
 *
 *  Reflection / types:
 *    - GetVersion
 *    - FindClass
 *    - GetSuperclass
 *    - IsAssignableFrom
 *    - IsInstanceOf
 *    - FromReflectedMethod / ToReflectedMethod
 *    - FromReflectedField / ToReflectedField
 *
 *  Object creation / VM:
 *    - AllocObject
 *    - JNIEnv::GetJavaVM
 *    - DefineClass (using dummy class bytes; may throw ClassFormatError)
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

/* Test 1: reflection / types (existing tests) */

static void test_reflection_and_types(JNIEnv *env) {
    LOGI("");
    LOGI("=== Core tests: reflection / types ===");

    jint version = (*env)->GetVersion(env);
    LOGI("GetVersion: 0x%x", version);
    TEST_ASSERT(version != 0, "GetVersion returns non-zero");

    jclass stringCls = (*env)->FindClass(env, "java/lang/String");
    jclass objectCls = (*env)->FindClass(env, "java/lang/Object");
    jclass systemCls = (*env)->FindClass(env, "java/lang/System");

    if (stringCls == NULL || objectCls == NULL || systemCls == NULL) {
        LOGE("FindClass failed for one of String/Object/System");
        (*env)->ExceptionClear(env);
        TEST_ASSERT(0, "FindClass for core types");
        return;
    }
    TEST_ASSERT(stringCls != NULL, "FindClass(java/lang/String)");
    TEST_ASSERT(objectCls != NULL, "FindClass(java/lang/Object)");
    TEST_ASSERT(systemCls != NULL, "FindClass(java/lang/System)");

    jclass superOfString = (*env)->GetSuperclass(env, stringCls);
    LOGI("GetSuperclass(String) -> %p", superOfString);
    TEST_ASSERT(superOfString != NULL, "GetSuperclass(String) non-NULL");

    jboolean stringToObject = (*env)->IsAssignableFrom(env, stringCls, objectCls);
    jboolean objectToString = (*env)->IsAssignableFrom(env, objectCls, stringCls);
    LOGI("IsAssignableFrom(String, Object) -> %s", stringToObject ? "true" : "false");
    LOGI("IsAssignableFrom(Object, String) -> %s", objectToString ? "true" : "false");
    TEST_ASSERT(stringToObject == JNI_TRUE,  "String is assignable to Object");
    TEST_ASSERT(objectToString == JNI_FALSE, "Object is not assignable to String");

    jstring s = (*env)->NewStringUTF(env, "core");
    if (s != NULL) {
        jboolean instString = (*env)->IsInstanceOf(env, s, stringCls);
        jboolean instObject = (*env)->IsInstanceOf(env, s, objectCls);
        LOGI("IsInstanceOf(jstring, String) -> %s", instString ? "true" : "false");
        LOGI("IsInstanceOf(jstring, Object) -> %s", instObject ? "true" : "false");
        TEST_ASSERT(instString == JNI_TRUE, "IsInstanceOf(jstring, String)");
        TEST_ASSERT(instObject == JNI_TRUE, "IsInstanceOf(jstring, Object)");
    } else {
        LOGE("NewStringUTF(\"core\") returned NULL");
        (*env)->ExceptionClear(env);
        TEST_ASSERT(0, "NewStringUTF(\"core\")");
    }

    // From/ToReflectedMethod on String.length()
    jmethodID lengthMid = (*env)->GetMethodID(env, stringCls, "length", "()I");
    if (lengthMid != NULL) {
        jobject reflectedMethod = (*env)->ToReflectedMethod(env, stringCls, lengthMid, JNI_FALSE);
        LOGI("ToReflectedMethod(String.length) -> %p", reflectedMethod);
        TEST_ASSERT(reflectedMethod != NULL, "ToReflectedMethod(String.length) non-NULL");

        if (reflectedMethod != NULL) {
            jmethodID lengthMid2 = (*env)->FromReflectedMethod(env, reflectedMethod);
            LOGI("FromReflectedMethod(reflected length) -> %p", lengthMid2);
            TEST_ASSERT(lengthMid2 != NULL, "FromReflectedMethod(String.length) non-NULL");
        }
    } else {
        LOGE("GetMethodID(String.length) failed");
        (*env)->ExceptionClear(env);
        TEST_ASSERT(0, "GetMethodID(String.length)");
    }

    // From/ToReflectedField on System.out
    jfieldID outFieldId = (*env)->GetStaticFieldID(
            env,
            systemCls,
            "out",
            "Ljava/io/PrintStream;"
    );
    if (outFieldId != NULL) {
        jobject reflectedField = (*env)->ToReflectedField(env, systemCls, outFieldId, JNI_TRUE);
        LOGI("ToReflectedField(System.out) -> %p", reflectedField);
        TEST_ASSERT(reflectedField != NULL, "ToReflectedField(System.out) non-NULL");

        if (reflectedField != NULL) {
            jfieldID outFieldId2 = (*env)->FromReflectedField(env, reflectedField);
            LOGI("FromReflectedField(reflected System.out) -> %p", outFieldId2);
            TEST_ASSERT(outFieldId2 != NULL, "FromReflectedField(System.out) non-NULL");
        }
    } else {
        LOGE("GetStaticFieldID(System.out) failed");
        (*env)->ExceptionClear(env);
        TEST_ASSERT(0, "GetStaticFieldID(System.out)");
    }
}

/* Test 2: AllocObject(java/lang/Object) */

static void test_alloc_object(JNIEnv *env) {
    LOGI("");
    LOGI("=== Core tests: AllocObject ===");

    jclass objCls = (*env)->FindClass(env, "java/lang/Object");
    if (objCls == NULL) {
        LOGE("FindClass(java/lang/Object) failed in test_alloc_object");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        TEST_ASSERT(0, "FindClass(java/lang/Object) for AllocObject");
        return;
    }

    jobject obj = (*env)->AllocObject(env, objCls);
    if (obj == NULL) {
        LOGE("AllocObject(java/lang/Object) returned NULL");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        TEST_ASSERT(0, "AllocObject(java/lang/Object) non-NULL");
        return;
    }

    LOGI("AllocObject(java/lang/Object) -> %p", obj);
    jboolean isObj = (*env)->IsInstanceOf(env, obj, objCls);
    TEST_ASSERT(isObj == JNI_TRUE, "AllocObject result is instance of Object");
}

/* Test 3: JNIEnv::GetJavaVM */

static void test_env_getjavavm(JNIEnv *env) {
    LOGI("");
    LOGI("=== Core tests: JNIEnv::GetJavaVM ===");

    JavaVM *vm = NULL;
    jint rc = (*env)->GetJavaVM(env, &vm);
    TEST_ASSERT(rc == 0, "JNIEnv::GetJavaVM returns JNI_OK");
    TEST_ASSERT(vm != NULL, "JNIEnv::GetJavaVM returns non-NULL JavaVM*");
}

/* Test 4: DefineClass with dummy class bytes (may throw) */

static void test_define_class(JNIEnv *env) {
    LOGI("");
    LOGI("=== Core tests: DefineClass (dummy bytes) ===");

    /*
     * Minimal, likely invalid or incomplete class file buffer.
     * The goal is to exercise the DefineClass hook and its enrichment
     * (class_data_hex, class_data_length, etc.), not to load a usable class.
     *
     * Header: 0xCAFEBABE, version 0x0000 0x0034 (Java 8),
     * followed by a small, fake constant pool body.
     */
    static const unsigned char classData[] = {
        0xCA, 0xFE, 0xBA, 0xBE,  // magic
        0x00, 0x00,              // minor version
        0x00, 0x34,              // major version (52)
        0x00, 0x01,              // constant_pool_count = 1 (minimal)
        // No constant pool entries; this is intentionally malformed
    };

    const char *name = "com/test/jnie2e/DummyDefinedClass";
    jclass result = (*env)->DefineClass(env,
                                        name,
                                        NULL, // bootstrap loader
                                        (const jbyte *)classData,
                                        (jsize) sizeof(classData));

    if (result == NULL) {
        jthrowable ex = (*env)->ExceptionOccurred(env);
        if (ex != NULL) {
            LOGI("DefineClass threw an exception (expected with dummy bytes)");
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
            TEST_ASSERT(1, "DefineClass invoked (exception OK)");
        } else {
            LOGE("DefineClass returned NULL without exception");
            TEST_ASSERT(0, "DefineClass result");
        }
    } else {
        LOGI("DefineClass succeeded for %s", name);
        TEST_ASSERT(1, "DefineClass succeeded");
    }
}

/* Entry point */

JNIEXPORT void JNICALL
Java_com_test_jnie2e_EnvCoreTests_runTests(JNIEnv *env, jclass clazz) {
    (void) clazz;

    tests_passed = 0;
    tests_failed = 0;

    LOGI("========================================");
    LOGI("EnvCoreTests: starting");
    LOGI("========================================");

    test_reflection_and_types(env);
    test_alloc_object(env);
    test_env_getjavavm(env);
    test_define_class(env);

    LOGI("========================================");
    LOGI("EnvCoreTests summary: %d passed, %d failed", tests_passed, tests_failed);
    LOGI("========================================");
}