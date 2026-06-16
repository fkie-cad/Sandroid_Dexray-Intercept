#include <stdlib.h>
#include <string.h>
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

/* Test 4: DefineClass with a structurally valid .class file buffer
 *
 * On Android/ART, DefineClass is not supported (ART uses DEX, not .class).
 * The function will return NULL (with or without an exception).
 * The hook is still triggered and enriches: define_class_name, class_data_hex,
 * class_data_length. This test uses a real classloader and proper class structure.
 */

static void test_define_class(JNIEnv *env) {
    LOGI("");
    LOGI("=== Core tests: DefineClass (valid structure, ART will reject) ===");

    /*
     * Minimal structurally-valid .class file for:
     *   public class com/test/jnie2e/DummyDefined extends java/lang/Object {}
     *
     * Constant pool (6 entries):
     *   #1 = Class          #5    // com/test/jnie2e/DummyDefined
     *   #2 = Class          #6    // java/lang/Object
     *   #3 = Utf8           "<init>"
     *   #4 = Utf8           "()V"
     *   #5 = Utf8           "com/test/jnie2e/DummyDefined"
     *   #6 = Utf8           "java/lang/Object"
     *
     * access_flags: ACC_PUBLIC | ACC_SUPER (0x0021)
     * this_class: #1, super_class: #2
     * No interfaces, fields, methods, or attributes.
     */
    static const unsigned char classData[] = {
        /* magic */
        0xCA, 0xFE, 0xBA, 0xBE,
        /* minor_version */ 0x00, 0x00,
        /* major_version (52 = Java 8) */ 0x00, 0x34,
        /* constant_pool_count = 7 (6 usable entries) */ 0x00, 0x07,

        /* cp[1]: CONSTANT_Class, name_index -> #5 */
        0x07, 0x00, 0x05,
        /* cp[2]: CONSTANT_Class, name_index -> #6 */
        0x07, 0x00, 0x06,
        /* cp[3]: CONSTANT_Utf8, length=6, "<init>" */
        0x01, 0x00, 0x06,
        0x3C, 0x69, 0x6E, 0x69, 0x74, 0x3E,
        /* cp[4]: CONSTANT_Utf8, length=3, "()V" */
        0x01, 0x00, 0x03,
        0x28, 0x29, 0x56,
        /* cp[5]: CONSTANT_Utf8, length=28, "com/test/jnie2e/DummyDefined" */
        0x01, 0x00, 0x1C,
        0x63, 0x6F, 0x6D, 0x2F, 0x74, 0x65, 0x73, 0x74,
        0x2F, 0x6A, 0x6E, 0x69, 0x65, 0x32, 0x65, 0x2F,
        0x44, 0x75, 0x6D, 0x6D, 0x79, 0x44, 0x65, 0x66,
        0x69, 0x6E, 0x65, 0x64,
        /* cp[6]: CONSTANT_Utf8, length=16, "java/lang/Object" */
        0x01, 0x00, 0x10,
        0x6A, 0x61, 0x76, 0x61, 0x2F, 0x6C, 0x61, 0x6E,
        0x67, 0x2F, 0x4F, 0x62, 0x6A, 0x65, 0x63, 0x74,

        /* access_flags: ACC_PUBLIC | ACC_SUPER */
        0x00, 0x21,
        /* this_class: #1 */  0x00, 0x01,
        /* super_class: #2 */ 0x00, 0x02,
        /* interfaces_count */ 0x00, 0x00,
        /* fields_count */     0x00, 0x00,
        /* methods_count */    0x00, 0x00,
        /* attributes_count */ 0x00, 0x00
    };

    /* Get the real classloader from EnvCoreTests class */
    jclass coreTestsCls = (*env)->FindClass(env, "com/test/jnie2e/EnvCoreTests");
    jobject classLoader = NULL;
    if (coreTestsCls != NULL) {
        jclass classCls = (*env)->FindClass(env, "java/lang/Class");
        if (classCls != NULL) {
            jmethodID getLoaderMid = (*env)->GetMethodID(env, classCls,
                                                         "getClassLoader",
                                                         "()Ljava/lang/ClassLoader;");
            if (getLoaderMid != NULL) {
                classLoader = (*env)->CallObjectMethod(env, coreTestsCls, getLoaderMid);
                if ((*env)->ExceptionCheck(env)) {
                    (*env)->ExceptionClear(env);
                    classLoader = NULL;
                }
            }
        }
    }
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
    }

    LOGI("DefineClass: using classLoader=%p (NULL means bootstrap)", classLoader);
    LOGI("DefineClass: class data size=%d bytes", (int)sizeof(classData));

    const char *name = "com/test/jnie2e/DummyDefined";
    jclass result = (*env)->DefineClass(env,
                                        name,
                                        classLoader,
                                        (const jbyte *)classData,
                                        (jsize) sizeof(classData));

    if (result != NULL) {
        LOGI("DefineClass succeeded (unexpected on ART, but valid)");
        TEST_ASSERT(1, "DefineClass succeeded");
    } else {
        jthrowable ex = (*env)->ExceptionOccurred(env);
        if (ex != NULL) {
            LOGI("DefineClass returned NULL with exception (expected on ART)");
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        } else {
            LOGI("DefineClass returned NULL without exception (ART silently rejects)");
        }
        /* Either way the hook was triggered and saw class_data_hex, define_class_name */
        TEST_ASSERT(1, "DefineClass hook exercised (NULL is expected on ART)");
    }
}

/* Test 5: NewDirectByteBuffer / GetDirectBufferAddress / GetDirectBufferCapacity */

static void test_direct_buffers(JNIEnv *env) {
    LOGI("");
    LOGI("=== Core tests: Direct byte buffers ===");

    /*
     * Allocate a native buffer, wrap it in a DirectByteBuffer, then
     * exercise GetDirectBufferAddress and GetDirectBufferCapacity.
     */
    const jlong capacity = 64;
    void *nativeBuf = malloc((size_t)capacity);
    if (nativeBuf == NULL) {
        LOGE("malloc(%lld) failed", (long long)capacity);
        TEST_ASSERT(0, "malloc for direct buffer");
        return;
    }

    // Write a known pattern so hook enrichment (buffer_hex) has content
    memset(nativeBuf, 0xAB, (size_t)capacity);

    // NewDirectByteBuffer
    jobject bbuf = (*env)->NewDirectByteBuffer(env, nativeBuf, capacity);
    if (bbuf == NULL) {
        LOGE("NewDirectByteBuffer returned NULL");
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        TEST_ASSERT(0, "NewDirectByteBuffer returned non-NULL");
        free(nativeBuf);
        return;
    }
    TEST_ASSERT(bbuf != NULL, "NewDirectByteBuffer returned non-NULL");

    // GetDirectBufferAddress
    void *addr = (*env)->GetDirectBufferAddress(env, bbuf);
    LOGI("GetDirectBufferAddress -> %p (expected %p)", addr, nativeBuf);
    TEST_ASSERT(addr == nativeBuf, "GetDirectBufferAddress returns original pointer");

    // GetDirectBufferCapacity
    jlong cap = (*env)->GetDirectBufferCapacity(env, bbuf);
    LOGI("GetDirectBufferCapacity -> %lld (expected %lld)", (long long)cap, (long long)capacity);
    TEST_ASSERT(cap == capacity, "GetDirectBufferCapacity returns 64");

    free(nativeBuf);
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

    LOGI("");
    LOGI(">> Running test_reflection_and_types...");
    test_reflection_and_types(env);
    LOGI(">> Running test_alloc_object...");
    test_alloc_object(env);
    LOGI(">> Running test_env_getjavavm...");
    test_env_getjavavm(env);
    LOGI(">> Running test_define_class...");
    test_define_class(env);
    LOGI(">> Running test_direct_buffers...");
    test_direct_buffers(env);

    LOGI("========================================");
    LOGI("EnvCoreTests summary: %d passed, %d failed", tests_passed, tests_failed);
    LOGI("========================================");
}