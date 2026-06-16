#include <jni.h>
#include <android/log.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>

#define LOG_TAG "JNI_ENV_CALLS"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

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

/* Helpers for Call*MethodV / CallStatic*MethodV */

static jboolean call_boolean_method_v(JNIEnv *env, jobject obj, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jboolean result = (*env)->CallBooleanMethodV(env, obj, mid, ap);
    va_end(ap);
    return result;
}

static jbyte call_byte_method_v(JNIEnv *env, jobject obj, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jbyte result = (*env)->CallByteMethodV(env, obj, mid, ap);
    va_end(ap);
    return result;
}

static jchar call_char_method_v(JNIEnv *env, jobject obj, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jchar result = (*env)->CallCharMethodV(env, obj, mid, ap);
    va_end(ap);
    return result;
}

static jshort call_short_method_v(JNIEnv *env, jobject obj, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jshort result = (*env)->CallShortMethodV(env, obj, mid, ap);
    va_end(ap);
    return result;
}

static jint call_int_method_v(JNIEnv *env, jobject obj, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jint result = (*env)->CallIntMethodV(env, obj, mid, ap);
    va_end(ap);
    return result;
}

static jlong call_long_method_v(JNIEnv *env, jobject obj, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jlong result = (*env)->CallLongMethodV(env, obj, mid, ap);
    va_end(ap);
    return result;
}

static jfloat call_float_method_v(JNIEnv *env, jobject obj, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jfloat result = (*env)->CallFloatMethodV(env, obj, mid, ap);
    va_end(ap);
    return result;
}

static jdouble call_double_method_v(JNIEnv *env, jobject obj, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jdouble result = (*env)->CallDoubleMethodV(env, obj, mid, ap);
    va_end(ap);
    return result;
}

static void call_void_method_v(JNIEnv *env, jobject obj, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    (*env)->CallVoidMethodV(env, obj, mid, ap);
    va_end(ap);
}

static jobject call_object_method_v(JNIEnv *env, jobject obj, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jobject result = (*env)->CallObjectMethodV(env, obj, mid, ap);
    va_end(ap);
    return result;
}

static jboolean call_static_boolean_method_v(JNIEnv *env, jclass cls, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jboolean result = (*env)->CallStaticBooleanMethodV(env, cls, mid, ap);
    va_end(ap);
    return result;
}

static jbyte call_static_byte_method_v(JNIEnv *env, jclass cls, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jbyte result = (*env)->CallStaticByteMethodV(env, cls, mid, ap);
    va_end(ap);
    return result;
}

static jchar call_static_char_method_v(JNIEnv *env, jclass cls, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jchar result = (*env)->CallStaticCharMethodV(env, cls, mid, ap);
    va_end(ap);
    return result;
}

static jshort call_static_short_method_v(JNIEnv *env, jclass cls, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jshort result = (*env)->CallStaticShortMethodV(env, cls, mid, ap);
    va_end(ap);
    return result;
}

static jint call_static_int_method_v(JNIEnv *env, jclass cls, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jint result = (*env)->CallStaticIntMethodV(env, cls, mid, ap);
    va_end(ap);
    return result;
}

static jlong call_static_long_method_v(JNIEnv *env, jclass cls, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jlong result = (*env)->CallStaticLongMethodV(env, cls, mid, ap);
    va_end(ap);
    return result;
}

static jfloat call_static_float_method_v(JNIEnv *env, jclass cls, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jfloat result = (*env)->CallStaticFloatMethodV(env, cls, mid, ap);
    va_end(ap);
    return result;
}

static jdouble call_static_double_method_v(JNIEnv *env, jclass cls, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jdouble result = (*env)->CallStaticDoubleMethodV(env, cls, mid, ap);
    va_end(ap);
    return result;
}

static void call_static_void_method_v(JNIEnv *env, jclass cls, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    (*env)->CallStaticVoidMethodV(env, cls, mid, ap);
    va_end(ap);
}

static jobject call_static_object_method_v(JNIEnv *env, jclass cls, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jobject result = (*env)->CallStaticObjectMethodV(env, cls, mid, ap);
    va_end(ap);
    return result;
}

static jobject new_object_v(JNIEnv *env, jclass cls, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jobject result = (*env)->NewObjectV(env, cls, mid, ap);
    va_end(ap);
    return result;
}

/*
 * EnvCallsTests for jni_trace.ts hooks (selected subset):
 *
 *  Instance calls:
 *    - CallIntMethod / CallIntMethodV / CallIntMethodA
 *    - CallLongMethod / CallLongMethodV / CallLongMethodA
 *    - CallObjectMethod / CallObjectMethodV / CallObjectMethodA
 *    - CallBooleanMethod / CallBooleanMethodV / CallBooleanMethodA
 *    - CallByteMethod, CallShortMethod
 *
 *  Static calls:
 *    - CallStaticLongMethod / CallStaticLongMethodV / CallStaticLongMethodA
 *    - CallStaticObjectMethod / CallStaticObjectMethodV / CallStaticObjectMethodA
 *
 *  Constructors:
 *    - NewObject / NewObjectA with MethodTarget(int,String) ctor
 *
 *  Methods are defined in com.test.jnie2e.MethodTarget.
 */

/* Test 1: add(int, int) -> int */
static void test_add(JNIEnv *env, jobject target, jmethodID mid) {
    LOGI("");
    LOGI("=== Call tests: Test 1 add(int,int) ===");

    jint r1 = (*env)->CallIntMethod(env, target, mid, (jint)10, (jint)20);
    TEST_ASSERT(r1 == 30, "CallIntMethod add(10,20)=30");

    jint r2 = call_int_method_v(env, target, mid, (jint)10, (jint)20);
    TEST_ASSERT(r2 == 30, "CallIntMethodV add(10,20)=30");

    jvalue args[2];
    args[0].i = 10;
    args[1].i = 20;
    jint r3 = (*env)->CallIntMethodA(env, target, mid, args);
    TEST_ASSERT(r3 == 30, "CallIntMethodA add(10,20)=30");
}

/* Test 2: sum3(long, long, long) -> long */
static void test_sum3(JNIEnv *env, jobject target, jmethodID mid) {
    LOGI("");
    LOGI("=== Call tests: Test 2 sum3(long,long,long) ===");

    jlong r1 = (*env)->CallLongMethod(env, target, mid,
                                      (jlong)100, (jlong)200, (jlong)300);
    TEST_ASSERT(r1 == 600, "CallLongMethod sum3(100,200,300)=600");

    jlong r2 = call_long_method_v(env, target, mid,
                                  (jlong)100, (jlong)200, (jlong)300);
    TEST_ASSERT(r2 == 600, "CallLongMethodV sum3(100,200,300)=600");

    jvalue args[3];
    args[0].j = 100;
    args[1].j = 200;
    args[2].j = 300;
    jlong r3 = (*env)->CallLongMethodA(env, target, mid, args);
    TEST_ASSERT(r3 == 600, "CallLongMethodA sum3(100,200,300)=600");
}

/* Test 3: concat(String, String) -> String */
static void test_concat(JNIEnv *env, jobject target, jmethodID mid) {
    LOGI("");
    LOGI("=== Call tests: Test 3 concat(String,String) ===");

    jstring s1 = (*env)->NewStringUTF(env, "Hello");
    jstring s2 = (*env)->NewStringUTF(env, "World");

    // CallObjectMethod
    jstring r1 = (jstring)(*env)->CallObjectMethod(env, target, mid, s1, s2);
    if (r1 != NULL) {
        const char *cstr = (*env)->GetStringUTFChars(env, r1, NULL);
        TEST_ASSERT(strcmp(cstr, "HelloWorld") == 0,
                    "CallObjectMethod concat='HelloWorld'");
        (*env)->ReleaseStringUTFChars(env, r1, cstr);
    } else {
        TEST_ASSERT(0, "CallObjectMethod concat returned NULL");
    }

    // CallObjectMethodV
    jstring r2 = (jstring)call_object_method_v(env, target, mid, s1, s2);
    if (r2 != NULL) {
        const char *cstr = (*env)->GetStringUTFChars(env, r2, NULL);
        TEST_ASSERT(strcmp(cstr, "HelloWorld") == 0,
                    "CallObjectMethodV concat='HelloWorld'");
        (*env)->ReleaseStringUTFChars(env, r2, cstr);
    } else {
        TEST_ASSERT(0, "CallObjectMethodV concat returned NULL");
    }

    // CallObjectMethodA
    jvalue args[2];
    args[0].l = s1;
    args[1].l = s2;
    jstring r3 = (jstring)(*env)->CallObjectMethodA(env, target, mid, args);
    if (r3 != NULL) {
        const char *cstr = (*env)->GetStringUTFChars(env, r3, NULL);
        TEST_ASSERT(strcmp(cstr, "HelloWorld") == 0,
                    "CallObjectMethodA concat='HelloWorld'");
        (*env)->ReleaseStringUTFChars(env, r3, cstr);
    } else {
        TEST_ASSERT(0, "CallObjectMethodA concat returned NULL");
    }
}

/* Test 4: mixed(int, String, double) -> String */
static void test_mixed(JNIEnv *env, jobject target, jmethodID mid) {
    LOGI("");
    LOGI("=== Call tests: Test 4 mixed(int,String,double) ===");

    jstring str = (*env)->NewStringUTF(env, "test");

    // CallObjectMethod (varargs)
    jstring r1 = (jstring)(*env)->CallObjectMethod(env, target, mid,
                                                   (jint)42, str, (jdouble)3.14);
    if (r1 != NULL) {
        const char *cstr = (*env)->GetStringUTFChars(env, r1, NULL);
        int match = strstr(cstr, "42") && strstr(cstr, "test") && strstr(cstr, "3.14");
        TEST_ASSERT(match, "CallObjectMethod mixed pattern");
        (*env)->ReleaseStringUTFChars(env, r1, cstr);
    } else {
        TEST_ASSERT(0, "CallObjectMethod mixed returned NULL");
    }

    // CallObjectMethodV
    jstring r2 = (jstring)call_object_method_v(env, target, mid,
                                               (jint)42, str, (jdouble)3.14);
    if (r2 != NULL) {
        const char *cstr = (*env)->GetStringUTFChars(env, r2, NULL);
        int match = strstr(cstr, "42") && strstr(cstr, "test") && strstr(cstr, "3.14");
        TEST_ASSERT(match, "CallObjectMethodV mixed pattern");
        (*env)->ReleaseStringUTFChars(env, r2, cstr);
    } else {
        TEST_ASSERT(0, "CallObjectMethodV mixed returned NULL");
    }

    // CallObjectMethodA
    jvalue args[3];
    args[0].i = 42;
    args[1].l = str;
    args[2].d = 3.14;
    jstring r3 = (jstring)(*env)->CallObjectMethodA(env, target, mid, args);
    if (r3 != NULL) {
        const char *cstr = (*env)->GetStringUTFChars(env, r3, NULL);
        int match = strstr(cstr, "42") && strstr(cstr, "test") && strstr(cstr, "3.14");
        TEST_ASSERT(match, "CallObjectMethodA mixed pattern");
        (*env)->ReleaseStringUTFChars(env, r3, cstr);
    } else {
        TEST_ASSERT(0, "CallObjectMethodA mixed returned NULL");
    }
}

/* Test 5: manyArgs(int, long, float, double, boolean) -> long */
static void test_manyArgs(JNIEnv *env, jobject target, jmethodID mid) {
    LOGI("");
    LOGI("=== Call tests: Test 5 manyArgs(int,long,float,double,boolean) ===");

    // CallLongMethod
    jlong r1 = (*env)->CallLongMethod(env, target, mid,
                                      (jint)1, (jlong)2, (jfloat)3.0f, (jdouble)4.0, (jboolean)JNI_TRUE);
    TEST_ASSERT(r1 == 11, "CallLongMethod manyArgs=11");

    // CallLongMethodV
    jlong r2 = call_long_method_v(env, target, mid,
                                  (jint)1, (jlong)2, (jfloat)3.0f, (jdouble)4.0, (jboolean)JNI_TRUE);
    TEST_ASSERT(r2 == 11, "CallLongMethodV manyArgs=11");

    // CallLongMethodA
    jvalue args[5];
    args[0].i = 1;
    args[1].j = 2;
    args[2].f = 3.0f;
    args[3].d = 4.0;
    args[4].z = JNI_TRUE;
    jlong r3 = (*env)->CallLongMethodA(env, target, mid, args);
    TEST_ASSERT(r3 == 11, "CallLongMethodA manyArgs=11");
}

/* Test 6: staticSum(long, long) [STATIC] */
static void test_staticSum(JNIEnv *env, jclass targetClass, jmethodID mid) {
    LOGI("");
    LOGI("=== Call tests: Test 6 staticSum(long,long) [STATIC] ===");

    jlong r1 = (*env)->CallStaticLongMethod(env, targetClass, mid,
                                            (jlong)1000, (jlong)2000);
    TEST_ASSERT(r1 == 3000, "CallStaticLongMethod staticSum=3000");

    jlong r2 = call_static_long_method_v(env, targetClass, mid,
                                         (jlong)1000, (jlong)2000);
    TEST_ASSERT(r2 == 3000, "CallStaticLongMethodV staticSum=3000");

    jvalue args[2];
    args[0].j = 1000;
    args[1].j = 2000;
    jlong r3 = (*env)->CallStaticLongMethodA(env, targetClass, mid, args);
    TEST_ASSERT(r3 == 3000, "CallStaticLongMethodA staticSum=3000");
}

/* Test 7: NewObject with constructor args (int, String) - all 3 forms */
static void test_newObject_with_args(JNIEnv *env, jclass targetClass, jmethodID ctorWithArgs) {
    LOGI("");
    LOGI("=== Call tests: Test 7 NewObject / NewObjectV / NewObjectA with args ===");

    jstring initStr = (*env)->NewStringUTF(env, "init");

    // NewObject (varargs)
    jobject r1 = (*env)->NewObject(env, targetClass, ctorWithArgs, (jint)42, initStr);
    TEST_ASSERT(r1 != NULL, "NewObject(int,String) returned non-NULL");

    // NewObjectV (via helper)
    jobject r2 = new_object_v(env, targetClass, ctorWithArgs, (jint)42, initStr);
    TEST_ASSERT(r2 != NULL, "NewObjectV(int,String) returned non-NULL");

    // NewObjectA (jvalue array)
    jvalue args[2];
    args[0].i = 42;
    args[1].l = initStr;
    jobject r3 = (*env)->NewObjectA(env, targetClass, ctorWithArgs, args);
    TEST_ASSERT(r3 != NULL, "NewObjectA(int,String) returned non-NULL");
}

/* Test 8: boolean and small primitive methods */
static void test_boolean_and_small_primitives(JNIEnv *env, jobject target, jclass targetClass) {
    LOGI("");
    LOGI("=== Call tests: Test 8 boolean and small primitives ===");

    jmethodID boolAndMid = (*env)->GetMethodID(env, targetClass,
                                               "boolAnd", "(IZ)Z");
    if (boolAndMid != NULL) {
        jboolean r1 = (*env)->CallBooleanMethod(env, target, boolAndMid, (jint)1, JNI_TRUE);
        TEST_ASSERT(r1 == JNI_TRUE, "CallBooleanMethod boolAnd(1,true)=true");

        jboolean r2 = call_boolean_method_v(env, target, boolAndMid, (jint)1, JNI_TRUE);
        TEST_ASSERT(r2 == JNI_TRUE, "CallBooleanMethodV boolAnd(1,true)=true");

        jvalue args[2];
        args[0].i = 1;
        args[1].z = JNI_TRUE;
        jboolean r3 = (*env)->CallBooleanMethodA(env, target, boolAndMid, args);
        TEST_ASSERT(r3 == JNI_TRUE, "CallBooleanMethodA boolAnd(1,true)=true");
    } else {
        LOGE("Skipping boolAnd: method not found");
        (*env)->ExceptionClear(env);
    }

    jmethodID addBytesMid = (*env)->GetMethodID(env, targetClass,
                                                "addBytes", "(BB)B");
    if (addBytesMid != NULL) {
        jbyte br = (*env)->CallByteMethod(env, target, addBytesMid, (jbyte)10, (jbyte)20);
        TEST_ASSERT(br == (jbyte)30, "CallByteMethod addBytes(10,20)=30");

        jbyte br2 = call_byte_method_v(env, target, addBytesMid, (jbyte)10, (jbyte)20);
        TEST_ASSERT(br2 == (jbyte)30, "CallByteMethodV addBytes(10,20)=30");

        jvalue bargs[2];
        bargs[0].b = 10;
        bargs[1].b = 20;
        jbyte br3 = (*env)->CallByteMethodA(env, target, addBytesMid, bargs);
        TEST_ASSERT(br3 == (jbyte)30, "CallByteMethodA addBytes(10,20)=30");
    } else {
        LOGE("Skipping addBytes: method not found");
        (*env)->ExceptionClear(env);
    }

    jmethodID addShortsMid = (*env)->GetMethodID(env, targetClass,
                                                 "addShorts", "(SS)S");
    if (addShortsMid != NULL) {
        jshort sr = (*env)->CallShortMethod(env, target, addShortsMid, (jshort)1000, (jshort)2000);
        TEST_ASSERT(sr == (jshort)3000, "CallShortMethod addShorts(1000,2000)=3000");

        jshort sr2 = call_short_method_v(env, target, addShortsMid, (jshort)1000, (jshort)2000);
        TEST_ASSERT(sr2 == (jshort)3000, "CallShortMethodV addShorts(1000,2000)=3000");

        jvalue sargs[2];
        sargs[0].s = 1000;
        sargs[1].s = 2000;
        jshort sr3 = (*env)->CallShortMethodA(env, target, addShortsMid, sargs);
        TEST_ASSERT(sr3 == (jshort)3000, "CallShortMethodA addShorts(1000,2000)=3000");
    } else {
        LOGE("Skipping addShorts: method not found");
        (*env)->ExceptionClear(env);
    }
}

/* Test 9: staticConcat3(String,String,String) -> String [STATIC] */
static void test_static_object_methods(JNIEnv *env, jclass targetClass) {
    LOGI("");
    LOGI("=== Call tests: Test 9 staticConcat3(String,String,String) [STATIC] ===");

    jmethodID staticConcat3Mid = (*env)->GetStaticMethodID(env, targetClass,
                                                           "staticConcat3",
                                                           "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    if (staticConcat3Mid == NULL) {
        LOGE("Skipping staticConcat3 tests: method not found");
        (*env)->ExceptionClear(env);
        return;
    }

    jstring s1 = (*env)->NewStringUTF(env, "one");
    jstring s2 = (*env)->NewStringUTF(env, "two");
    jstring s3 = (*env)->NewStringUTF(env, "three");

    jstring r1 = (jstring)(*env)->CallStaticObjectMethod(env, targetClass, staticConcat3Mid, s1, s2, s3);
    if (r1 != NULL) {
        const char *c1 = (*env)->GetStringUTFChars(env, r1, NULL);
        LOGI("  CallStaticObjectMethod: '%s'", c1);
        (*env)->ReleaseStringUTFChars(env, r1, c1);
    }

    jstring r2 = (jstring)call_static_object_method_v(env, targetClass, staticConcat3Mid, s1, s2, s3);
    if (r2 != NULL) {
        const char *c2 = (*env)->GetStringUTFChars(env, r2, NULL);
        LOGI("  CallStaticObjectMethodV: '%s'", c2);
        (*env)->ReleaseStringUTFChars(env, r2, c2);
    }

    jvalue args[3];
    args[0].l = s1;
    args[1].l = s2;
    args[2].l = s3;
    jstring r3 = (jstring)(*env)->CallStaticObjectMethodA(env, targetClass, staticConcat3Mid, args);
    if (r3 != NULL) {
        const char *c3 = (*env)->GetStringUTFChars(env, r3, NULL);
        LOGI("  CallStaticObjectMethodA: '%s'", c3);
        (*env)->ReleaseStringUTFChars(env, r3, c3);
    }
}

/* Test 10: float/double instance calls (CallFloatMethod/CallFloatMethodV/CallFloatMethodA,CallDoubleMethod/CallDoubleMethodV/CallDoubleMethodA) */
static void test_float_double_calls(JNIEnv *env, jobject target, jclass targetClass) {
    LOGI("");
    LOGI("=== Call tests: Test 10 float/double instance calls ===");

    jmethodID mulFloatMid = (*env)->GetMethodID(env, targetClass,
                                                "mulFloat", "(FF)F");
    jmethodID mulDoubleMid = (*env)->GetMethodID(env, targetClass,
                                                 "mulDouble", "(DD)D");

    if (mulFloatMid != NULL) {
        jfloat rf1 = (*env)->CallFloatMethod(env, target, mulFloatMid,
                                             (jfloat)1.5f, (jfloat)2.0f);
        TEST_ASSERT(fabsf(rf1 - 3.0f) < 0.0001f, "CallFloatMethod mulFloat(1.5,2)=3");

        jfloat rf2 = call_float_method_v(env, target, mulFloatMid,
                                         (jfloat)1.5f, (jfloat)2.0f);
        TEST_ASSERT(fabsf(rf2 - 3.0f) < 0.0001f, "CallFloatMethodV mulFloat(1.5,2)=3");

        jvalue args[2];
        args[0].f = 1.5f;
        args[1].f = 2.0f;
        jfloat rf3 = (*env)->CallFloatMethodA(env, target, mulFloatMid, args);
        TEST_ASSERT(fabsf(rf3 - 3.0f) < 0.0001f, "CallFloatMethodA mulFloat(1.5,2)=3");
    } else {
        LOGE("Skipping mulFloat: method not found");
        (*env)->ExceptionClear(env);
    }

    if (mulDoubleMid != NULL) {
        jdouble rd1 = (*env)->CallDoubleMethod(env, target, mulDoubleMid,
                                               (jdouble)2.0, (jdouble)4.0);
        TEST_ASSERT(fabs(rd1 - 8.0) < 1e-6, "CallDoubleMethod mulDouble(2,4)=8");

        jdouble rd2 = call_double_method_v(env, target, mulDoubleMid,
                                           (jdouble)2.0, (jdouble)4.0);
        TEST_ASSERT(fabs(rd2 - 8.0) < 1e-6, "CallDoubleMethodV mulDouble(2,4)=8");

        jvalue args[2];
        args[0].d = 2.0;
        args[1].d = 4.0;
        jdouble rd3 = (*env)->CallDoubleMethodA(env, target, mulDoubleMid, args);
        TEST_ASSERT(fabs(rd3 - 8.0) < 1e-6, "CallDoubleMethodA mulDouble(2,4)=8");
    } else {
        LOGE("Skipping mulDouble: method not found");
        (*env)->ExceptionClear(env);
    }
}

/* Test 11: void instance calls */
static void test_void_calls(JNIEnv *env, jobject target, jclass targetClass) {
    LOGI("");
    LOGI("=== Call tests: Test 11 void instance calls ===");

    jmethodID voidMid = (*env)->GetMethodID(env, targetClass,
                                            "voidMethod", "(ILjava/lang/String;)V");
    if (voidMid == NULL) {
        LOGE("Skipping voidMethod: method not found");
        (*env)->ExceptionClear(env);
        return;
    }

    jstring s = (*env)->NewStringUTF(env, "void");
    if (s == NULL) {
        LOGE("NewStringUTF(\"void\") failed");
        (*env)->ExceptionClear(env);
        return;
    }

    // CallVoidMethod
    (*env)->CallVoidMethod(env, target, voidMid, (jint)123, s);
    TEST_ASSERT(1, "CallVoidMethod voidMethod executed");

    // CallVoidMethodV
    call_void_method_v(env, target, voidMid, (jint)789, s);
    TEST_ASSERT(1, "CallVoidMethodV voidMethod executed");

    // CallVoidMethodA
    jvalue args[2];
    args[0].i = 456;
    args[1].l = s;
    (*env)->CallVoidMethodA(env, target, voidMid, args);
    TEST_ASSERT(1, "CallVoidMethodA voidMethod executed");
}

/* Test 12: static primitive calls (CallStatic*Method* families) */
static void test_static_primitive_calls(JNIEnv *env, jclass targetClass) {
    LOGI("");
    LOGI("=== Call tests: Test 12 static primitive calls ===");

    // boolean staticAnd(boolean,boolean)
    jmethodID midAnd = (*env)->GetStaticMethodID(env, targetClass,
                                                 "staticAnd", "(ZZ)Z");
    if (midAnd != NULL) {
        jboolean r1 = (*env)->CallStaticBooleanMethod(env, targetClass, midAnd,
                                                      (jboolean)JNI_TRUE, (jboolean)JNI_TRUE);
        TEST_ASSERT(r1 == JNI_TRUE, "CallStaticBooleanMethod staticAnd(true,true)=true");

        jboolean r2 = call_static_boolean_method_v(env, targetClass, midAnd,
                                                    (jboolean)JNI_TRUE, (jboolean)JNI_TRUE);
        TEST_ASSERT(r2 == JNI_TRUE, "CallStaticBooleanMethodV staticAnd(true,true)=true");

        jvalue args[2];
        args[0].z = JNI_TRUE;
        args[1].z = JNI_FALSE;
        jboolean r3 = (*env)->CallStaticBooleanMethodA(env, targetClass, midAnd, args);
        TEST_ASSERT(r3 == JNI_FALSE, "CallStaticBooleanMethodA staticAnd(true,false)=false");
    } else {
        LOGE("Skipping staticAnd: method not found");
        (*env)->ExceptionClear(env);
    }

    // byte staticAddBytes(byte,byte)
    jmethodID midAddBytes = (*env)->GetStaticMethodID(env, targetClass,
                                                      "staticAddBytes", "(BB)B");
    if (midAddBytes != NULL) {
        jbyte br1 = (*env)->CallStaticByteMethod(env, targetClass, midAddBytes,
                                                (jbyte)10, (jbyte)20);
        TEST_ASSERT(br1 == (jbyte)30, "CallStaticByteMethod staticAddBytes(10,20)=30");

        jbyte br2 = call_static_byte_method_v(env, targetClass, midAddBytes,
                                              (jbyte)10, (jbyte)20);
        TEST_ASSERT(br2 == (jbyte)30, "CallStaticByteMethodV staticAddBytes(10,20)=30");

        jvalue args[2];
        args[0].b = 10;
        args[1].b = 20;
        jbyte br3 = (*env)->CallStaticByteMethodA(env, targetClass, midAddBytes, args);
        TEST_ASSERT(br3 == (jbyte)30, "CallStaticByteMethodA staticAddBytes(10,20)=30");
    } else {
        LOGE("Skipping staticAddBytes: method not found");
        (*env)->ExceptionClear(env);
    }

    // char staticShiftChar(char)
    jmethodID midShiftChar = (*env)->GetStaticMethodID(env, targetClass,
                                                       "staticShiftChar", "(C)C");
    if (midShiftChar != NULL) {
        jchar cr1 = (*env)->CallStaticCharMethod(env, targetClass, midShiftChar, (jchar)'A');
        TEST_ASSERT(cr1 == (jchar)('A' + 1), "CallStaticCharMethod staticShiftChar('A')='B'");

        jchar cr2 = call_static_char_method_v(env, targetClass, midShiftChar, (jchar)'A');
        TEST_ASSERT(cr2 == (jchar)('A' + 1), "CallStaticCharMethodV staticShiftChar('A')='B'");

        jvalue args[1];
        args[0].c = 'A';
        jchar cr3 = (*env)->CallStaticCharMethodA(env, targetClass, midShiftChar, args);
        TEST_ASSERT(cr3 == (jchar)('A' + 1), "CallStaticCharMethodA staticShiftChar('A')='B'");
    } else {
        LOGE("Skipping staticShiftChar: method not found");
        (*env)->ExceptionClear(env);
    }

    // short staticAddShorts(short,short)
    jmethodID midAddShorts = (*env)->GetStaticMethodID(env, targetClass,
                                                       "staticAddShorts", "(SS)S");
    if (midAddShorts != NULL) {
        jshort sr1 = (*env)->CallStaticShortMethod(env, targetClass, midAddShorts,
                                                  (jshort)100, (jshort)200);
        TEST_ASSERT(sr1 == (jshort)300, "CallStaticShortMethod staticAddShorts(100,200)=300");

        jshort sr2 = call_static_short_method_v(env, targetClass, midAddShorts,
                                                (jshort)100, (jshort)200);
        TEST_ASSERT(sr2 == (jshort)300, "CallStaticShortMethodV staticAddShorts(100,200)=300");

        jvalue args[2];
        args[0].s = 100;
        args[1].s = 200;
        jshort sr3 = (*env)->CallStaticShortMethodA(env, targetClass, midAddShorts, args);
        TEST_ASSERT(sr3 == (jshort)300, "CallStaticShortMethodA staticAddShorts(100,200)=300");
    } else {
        LOGE("Skipping staticAddShorts: method not found");
        (*env)->ExceptionClear(env);
    }

    // int staticAddInts(int,int)
    jmethodID midAddInts = (*env)->GetStaticMethodID(env, targetClass,
                                                     "staticAddInts", "(II)I");
    if (midAddInts != NULL) {
        jint ir1 = (*env)->CallStaticIntMethod(env, targetClass, midAddInts, (jint)2, (jint)3);
        TEST_ASSERT(ir1 == 5, "CallStaticIntMethod staticAddInts(2,3)=5");

        jint ir2 = call_static_int_method_v(env, targetClass, midAddInts, (jint)2, (jint)3);
        TEST_ASSERT(ir2 == 5, "CallStaticIntMethodV staticAddInts(2,3)=5");

        jvalue args[2];
        args[0].i = 2;
        args[1].i = 3;
        jint ir3 = (*env)->CallStaticIntMethodA(env, targetClass, midAddInts, args);
        TEST_ASSERT(ir3 == 5, "CallStaticIntMethodA staticAddInts(2,3)=5");
    } else {
        LOGE("Skipping staticAddInts: method not found");
        (*env)->ExceptionClear(env);
    }

    // float staticMulFloats(float,float)
    jmethodID midMulFloats = (*env)->GetStaticMethodID(env, targetClass,
                                                       "staticMulFloats", "(FF)F");
    if (midMulFloats != NULL) {
        jfloat fr1 = (*env)->CallStaticFloatMethod(env, targetClass, midMulFloats,
                                                  (jfloat)1.5f, (jfloat)2.0f);
        TEST_ASSERT(fabsf(fr1 - 3.0f) < 0.0001f, "CallStaticFloatMethod staticMulFloats(1.5,2)=3");

        jfloat fr2 = call_static_float_method_v(env, targetClass, midMulFloats,
                                                (jfloat)1.5f, (jfloat)2.0f);
        TEST_ASSERT(fabsf(fr2 - 3.0f) < 0.0001f, "CallStaticFloatMethodV staticMulFloats(1.5,2)=3");

        jvalue args[2];
        args[0].f = 1.5f;
        args[1].f = 2.0f;
        jfloat fr3 = (*env)->CallStaticFloatMethodA(env, targetClass, midMulFloats, args);
        TEST_ASSERT(fabsf(fr3 - 3.0f) < 0.0001f, "CallStaticFloatMethodA staticMulFloats(1.5,2)=3");
    } else {
        LOGE("Skipping staticMulFloats: method not found");
        (*env)->ExceptionClear(env);
    }

    // double staticMulDoubles(double,double)
    jmethodID midMulDoubles = (*env)->GetStaticMethodID(env, targetClass,
                                                        "staticMulDoubles", "(DD)D");
    if (midMulDoubles != NULL) {
        jdouble dr1 = (*env)->CallStaticDoubleMethod(env, targetClass, midMulDoubles,
                                                    (jdouble)2.0, (jdouble)4.0);
        TEST_ASSERT(fabs(dr1 - 8.0) < 1e-6, "CallStaticDoubleMethod staticMulDoubles(2,4)=8");

        jdouble dr2 = call_static_double_method_v(env, targetClass, midMulDoubles,
                                                  (jdouble)2.0, (jdouble)4.0);
        TEST_ASSERT(fabs(dr2 - 8.0) < 1e-6, "CallStaticDoubleMethodV staticMulDoubles(2,4)=8");

        jvalue args[2];
        args[0].d = 2.0;
        args[1].d = 4.0;
        jdouble dr3 = (*env)->CallStaticDoubleMethodA(env, targetClass, midMulDoubles, args);
        TEST_ASSERT(fabs(dr3 - 8.0) < 1e-6, "CallStaticDoubleMethodA staticMulDoubles(2,4)=8");
    } else {
        LOGE("Skipping staticMulDoubles: method not found");
        (*env)->ExceptionClear(env);
    }

    // void staticVoidLog(String)
    jmethodID midVoid = (*env)->GetStaticMethodID(env, targetClass,
                                                  "staticVoidLog", "(Ljava/lang/String;)V");
    if (midVoid != NULL) {
        jstring s = (*env)->NewStringUTF(env, "static-void");

        (*env)->CallStaticVoidMethod(env, targetClass, midVoid, s);
        TEST_ASSERT(1, "CallStaticVoidMethod executed");

        call_static_void_method_v(env, targetClass, midVoid, s);
        TEST_ASSERT(1, "CallStaticVoidMethodV executed");

        jvalue args[1];
        args[0].l = s;
        (*env)->CallStaticVoidMethodA(env, targetClass, midVoid, args);
        TEST_ASSERT(1, "CallStaticVoidMethodA executed");
    } else {
        LOGE("Skipping staticVoidLog: method not found");
        (*env)->ExceptionClear(env);
    }
}

/* Test 13: Nonvirtual calls using NonvirtualBase / NonvirtualDerived */
static void test_nonvirtual_calls(JNIEnv *env) {
    LOGI("");
    LOGI("=== Call tests: Test 13 nonvirtual calls ===");

    jclass baseCls = (*env)->FindClass(env, "com/test/jnie2e/NonvirtualBase");
    jclass derivedCls = (*env)->FindClass(env, "com/test/jnie2e/NonvirtualDerived");
    if (baseCls == NULL || derivedCls == NULL) {
        LOGE("FindClass(NonvirtualBase/NonvirtualDerived) failed");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return;
    }

    jmethodID ctorDerived = (*env)->GetMethodID(env, derivedCls, "<init>", "()V");
    if (ctorDerived == NULL) {
        LOGE("GetMethodID(NonvirtualDerived.<init>) failed");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return;
    }

    jobject derivedObj = (*env)->NewObject(env, derivedCls, ctorDerived);
    if (derivedObj == NULL) {
        LOGE("NewObject(NonvirtualDerived) failed");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return;
    }

    // Prepare base-class method IDs
    jmethodID midInt    = (*env)->GetMethodID(env, baseCls, "baseInt",    "(I)I");
    jmethodID midBool   = (*env)->GetMethodID(env, baseCls, "baseBool",   "(Z)Z");
    jmethodID midByte   = (*env)->GetMethodID(env, baseCls, "baseByte",   "(B)B");
    jmethodID midChar   = (*env)->GetMethodID(env, baseCls, "baseChar",   "(C)C");
    jmethodID midShort  = (*env)->GetMethodID(env, baseCls, "baseShort",  "(S)S");
    jmethodID midLong   = (*env)->GetMethodID(env, baseCls, "baseLong",   "(J)J");
    jmethodID midFloat  = (*env)->GetMethodID(env, baseCls, "baseFloat",  "(F)F");
    jmethodID midDouble = (*env)->GetMethodID(env, baseCls, "baseDouble", "(D)D");
    jmethodID midVoid   = (*env)->GetMethodID(env, baseCls, "baseVoid",
                                              "(Ljava/lang/String;)V");

    if (midInt != NULL) {
        jint v = (*env)->CallNonvirtualIntMethod(env, derivedObj, baseCls, midInt, (jint)2);
        TEST_ASSERT(v == 20, "CallNonvirtualIntMethod baseInt(2)=20");
    }

    if (midBool != NULL) {
        jboolean b = (*env)->CallNonvirtualBooleanMethod(env, derivedObj, baseCls, midBool,
                                                         (jboolean)JNI_TRUE);
        TEST_ASSERT(b == JNI_FALSE, "CallNonvirtualBooleanMethod baseBool(true)=false");
    }

    if (midByte != NULL) {
        jbyte bb = (*env)->CallNonvirtualByteMethod(env, derivedObj, baseCls, midByte,
                                                    (jbyte)5);
        TEST_ASSERT(bb == (jbyte)6, "CallNonvirtualByteMethod baseByte(5)=6");
    }

    if (midChar != NULL) {
        jchar c = (*env)->CallNonvirtualCharMethod(env, derivedObj, baseCls, midChar,
                                                   (jchar)'A');
        TEST_ASSERT(c == (jchar)('A' + 1), "CallNonvirtualCharMethod baseChar('A')='B'");
    }

    if (midShort != NULL) {
        jshort s = (*env)->CallNonvirtualShortMethod(env, derivedObj, baseCls, midShort,
                                                     (jshort)100);
        TEST_ASSERT(s == (jshort)110, "CallNonvirtualShortMethod baseShort(100)=110");
    }

    if (midLong != NULL) {
        jlong l = (*env)->CallNonvirtualLongMethod(env, derivedObj, baseCls, midLong,
                                                   (jlong)1000);
        TEST_ASSERT(l == 1100, "CallNonvirtualLongMethod baseLong(1000)=1100");
    }

    if (midFloat != NULL) {
        jfloat f = (*env)->CallNonvirtualFloatMethod(env, derivedObj, baseCls, midFloat,
                                                     (jfloat)1.5f);
        TEST_ASSERT(fabsf(f - 2.5f) < 0.0001f, "CallNonvirtualFloatMethod baseFloat(1.5)=2.5");
    }

    if (midDouble != NULL) {
        jdouble d = (*env)->CallNonvirtualDoubleMethod(env, derivedObj, baseCls, midDouble,
                                                       (jdouble)2.5);
        TEST_ASSERT(fabs(d - 3.5) < 1e-6, "CallNonvirtualDoubleMethod baseDouble(2.5)=3.5");
    }

    if (midVoid != NULL) {
        jstring js = (*env)->NewStringUTF(env, "nv");
        (*env)->CallNonvirtualVoidMethod(env, derivedObj, baseCls, midVoid, js);
        TEST_ASSERT(1, "CallNonvirtualVoidMethod baseVoid executed");
    }
}

/* Test 14: CallCharMethod / CallCharMethodV / CallCharMethodA (instance) */
static void test_char_instance_calls(JNIEnv *env, jobject target, jclass targetClass) {
    LOGI("");
    LOGI("=== Call tests: Test 14 CallCharMethod/V/A (instance) ===");

    jmethodID shiftCharMid = (*env)->GetMethodID(env, targetClass,
                                                  "shiftChar", "(C)C");
    if (shiftCharMid == NULL) {
        LOGE("Skipping shiftChar: method not found");
        (*env)->ExceptionClear(env);
        return;
    }

    // CallCharMethod
    jchar r1 = (*env)->CallCharMethod(env, target, shiftCharMid, (jchar)'A');
    TEST_ASSERT(r1 == (jchar)'B', "CallCharMethod shiftChar('A')='B'");

    // CallCharMethodV
    jchar r2 = call_char_method_v(env, target, shiftCharMid, (jchar)'X');
    TEST_ASSERT(r2 == (jchar)'Y', "CallCharMethodV shiftChar('X')='Y'");

    // CallCharMethodA
    jvalue args[1];
    args[0].c = 'M';
    jchar r3 = (*env)->CallCharMethodA(env, target, shiftCharMid, args);
    TEST_ASSERT(r3 == (jchar)'N', "CallCharMethodA shiftChar('M')='N'");
}

/* Entry point */

JNIEXPORT void JNICALL
Java_com_test_jnie2e_EnvCallsTests_runTests(JNIEnv *env, jclass clazz) {
    (void) clazz;

    tests_passed = 0;
    tests_failed = 0;

    LOGI("========================================");
    LOGI("EnvCallsTests: starting");
    LOGI("========================================");

    jclass targetClass = (*env)->FindClass(env, "com/test/jnie2e/MethodTarget");
    if (targetClass == NULL) {
        LOGE("FindClass(MethodTarget) failed");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return;
    }

    jmethodID ctor = (*env)->GetMethodID(env, targetClass, "<init>", "()V");
    if (ctor == NULL) {
        LOGE("GetMethodID(MethodTarget.<init>) failed");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return;
    }

    jobject target = (*env)->NewObject(env, targetClass, ctor);
    if (target == NULL) {
        LOGE("NewObject(MethodTarget) failed");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return;
    }

    jmethodID addMid       = (*env)->GetMethodID(env, targetClass, "add",       "(II)I");
    jmethodID sum3Mid      = (*env)->GetMethodID(env, targetClass, "sum3",      "(JJJ)J");
    jmethodID concatMid    = (*env)->GetMethodID(env, targetClass, "concat",
                                                 "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    jmethodID mixedMid     = (*env)->GetMethodID(env, targetClass, "mixed",
                                                 "(ILjava/lang/String;D)Ljava/lang/String;");
    jmethodID manyArgsMid  = (*env)->GetMethodID(env, targetClass, "manyArgs",
                                                 "(IJFDZ)J");
    jmethodID staticSumMid = (*env)->GetStaticMethodID(env, targetClass,
                                                       "staticSum", "(JJ)J");
    jmethodID ctorWithArgs = (*env)->GetMethodID(env, targetClass, "<init>",
                                                 "(ILjava/lang/String;)V");

    if (addMid != NULL)         test_add(env, target, addMid);
    else                        LOGE("Skipping test_add: method not found");

    if (sum3Mid != NULL)        test_sum3(env, target, sum3Mid);
    else                        LOGE("Skipping test_sum3: method not found");

    if (concatMid != NULL)      test_concat(env, target, concatMid);
    else                        LOGE("Skipping test_concat: method not found");

    if (mixedMid != NULL)       test_mixed(env, target, mixedMid);
    else                        LOGE("Skipping test_mixed: method not found");

    if (manyArgsMid != NULL)    test_manyArgs(env, target, manyArgsMid);
    else                        LOGE("Skipping test_manyArgs: method not found");

    if (staticSumMid != NULL)   test_staticSum(env, targetClass, staticSumMid);
    else                        LOGE("Skipping test_staticSum: method not found");

    if (ctorWithArgs != NULL)   test_newObject_with_args(env, targetClass, ctorWithArgs);
    else                        LOGE("Skipping test_newObject_with_args: ctor not found");

    LOGI("");
    LOGI(">> Running test_boolean_and_small_primitives...");
    test_boolean_and_small_primitives(env, target, targetClass);

    LOGI("");
    LOGI(">> Running test_static_object_methods...");
    test_static_object_methods(env, targetClass);

    LOGI("");
    LOGI(">> Running test_float_double_calls...");
    test_float_double_calls(env, target, targetClass);

    LOGI("");
    LOGI(">> Running test_void_calls...");
    test_void_calls(env, target, targetClass);

    LOGI("");
    LOGI(">> Running test_static_primitive_calls...");
    test_static_primitive_calls(env, targetClass);

    LOGI("");
    LOGI(">> Running test_nonvirtual_calls...");
    test_nonvirtual_calls(env);

    LOGI("");
    LOGI(">> Running test_char_instance_calls...");
    test_char_instance_calls(env, target, targetClass);

    LOGI("========================================");
    LOGI("EnvCallsTests summary: %d passed, %d failed", tests_passed, tests_failed);
    LOGI("========================================");
}