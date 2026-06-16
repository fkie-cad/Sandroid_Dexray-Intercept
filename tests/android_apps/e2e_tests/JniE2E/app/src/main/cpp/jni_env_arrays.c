#include <jni.h>
#include <android/log.h>
#include <math.h>
#include <string.h>

#define LOG_TAG "JNI_ENV_ARRAYS"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * EnvArrayTests for jni_trace.ts hooks:
 *
 *  - GetArrayLength
 *  - NewObjectArray / GetObjectArrayElement / SetObjectArrayElement
 *
 *  Primitive arrays:
 *    - NewBooleanArray, NewByteArray, NewCharArray, NewShortArray,
 *      NewIntArray, NewLongArray, NewFloatArray, NewDoubleArray
 *    - Get*ArrayElements / Release*ArrayElements
 *    - Set*ArrayRegion / Get*ArrayRegion
 *    - GetPrimitiveArrayCritical / ReleasePrimitiveArrayCritical
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

/* Test A: jintArray and jlongArray (length, elements, regions) */

static void test_int_and_long_arrays(JNIEnv *env) {
    LOGI("");
    LOGI("=== Array tests: jintArray / jlongArray ===");

    // jintArray
    {
        jsize len = 5;
        jintArray arr = (*env)->NewIntArray(env, len);
        if (arr == NULL) {
            LOGE("NewIntArray failed");
        } else {
            jint tmp[5] = { 1, 2, 3, 4, 5 };

            (*env)->SetIntArrayRegion(env, arr, 0, len, tmp);

            jsize len2 = (*env)->GetArrayLength(env, arr);
            LOGI("  jintArray length = %d", (int)len2);
            TEST_ASSERT(len2 == len, "GetArrayLength for jintArray");

            jboolean isCopy = JNI_FALSE;
            jint *elems = (*env)->GetIntArrayElements(env, arr, &isCopy);
            if (elems == NULL) {
                LOGE("  GetIntArrayElements returned NULL");
                TEST_ASSERT(0, "GetIntArrayElements non-NULL");
            } else {
                LOGI("  jintArray elems: %d %d %d %d %d",
                     elems[0], elems[1], elems[2], elems[3], elems[4]);
                TEST_ASSERT(elems[0] == 1 && elems[1] == 2 &&
                            elems[2] == 3 && elems[3] == 4 && elems[4] == 5,
                            "jintArray contents [1,2,3,4,5]");
                (*env)->ReleaseIntArrayElements(env, arr, elems, 0);
            }

            jint out[5] = {0};
            (*env)->GetIntArrayRegion(env, arr, 0, len, out);
            LOGI("  GetIntArrayRegion: %d %d %d %d %d",
                 out[0], out[1], out[2], out[3], out[4]);
            TEST_ASSERT(out[0] == 1 && out[1] == 2 &&
                        out[2] == 3 && out[3] == 4 && out[4] == 5,
                        "GetIntArrayRegion contents [1,2,3,4,5]");
        }
    }

    // jlongArray
    {
        jsize len = 3;
        jlongArray arr = (*env)->NewLongArray(env, len);
        if (arr == NULL) {
            LOGE("NewLongArray failed");
        } else {
            jlong tmp[3] = { 100, 200, 300 };

            (*env)->SetLongArrayRegion(env, arr, 0, len, tmp);

            jsize len2 = (*env)->GetArrayLength(env, arr);
            LOGI("  jlongArray length = %d", (int)len2);
            TEST_ASSERT(len2 == len, "GetArrayLength for jlongArray");

            jboolean isCopy = JNI_FALSE;
            jlong *elems = (*env)->GetLongArrayElements(env, arr, &isCopy);
            if (elems == NULL) {
                LOGE("  GetLongArrayElements returned NULL");
                TEST_ASSERT(0, "GetLongArrayElements non-NULL");
            } else {
                LOGI("  jlongArray elems: %lld %lld %lld",
                     (long long)elems[0],
                     (long long)elems[1],
                     (long long)elems[2]);
                TEST_ASSERT(elems[0] == 100 && elems[1] == 200 && elems[2] == 300,
                            "jlongArray contents [100,200,300]");
                (*env)->ReleaseLongArrayElements(env, arr, elems, 0);
            }

            jlong out[3] = {0};
            (*env)->GetLongArrayRegion(env, arr, 0, len, out);
            LOGI("  GetLongArrayRegion: %lld %lld %lld",
                 (long long)out[0],
                 (long long)out[1],
                 (long long)out[2]);
            TEST_ASSERT(out[0] == 100 && out[1] == 200 && out[2] == 300,
                        "GetLongArrayRegion contents [100,200,300]");
        }
    }
}

/* Test B: remaining primitive arrays (boolean, byte, char, short, float, double) */

static void test_more_primitive_arrays(JNIEnv *env) {
    LOGI("");
    LOGI("=== Array tests: remaining primitive arrays ===");

    // jbooleanArray
    {
        LOGI("  [bool] jbooleanArray");
        jsize len = 3;
        jbooleanArray arr = (*env)->NewBooleanArray(env, len);
        if (arr) {
            jboolean tmp[3] = { JNI_TRUE, JNI_FALSE, JNI_TRUE };
            (*env)->SetBooleanArrayRegion(env, arr, 0, len, tmp);

            jboolean isCopy = JNI_FALSE;
            jboolean *elems = (*env)->GetBooleanArrayElements(env, arr, &isCopy);
            if (elems) {
                LOGI("    elems: %d %d %d", elems[0], elems[1], elems[2]);
                TEST_ASSERT(elems[0] == JNI_TRUE &&
                            elems[1] == JNI_FALSE &&
                            elems[2] == JNI_TRUE,
                            "jbooleanArray contents [T,F,T]");
                (*env)->ReleaseBooleanArrayElements(env, arr, elems, 0);
            }

            // GetBooleanArrayRegion
            jboolean out[3] = {0};
            (*env)->GetBooleanArrayRegion(env, arr, 0, len, out);
            LOGI("    GetBooleanArrayRegion: %d %d %d", out[0], out[1], out[2]);
            TEST_ASSERT(out[0] == JNI_TRUE &&
                        out[1] == JNI_FALSE &&
                        out[2] == JNI_TRUE,
                        "GetBooleanArrayRegion contents [T,F,T]");
        }
    }

    // jbyteArray
    {
        LOGI("  [byte] jbyteArray");
        jsize len = 4;
        jbyteArray arr = (*env)->NewByteArray(env, len);
        if (arr) {
            jbyte tmp[4] = { 10, 20, 30, 40 };
            (*env)->SetByteArrayRegion(env, arr, 0, len, tmp);

            jboolean isCopy = JNI_FALSE;
            jbyte *elems = (*env)->GetByteArrayElements(env, arr, &isCopy);
            if (elems) {
                LOGI("    elems: %d %d %d %d",
                     (int)elems[0], (int)elems[1], (int)elems[2], (int)elems[3]);
                TEST_ASSERT(elems[0] == 10 && elems[1] == 20 &&
                            elems[2] == 30 && elems[3] == 40,
                            "jbyteArray contents [10,20,30,40]");
                (*env)->ReleaseByteArrayElements(env, arr, elems, 0);
            }

            jbyte out[4] = {0};
            (*env)->GetByteArrayRegion(env, arr, 0, len, out);
            LOGI("    GetByteArrayRegion: %d %d %d %d",
                 (int)out[0], (int)out[1], (int)out[2], (int)out[3]);
            TEST_ASSERT(out[0] == 10 && out[1] == 20 &&
                        out[2] == 30 && out[3] == 40,
                        "GetByteArrayRegion contents [10,20,30,40]");
        }
    }

    // jcharArray
    {
        LOGI("  [char] jcharArray");
        jsize len = 3;
        jcharArray arr = (*env)->NewCharArray(env, len);
        if (arr) {
            jchar tmp[3] = { 'A', 'B', 'C' };
            (*env)->SetCharArrayRegion(env, arr, 0, len, tmp);

            jboolean isCopy = JNI_FALSE;
            jchar *elems = (*env)->GetCharArrayElements(env, arr, &isCopy);
            if (elems) {
                LOGI("    elems: %c %c %c",
                     (char)elems[0], (char)elems[1], (char)elems[2]);
                TEST_ASSERT(elems[0] == 'A' && elems[1] == 'B' && elems[2] == 'C',
                            "jcharArray contents ['A','B','C']");
                (*env)->ReleaseCharArrayElements(env, arr, elems, 0);
            }

            jchar out[3] = {0};
            (*env)->GetCharArrayRegion(env, arr, 0, len, out);
            LOGI("    GetCharArrayRegion: %c %c %c",
                 (char)out[0], (char)out[1], (char)out[2]);
            TEST_ASSERT(out[0] == 'A' && out[1] == 'B' && out[2] == 'C',
                        "GetCharArrayRegion contents ['A','B','C']");
        }
    }

    // jshortArray
    {
        LOGI("  [short] jshortArray");
        jsize len = 3;
        jshortArray arr = (*env)->NewShortArray(env, len);
        if (arr) {
            jshort tmp[3] = { 100, 200, 300 };
            (*env)->SetShortArrayRegion(env, arr, 0, len, tmp);

            jboolean isCopy = JNI_FALSE;
            jshort *elems = (*env)->GetShortArrayElements(env, arr, &isCopy);
            if (elems) {
                LOGI("    elems: %d %d %d", elems[0], elems[1], elems[2]);
                TEST_ASSERT(elems[0] == 100 && elems[1] == 200 && elems[2] == 300,
                            "jshortArray contents [100,200,300]");
                (*env)->ReleaseShortArrayElements(env, arr, elems, 0);
            }

            jshort out[3] = {0};
            (*env)->GetShortArrayRegion(env, arr, 0, len, out);
            LOGI("    GetShortArrayRegion: %d %d %d", out[0], out[1], out[2]);
            TEST_ASSERT(out[0] == 100 && out[1] == 200 && out[2] == 300,
                        "GetShortArrayRegion contents [100,200,300]");
        }
    }

    // jfloatArray
    {
        LOGI("  [float] jfloatArray");
        jsize len = 3;
        jfloatArray arr = (*env)->NewFloatArray(env, len);
        if (arr) {
            jfloat tmp[3] = { 1.5f, 2.5f, 3.5f };
            (*env)->SetFloatArrayRegion(env, arr, 0, len, tmp);

            jboolean isCopy = JNI_FALSE;
            jfloat *elems = (*env)->GetFloatArrayElements(env, arr, &isCopy);
            if (elems) {
                LOGI("    elems: %f %f %f",
                     elems[0], elems[1], elems[2]);
                TEST_ASSERT(fabsf(elems[0] - 1.5f) < 0.0001f &&
                            fabsf(elems[1] - 2.5f) < 0.0001f &&
                            fabsf(elems[2] - 3.5f) < 0.0001f,
                            "jfloatArray contents [1.5,2.5,3.5]");
                (*env)->ReleaseFloatArrayElements(env, arr, elems, 0);
            }

            jfloat out[3] = {0.0f};
            (*env)->GetFloatArrayRegion(env, arr, 0, len, out);
            LOGI("    GetFloatArrayRegion: %f %f %f",
                 out[0], out[1], out[2]);
            TEST_ASSERT(fabsf(out[0] - 1.5f) < 0.0001f &&
                        fabsf(out[1] - 2.5f) < 0.0001f &&
                        fabsf(out[2] - 3.5f) < 0.0001f,
                        "GetFloatArrayRegion contents [1.5,2.5,3.5]");
        }
    }

    // jdoubleArray
    {
        LOGI("  [double] jdoubleArray");
        jsize len = 2;
        jdoubleArray arr = (*env)->NewDoubleArray(env, len);
        if (arr) {
            jdouble tmp[2] = { 3.14159, 4.2 };
            (*env)->SetDoubleArrayRegion(env, arr, 0, len, tmp);

            jboolean isCopy = JNI_FALSE;
            jdouble *elems = (*env)->GetDoubleArrayElements(env, arr, &isCopy);
            if (elems) {
                LOGI("    elems: %f %f",
                     elems[0], elems[1]);
                TEST_ASSERT(fabs(elems[0] - 3.14159) < 1e-6 &&
                            fabs(elems[1] - 4.2) < 1e-6,
                            "jdoubleArray contents [3.14159,4.2]");
                (*env)->ReleaseDoubleArrayElements(env, arr, elems, 0);
            }

            jdouble out[2] = {0.0};
            (*env)->GetDoubleArrayRegion(env, arr, 0, len, out);
            LOGI("    GetDoubleArrayRegion: %f %f",
                 out[0], out[1]);
            TEST_ASSERT(fabs(out[0] - 3.14159) < 1e-6 &&
                        fabs(out[1] - 4.2) < 1e-6,
                        "GetDoubleArrayRegion contents [3.14159,4.2]");
        }
    }
}

/* Test C: PrimitiveArrayCritical */

static void test_primitive_array_critical(JNIEnv *env) {
    LOGI("");
    LOGI("=== Array tests: GetPrimitiveArrayCritical / ReleasePrimitiveArrayCritical ===");

    // jintArray
    {
        jsize len = 4;
        jintArray arr = (*env)->NewIntArray(env, len);
        if (arr) {
            jint in[4] = { 1, 2, 3, 4 };
            (*env)->SetIntArrayRegion(env, arr, 0, len, in);

            jboolean isCopy = JNI_FALSE;
            jint *p = (jint *)(*env)->GetPrimitiveArrayCritical(env, arr, &isCopy);
            if (p) {
                LOGI("  jintArray critical: %d %d %d %d", p[0], p[1], p[2], p[3]);
                TEST_ASSERT(p[0] == 1 && p[1] == 2 &&
                            p[2] == 3 && p[3] == 4,
                            "GetPrimitiveArrayCritical jintArray [1,2,3,4]");
                (*env)->ReleasePrimitiveArrayCritical(env, arr, p, 0);
            } else {
                TEST_ASSERT(0, "GetPrimitiveArrayCritical jintArray returned NULL");
            }
        }
    }

    // jdoubleArray
    {
        jsize len = 2;
        jdoubleArray arr = (*env)->NewDoubleArray(env, len);
        if (arr) {
            jdouble in[2] = { 10.0, 20.5 };
            (*env)->SetDoubleArrayRegion(env, arr, 0, len, in);

            jboolean isCopy = JNI_FALSE;
            jdouble *p = (jdouble *)(*env)->GetPrimitiveArrayCritical(env, arr, &isCopy);
            if (p) {
                LOGI("  jdoubleArray critical: %f %f", p[0], p[1]);
                TEST_ASSERT(fabs(p[0] - 10.0) < 1e-6 &&
                            fabs(p[1] - 20.5) < 1e-6,
                            "GetPrimitiveArrayCritical jdoubleArray [10.0,20.5]");
                (*env)->ReleasePrimitiveArrayCritical(env, arr, p, 0);
            } else {
                TEST_ASSERT(0, "GetPrimitiveArrayCritical jdoubleArray returned NULL");
            }
        }
    }
}

/* Test D: Object arrays (NewObjectArray / Get / Set element) */

static void test_object_arrays(JNIEnv *env) {
    LOGI("");
    LOGI("=== Array tests: object arrays ===");

    jclass stringCls = (*env)->FindClass(env, "java/lang/String");
    if (stringCls == NULL) {
        LOGE("FindClass(java/lang/String) failed");
        (*env)->ExceptionClear(env);
        return;
    }

    jsize len = 3;
    jobjectArray arr = (*env)->NewObjectArray(env, len, stringCls, NULL);
    if (arr == NULL) {
        LOGE("NewObjectArray failed");
        (*env)->ExceptionClear(env);
        return;
    }

    jstring s0 = (*env)->NewStringUTF(env, "one");
    jstring s1 = (*env)->NewStringUTF(env, "two");
    jstring s2 = (*env)->NewStringUTF(env, "three");

    (*env)->SetObjectArrayElement(env, arr, 0, s0);
    (*env)->SetObjectArrayElement(env, arr, 1, s1);
    (*env)->SetObjectArrayElement(env, arr, 2, s2);

    jsize len2 = (*env)->GetArrayLength(env, arr);
    LOGI("  object array length = %d", (int)len2);
    TEST_ASSERT(len2 == len, "GetArrayLength for object array");

    for (jsize i = 0; i < len; i++) {
        jobject elem = (*env)->GetObjectArrayElement(env, arr, i);
        if (elem != NULL) {
            const char *cstr = (*env)->GetStringUTFChars(env, (jstring)elem, NULL);
            LOGI("  element[%d] = \"%s\"", (int)i, cstr ? cstr : "<null>");
            if (cstr) {
                (*env)->ReleaseStringUTFChars(env, (jstring)elem, cstr);
            }
        } else {
            LOGE("  element[%d] is NULL", (int)i);
        }
    }
}

JNIEXPORT void JNICALL
Java_com_test_jnie2e_EnvArrayTests_runTests(JNIEnv *env, jclass clazz) {
    (void) clazz;

    tests_passed = 0;
    tests_failed = 0;

    LOGI("========================================");
    LOGI("EnvArrayTests: starting");
    LOGI("========================================");

    LOGI("");
    LOGI(">> Running test_int_and_long_arrays...");
    test_int_and_long_arrays(env);
    LOGI("");
    LOGI(">> Running test_more_primitive_arrays...");
    test_more_primitive_arrays(env);
    LOGI("");
    LOGI(">> Running test_primitive_array_critical...");
    test_primitive_array_critical(env);
    LOGI("");
    LOGI(">> Running test_object_arrays...");
    test_object_arrays(env);

    LOGI("========================================");
    LOGI("EnvArrayTests summary: %d passed, %d failed", tests_passed, tests_failed);
    LOGI("========================================");
}