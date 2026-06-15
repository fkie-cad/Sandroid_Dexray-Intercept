#include <jni.h>
#include <android/log.h>
#include <string.h>

#define LOG_TAG "JNI_ENV_STRINGS"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * EnvStringTests for jni_trace.ts hooks:
 *
 *  UTF-based:
 *    - NewStringUTF            -> JNIInterceptor.attach("NewStringUTF", jniEnvCallback)
 *    - GetStringUTFLength      -> ...("GetStringUTFLength", jniEnvCallback)
 *    - GetStringUTFChars       -> ...("GetStringUTFChars", jniEnvCallback)
 *    - ReleaseStringUTFChars   -> ...("ReleaseStringUTFChars", jniEnvCallback)
 *    - GetStringUTFRegion      -> ...("GetStringUTFRegion", jniEnvCallback)
 *
 *  jchar-based:
 *    - NewString               -> ...("NewString", jniEnvCallback)
 *    - GetStringLength         -> ...("GetStringLength", jniEnvCallback)
 *    - GetStringChars          -> ...("GetStringChars", jniEnvCallback)
 *    - ReleaseStringChars      -> ...("ReleaseStringChars", jniEnvCallback)
 *    - GetStringRegion         -> ...("GetStringRegion", jniEnvCallback)
 *
 *  Critical:
 *    - GetStringCritical       -> ...("GetStringCritical", jniEnvCallback)
 *    - ReleaseStringCritical   -> ...("ReleaseStringCritical", jniEnvCallback)
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

static void test_utf_string_apis(JNIEnv *env) {
    LOGI("");
    LOGI("=== String tests: UTF-based APIs ===");

    jstring s = (*env)->NewStringUTF(env, "HelloUTF");
    if (s == NULL) {
        LOGE("NewStringUTF(\"HelloUTF\") failed");
        (*env)->ExceptionClear(env);
        TEST_ASSERT(0, "NewStringUTF(\"HelloUTF\")");
        return;
    }

    jsize utfLen = (*env)->GetStringUTFLength(env, s);
    LOGI("GetStringUTFLength(\"HelloUTF\") = %d", (int)utfLen);
    TEST_ASSERT(utfLen == 8, "GetStringUTFLength(\"HelloUTF\") == 8");

    const char *cstr = (*env)->GetStringUTFChars(env, s, NULL);
    if (cstr != NULL) {
        LOGI("GetStringUTFChars -> \"%s\"", cstr);
        TEST_ASSERT(strcmp(cstr, "HelloUTF") == 0,
                    "GetStringUTFChars(\"HelloUTF\") returns \"HelloUTF\"");
    } else {
        LOGE("GetStringUTFChars returned NULL");
        TEST_ASSERT(0, "GetStringUTFChars(\"HelloUTF\") non-NULL");
    }

    if (utfLen > 0 && utfLen < 64) {
        char buf[64];
        memset(buf, 0, sizeof(buf));
        (*env)->GetStringUTFRegion(env, s, 0, utfLen, buf);
        buf[utfLen] = '\0';
        LOGI("GetStringUTFRegion(0,%d) -> \"%s\"", (int)utfLen, buf);
        TEST_ASSERT(strcmp(buf, "HelloUTF") == 0,
                    "GetStringUTFRegion matches \"HelloUTF\"");
    }

    if (cstr != NULL) {
        (*env)->ReleaseStringUTFChars(env, s, cstr);
    }
}

static void test_jchar_string_apis(JNIEnv *env) {
    LOGI("");
    LOGI("=== String tests: jchar-based APIs ===");

    jchar chars[4] = { 'A', 'B', 'C', 'D' };
    jstring s = (*env)->NewString(env, chars, 4);
    if (s == NULL) {
        LOGE("NewString(jchar[4]) failed");
        (*env)->ExceptionClear(env);
        TEST_ASSERT(0, "NewString(\"ABCD\")");
        return;
    }

    jsize len = (*env)->GetStringLength(env, s);
    LOGI("GetStringLength(\"ABCD\") = %d", (int)len);
    TEST_ASSERT(len == 4, "GetStringLength(\"ABCD\") == 4");

    const jchar *p = (*env)->GetStringChars(env, s, NULL);
    if (p != NULL) {
        LOGI("GetStringChars -> jchar values: 0x%04x 0x%04x 0x%04x 0x%04x",
             p[0], p[1], p[2], p[3]);
        TEST_ASSERT(p[0] == 'A' &&
                    p[1] == 'B' &&
                    p[2] == 'C' &&
                    p[3] == 'D',
                    "GetStringChars(\"ABCD\") returns ['A','B','C','D']");
        (*env)->ReleaseStringChars(env, s, p);
    } else {
        LOGE("GetStringChars returned NULL");
        TEST_ASSERT(0, "GetStringChars(\"ABCD\") non-NULL");
    }

    if (len >= 3) {
        jchar region[3] = {0};
        (*env)->GetStringRegion(env, s, (jsize)1, (jsize)2, region);
        LOGI("GetStringRegion(1,2) -> jchar: 0x%04x 0x%04x ('%c''%c')",
             region[0], region[1],
             (char)region[0], (char)region[1]);
        TEST_ASSERT(region[0] == 'B' &&
                    region[1] == 'C',
                    "GetStringRegion(\"ABCD\",1,2) == ['B','C']");
    }
}

static void test_string_critical(JNIEnv *env) {
    LOGI("");
    LOGI("=== String tests: GetStringCritical/ReleaseStringCritical ===");

    jstring s = (*env)->NewStringUTF(env, "Crit");
    if (s == NULL) {
        LOGE("NewStringUTF(\"Crit\") failed");
        (*env)->ExceptionClear(env);
        TEST_ASSERT(0, "NewStringUTF(\"Crit\")");
        return;
    }

    jsize len = (*env)->GetStringLength(env, s);
    LOGI("GetStringLength(\"Crit\") = %d", (int)len);
    TEST_ASSERT(len == 4, "GetStringLength(\"Crit\") == 4");

    jboolean isCopy = JNI_FALSE;
    const jchar *chars = (*env)->GetStringCritical(env, s, &isCopy);
    if (chars == NULL) {
        LOGE("GetStringCritical returned NULL");
        (*env)->ExceptionClear(env);
        TEST_ASSERT(0, "GetStringCritical(\"Crit\") non-NULL");
        return;
    }

    LOGI("GetStringCritical -> jchar values: 0x%04x 0x%04x 0x%04x 0x%04x",
         chars[0], chars[1], chars[2], chars[3]);
    TEST_ASSERT(chars[0] == 'C' &&
                chars[1] == 'r' &&
                chars[2] == 'i' &&
                chars[3] == 't',
                "GetStringCritical(\"Crit\") returns ['C','r','i','t']");

    (*env)->ReleaseStringCritical(env, s, chars);
}

JNIEXPORT void JNICALL
Java_com_test_jnie2e_EnvStringTests_runTests(JNIEnv *env, jclass clazz) {
    (void) clazz;

    tests_passed = 0;
    tests_failed = 0;

    LOGI("========================================");
    LOGI("EnvStringTests: starting");
    LOGI("========================================");

    test_utf_string_apis(env);
    test_jchar_string_apis(env);
    test_string_critical(env);

    LOGI("========================================");
    LOGI("EnvStringTests summary: %d passed, %d failed", tests_passed, tests_failed);
    LOGI("========================================");
}