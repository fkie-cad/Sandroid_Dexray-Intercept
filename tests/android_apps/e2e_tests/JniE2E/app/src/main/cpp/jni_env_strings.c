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

static void test_utf_string_apis(JNIEnv *env) {
    LOGI("");
    LOGI("=== String tests: UTF-based APIs ===");

    // NewStringUTF + GetStringUTFLength
    jstring s = (*env)->NewStringUTF(env, "HelloUTF");
    if (s == NULL) {
        LOGE("NewStringUTF(\"HelloUTF\") failed");
        (*env)->ExceptionClear(env);
        return;
    }

    jsize utfLen = (*env)->GetStringUTFLength(env, s);
    LOGI("GetStringUTFLength(\"HelloUTF\") = %d", (int)utfLen);

    // GetStringUTFChars / ReleaseStringUTFChars
    const char *cstr = (*env)->GetStringUTFChars(env, s, NULL);
    if (cstr != NULL) {
        LOGI("GetStringUTFChars -> \"%s\"", cstr);
    } else {
        LOGE("GetStringUTFChars returned NULL");
    }

    // GetStringUTFRegion into a buffer
    if (utfLen > 0 && utfLen < 64) {
        char buf[64];
        memset(buf, 0, sizeof(buf));
        (*env)->GetStringUTFRegion(env, s, 0, utfLen, buf); // no null-terminator
        buf[utfLen] = '\0';
        LOGI("GetStringUTFRegion(0,%d) -> \"%s\"", (int)utfLen, buf);
    }

    if (cstr != NULL) {
        (*env)->ReleaseStringUTFChars(env, s, cstr);
    }
}

static void test_jchar_string_apis(JNIEnv *env) {
    LOGI("");
    LOGI("=== String tests: jchar-based APIs ===");

    // NewString from jchar[]
    jchar chars[4] = { 'A', 'B', 'C', 'D' };
    jstring s = (*env)->NewString(env, chars, 4);
    if (s == NULL) {
        LOGE("NewString(jchar[4]) failed");
        (*env)->ExceptionClear(env);
        return;
    }

    // GetStringLength
    jsize len = (*env)->GetStringLength(env, s);
    LOGI("GetStringLength(\"ABCD\") = %d", (int)len);

    // GetStringChars / ReleaseStringChars
    const jchar *p = (*env)->GetStringChars(env, s, NULL);
    if (p != NULL) {
        LOGI("GetStringChars -> jchar values: 0x%04x 0x%04x 0x%04x 0x%04x",
             p[0], p[1], p[2], p[3]);
        (*env)->ReleaseStringChars(env, s, p);
    } else {
        LOGE("GetStringChars returned NULL");
    }

    // GetStringRegion: extract "BC" (indices 1..2)
    if (len >= 3) {
        jchar region[3] = {0};
        (*env)->GetStringRegion(env, s, (jsize)1, (jsize)2, region);
        LOGI("GetStringRegion(1,2) -> jchar: 0x%04x 0x%04x ('%c''%c')",
             region[0], region[1],
             (char)region[0], (char)region[1]);
    }
}

static void test_string_critical(JNIEnv *env) {
    LOGI("");
    LOGI("=== String tests: GetStringCritical/ReleaseStringCritical ===");

    jstring s = (*env)->NewStringUTF(env, "Crit");
    if (s == NULL) {
        LOGE("NewStringUTF(\"Crit\") failed");
        (*env)->ExceptionClear(env);
        return;
    }

    jsize len = (*env)->GetStringLength(env, s);
    LOGI("GetStringLength(\"Crit\") = %d", (int)len);

    jboolean isCopy = JNI_FALSE;
    const jchar *chars = (*env)->GetStringCritical(env, s, &isCopy);
    if (chars == NULL) {
        LOGE("GetStringCritical returned NULL");
        (*env)->ExceptionClear(env);
        return;
    }

    LOGI("GetStringCritical -> jchar values: 0x%04x 0x%04x 0x%04x 0x%04x",
         chars[0], chars[1], chars[2], chars[3]);

    (*env)->ReleaseStringCritical(env, s, chars);
}

JNIEXPORT void JNICALL
Java_com_test_jnie2e_EnvStringTests_runTests(JNIEnv *env, jclass clazz) {
    (void) clazz;

    LOGI("========================================");
    LOGI("EnvStringTests: starting");
    LOGI("========================================");

    test_utf_string_apis(env);
    test_jchar_string_apis(env);
    test_string_critical(env);

    LOGI("========================================");
    LOGI("EnvStringTests: done");
    LOGI("========================================");
}