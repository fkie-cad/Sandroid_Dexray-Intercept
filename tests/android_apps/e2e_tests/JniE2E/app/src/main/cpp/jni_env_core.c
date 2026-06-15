#include <jni.h>
#include <android/log.h>

#define LOG_TAG "JNI_ENV_CORE"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * Env core tests for jni_trace.ts hooks:
 *
 *  - GetVersion                -> JNIInterceptor.attach("GetVersion", jniEnvCallback)
 *  - FindClass                 -> JNIInterceptor.attach("FindClass", jniEnvCallback)
 *  - GetSuperclass             -> JNIInterceptor.attach("GetSuperclass", jniEnvCallback)
 *  - IsAssignableFrom          -> JNIInterceptor.attach("IsAssignableFrom", jniEnvCallback)
 *  - IsInstanceOf              -> JNIInterceptor.attach("IsInstanceOf", jniEnvCallback)
 *  - FromReflectedMethod       -> JNIInterceptor.attach("FromReflectedMethod", jniEnvCallback)
 *  - FromReflectedField        -> JNIInterceptor.attach("FromReflectedField", jniEnvCallback)
 *  - ToReflectedMethod         -> JNIInterceptor.attach("ToReflectedMethod", jniEnvCallback)
 *  - ToReflectedField          -> JNIInterceptor.attach("ToReflectedField", jniEnvCallback)
 */

JNIEXPORT void JNICALL
Java_com_test_jnie2e_EnvCoreTests_runTests(JNIEnv *env, jclass clazz) {
    (void) clazz;

    LOGI("=== EnvCoreTests: start ===");

    // 1) GetVersion
    jint version = (*env)->GetVersion(env);
    LOGI("GetVersion: 0x%x", version);

    // 2) FindClass for core types
    jclass stringCls = (*env)->FindClass(env, "java/lang/String");
    jclass objectCls = (*env)->FindClass(env, "java/lang/Object");
    jclass systemCls = (*env)->FindClass(env, "java/lang/System");

    if (stringCls == NULL || objectCls == NULL || systemCls == NULL) {
        LOGE("FindClass failed for one of: java/lang/String, java/lang/Object, java/lang/System");
        (*env)->ExceptionClear(env);
        LOGI("=== EnvCoreTests: abort (FindClass failure) ===");
        return;
    }

    // 3) GetSuperclass
    jclass superOfString = (*env)->GetSuperclass(env, stringCls);
    LOGI("GetSuperclass(String) -> %p", superOfString);

    // 4) IsAssignableFrom (String vs Object)
    //    According to JNI spec: IsAssignableFrom(env, c1, c2) == c2.isAssignableFrom(c1)
    jboolean stringToObject = (*env)->IsAssignableFrom(env, stringCls, objectCls);
    jboolean objectToString = (*env)->IsAssignableFrom(env, objectCls, stringCls);
    LOGI("IsAssignableFrom(String, Object)  -> %s", stringToObject ? "true" : "false");
    LOGI("IsAssignableFrom(Object, String)  -> %s", objectToString ? "true" : "false");

    // 5) IsInstanceOf
    jstring s = (*env)->NewStringUTF(env, "core");
    if (s != NULL) {
        jboolean instString = (*env)->IsInstanceOf(env, s, stringCls);
        jboolean instObject = (*env)->IsInstanceOf(env, s, objectCls);
        LOGI("IsInstanceOf(jstring, String) -> %s", instString ? "true" : "false");
        LOGI("IsInstanceOf(jstring, Object) -> %s", instObject ? "true" : "false");
    } else {
        LOGE("NewStringUTF(\"core\") returned NULL");
    }

    // 6) FromReflectedMethod / ToReflectedMethod
    //    Use String.length() as the target method.
    jmethodID lengthMid = (*env)->GetMethodID(env, stringCls, "length", "()I");
    if (lengthMid != NULL) {
        // ToReflectedMethod: get java.lang.reflect.Method object from jmethodID
        jobject reflectedMethod = (*env)->ToReflectedMethod(env, stringCls, lengthMid, JNI_FALSE);
        LOGI("ToReflectedMethod(String.length) -> %p", reflectedMethod);

        // FromReflectedMethod: back to jmethodID from Method
        if (reflectedMethod != NULL) {
            jmethodID lengthMid2 = (*env)->FromReflectedMethod(env, reflectedMethod);
            LOGI("FromReflectedMethod(reflected length) -> %p", lengthMid2);
        }
    } else {
        LOGE("GetMethodID(String.length) failed");
        (*env)->ExceptionClear(env);
    }

    // 7) FromReflectedField / ToReflectedField
    //    Use System.out (static field) as the target field.
    jfieldID outFieldId = (*env)->GetStaticFieldID(
            env,
            systemCls,
            "out",
            "Ljava/io/PrintStream;"
    );
    if (outFieldId != NULL) {
        // ToReflectedField: get java.lang.reflect.Field from jfieldID (static)
        jobject reflectedField = (*env)->ToReflectedField(env, systemCls, outFieldId, JNI_TRUE);
        LOGI("ToReflectedField(System.out) -> %p", reflectedField);

        // FromReflectedField: back to jfieldID from Field
        if (reflectedField != NULL) {
            jfieldID outFieldId2 = (*env)->FromReflectedField(env, reflectedField);
            LOGI("FromReflectedField(reflected System.out) -> %p", outFieldId2);
        }
    } else {
        LOGE("GetStaticFieldID(System.out) failed");
        (*env)->ExceptionClear(env);
    }

    LOGI("=== EnvCoreTests: done ===");
}