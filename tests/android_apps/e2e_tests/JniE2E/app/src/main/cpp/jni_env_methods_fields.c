#include <jni.h>
#include <android/log.h>

#define LOG_TAG "JNI_ENV_FIELDS"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * EnvMethodsFieldsTests for jni_trace.ts hooks:
 *
 *  Instance-related:
 *    - GetObjectClass              -> JNIInterceptor.attach("GetObjectClass", jniEnvCallback)
 *    - GetFieldID                  -> ...("GetFieldID", jniEnvCallback)
 *    - GetObjectField              -> ...("GetObjectField", jniEnvCallback)
 *    - GetBooleanField             -> ...("GetBooleanField", jniEnvCallback)
 *    - GetByteField                -> ...("GetByteField", jniEnvCallback)
 *    - GetCharField                -> ...("GetCharField", jniEnvCallback)
 *    - GetShortField               -> ...("GetShortField", jniEnvCallback)
 *    - GetIntField                 -> ...("GetIntField", jniEnvCallback)
 *    - GetLongField                -> ...("GetLongField", jniEnvCallback)
 *    - GetFloatField               -> ...("GetFloatField", jniEnvCallback)
 *    - GetDoubleField              -> ...("GetDoubleField", jniEnvCallback)
 *    - SetObjectField              -> ...("SetObjectField", jniEnvCallback)
 *    - SetBooleanField             -> ...("SetBooleanField", jniEnvCallback)
 *    - SetByteField                -> ...("SetByteField", jniEnvCallback)
 *    - SetCharField                -> ...("SetCharField", jniEnvCallback)
 *    - SetShortField               -> ...("SetShortField", jniEnvCallback)
 *    - SetIntField                 -> ...("SetIntField", jniEnvCallback)
 *    - SetLongField                -> ...("SetLongField", jniEnvCallback)
 *    - SetFloatField               -> ...("SetFloatField", jniEnvCallback)
 *    - SetDoubleField              -> ...("SetDoubleField", jniEnvCallback)
 *
 *  Static-related:
 *    - GetStaticFieldID            -> ...("GetStaticFieldID", jniEnvCallback)
 *    - GetStaticObjectField        -> ...("GetStaticObjectField", jniEnvCallback)
 *    - GetStaticBooleanField       -> ...("GetStaticBooleanField", jniEnvCallback)
 *    - GetStaticByteField          -> ...("GetStaticByteField", jniEnvCallback)
 *    - GetStaticCharField          -> ...("GetStaticCharField", jniEnvCallback)
 *    - GetStaticShortField         -> ...("GetStaticShortField", jniEnvCallback)
 *    - GetStaticIntField           -> ...("GetStaticIntField", jniEnvCallback)
 *    - GetStaticLongField          -> ...("GetStaticLongField", jniEnvCallback)
 *    - GetStaticFloatField         -> ...("GetStaticFloatField", jniEnvCallback)
 *    - GetStaticDoubleField        -> ...("GetStaticDoubleField", jniEnvCallback)
 *    - SetStaticObjectField        -> ...("SetStaticObjectField", jniEnvCallback)
 *    - SetStaticBooleanField       -> ...("SetStaticBooleanField", jniEnvCallback)
 *    - SetStaticByteField          -> ...("SetStaticByteField", jniEnvCallback)
 *    - SetStaticCharField          -> ...("SetStaticCharField", jniEnvCallback)
 *    - SetStaticShortField         -> ...("SetStaticShortField", jniEnvCallback)
 *    - SetStaticIntField           -> ...("SetStaticIntField", jniEnvCallback)
 *    - SetStaticLongField          -> ...("SetStaticLongField", jniEnvCallback)
 *    - SetStaticFloatField         -> ...("SetStaticFloatField", jniEnvCallback)
 *    - SetStaticDoubleField        -> ...("SetStaticDoubleField", jniEnvCallback)
 */

JNIEXPORT void JNICALL
Java_com_test_jnie2e_EnvMethodsFieldsTests_runTests(JNIEnv *env, jclass clazz) {
    (void) clazz;

    LOGI("=== EnvMethodsFieldsTests: start ===");

    // 1) Find FieldTarget class
    jclass fieldTargetCls = (*env)->FindClass(env, "com/test/jnie2e/FieldTarget");
    if (fieldTargetCls == NULL) {
        LOGE("FindClass(com/test/jnie2e/FieldTarget) failed");
        (*env)->ExceptionClear(env);
        LOGI("=== EnvMethodsFieldsTests: abort (no FieldTarget) ===");
        return;
    }

    // 2) Get default constructor and create instance
    jmethodID ctor = (*env)->GetMethodID(env, fieldTargetCls, "<init>", "()V");
    if (ctor == NULL) {
        LOGE("GetMethodID(<init>) failed");
        (*env)->ExceptionClear(env);
        LOGI("=== EnvMethodsFieldsTests: abort (no ctor) ===");
        return;
    }

    jobject target = (*env)->NewObject(env, fieldTargetCls, ctor);
    if (target == NULL) {
        LOGE("NewObject(FieldTarget) failed");
        (*env)->ExceptionClear(env);
        LOGI("=== EnvMethodsFieldsTests: abort (no instance) ===");
        return;
    }

    // 3) GetObjectClass (instance-level reflection)
    jclass clsFromObj = (*env)->GetObjectClass(env, target);
    LOGI("GetObjectClass(FieldTarget instance) -> %p", clsFromObj);

    // ---------------------------------------------------------------------
    // Instance fields: GetFieldID + Get*/Set*Field
    // ---------------------------------------------------------------------
    LOGI("--- Instance fields ---");

    jfieldID fidInt = (*env)->GetFieldID(env, fieldTargetCls, "intField", "I");
    jfieldID fidLong = (*env)->GetFieldID(env, fieldTargetCls, "longField", "J");
    jfieldID fidBool = (*env)->GetFieldID(env, fieldTargetCls, "boolField", "Z");
    jfieldID fidByte = (*env)->GetFieldID(env, fieldTargetCls, "byteField", "B");
    jfieldID fidShort = (*env)->GetFieldID(env, fieldTargetCls, "shortField", "S");
    jfieldID fidChar = (*env)->GetFieldID(env, fieldTargetCls, "charField", "C");
    jfieldID fidFloat = (*env)->GetFieldID(env, fieldTargetCls, "floatField", "F");
    jfieldID fidDouble = (*env)->GetFieldID(env, fieldTargetCls, "doubleField", "D");
    jfieldID fidObj = (*env)->GetFieldID(env, fieldTargetCls, "objectField",
                                         "Ljava/lang/String;");

    if (fidInt == NULL || fidLong == NULL || fidBool == NULL || fidByte == NULL ||
        fidShort == NULL || fidChar == NULL || fidFloat == NULL || fidDouble == NULL ||
        fidObj == NULL) {
        LOGE("GetFieldID failed for one or more instance fields");
        (*env)->ExceptionClear(env);
    } else {
        // Set*Field
        (*env)->SetIntField(env, target, fidInt, (jint) 42);
        (*env)->SetLongField(env, target, fidLong, (jlong) 123456789L);
        (*env)->SetBooleanField(env, target, fidBool, JNI_TRUE);
        (*env)->SetByteField(env, target, fidByte, (jbyte) 7);
        (*env)->SetShortField(env, target, fidShort, (jshort) 32000);
        (*env)->SetCharField(env, target, fidChar, (jchar) 'Z');
        (*env)->SetFloatField(env, target, fidFloat, (jfloat) 3.14f);
        (*env)->SetDoubleField(env, target, fidDouble, (jdouble) 2.71828);

        jstring js = (*env)->NewStringUTF(env, "instance-object");
        (*env)->SetObjectField(env, target, fidObj, js);

        // Get*Field
        jint intVal = (*env)->GetIntField(env, target, fidInt);
        jlong longVal = (*env)->GetLongField(env, target, fidLong);
        jboolean boolVal = (*env)->GetBooleanField(env, target, fidBool);
        jbyte byteVal = (*env)->GetByteField(env, target, fidByte);
        jshort shortVal = (*env)->GetShortField(env, target, fidShort);
        jchar charVal = (*env)->GetCharField(env, target, fidChar);
        jfloat floatVal = (*env)->GetFloatField(env, target, fidFloat);
        jdouble doubleVal = (*env)->GetDoubleField(env, target, fidDouble);
        jobject objVal = (*env)->GetObjectField(env, target, fidObj);

        LOGI("Instance intField = %d", (int) intVal);
        LOGI("Instance longField = %lld", (long long) longVal);
        LOGI("Instance boolField = %s", boolVal ? "true" : "false");
        LOGI("Instance byteField = %d", (int) byteVal);
        LOGI("Instance shortField = %d", (int) shortVal);
        LOGI("Instance charField = '%c'", (char) charVal);
        LOGI("Instance floatField = %f", floatVal);
        LOGI("Instance doubleField = %f", doubleVal);

        if (objVal != NULL) {
            const char *cstr = (*env)->GetStringUTFChars(env, (jstring) objVal, NULL);
            LOGI("Instance objectField = \"%s\"", cstr ? cstr : "<null>");
            if (cstr) {
                (*env)->ReleaseStringUTFChars(env, (jstring) objVal, cstr);
            }
        }
    }

    // ---------------------------------------------------------------------
    // Static fields: GetStaticFieldID + GetStatic*/SetStatic*Field
    // ---------------------------------------------------------------------
    LOGI("--- Static fields ---");

    jfieldID sfidInt    = (*env)->GetStaticFieldID(env, fieldTargetCls,
                                                   "staticIntField", "I");
    jfieldID sfidLong   = (*env)->GetStaticFieldID(env, fieldTargetCls,
                                                   "staticLongField", "J");
    jfieldID sfidBool   = (*env)->GetStaticFieldID(env, fieldTargetCls,
                                                   "staticBoolField", "Z");
    jfieldID sfidByte   = (*env)->GetStaticFieldID(env, fieldTargetCls,
                                                   "staticByteField", "B");
    jfieldID sfidShort  = (*env)->GetStaticFieldID(env, fieldTargetCls,
                                                   "staticShortField", "S");
    jfieldID sfidChar   = (*env)->GetStaticFieldID(env, fieldTargetCls,
                                                   "staticCharField", "C");
    jfieldID sfidFloat  = (*env)->GetStaticFieldID(env, fieldTargetCls,
                                                   "staticFloatField", "F");
    jfieldID sfidDouble = (*env)->GetStaticFieldID(env, fieldTargetCls,
                                                   "staticDoubleField", "D");
    jfieldID sfidObj    = (*env)->GetStaticFieldID(env, fieldTargetCls,
                                                   "staticObjectField",
                                                   "Ljava/lang/String;");

    if (sfidInt == NULL || sfidLong == NULL || sfidBool == NULL || sfidByte == NULL ||
        sfidShort == NULL || sfidChar == NULL || sfidFloat == NULL || sfidDouble == NULL ||
        sfidObj == NULL) {
        LOGE("GetStaticFieldID failed for one or more static fields");
        (*env)->ExceptionClear(env);
    } else {
        // SetStatic*Field
        (*env)->SetStaticIntField(env, fieldTargetCls, sfidInt, (jint) 100);
        (*env)->SetStaticLongField(env, fieldTargetCls, sfidLong, (jlong) 987654321L);
        (*env)->SetStaticBooleanField(env, fieldTargetCls, sfidBool, JNI_FALSE);
        (*env)->SetStaticByteField(env, fieldTargetCls, sfidByte, (jbyte) -5);
        (*env)->SetStaticShortField(env, fieldTargetCls, sfidShort, (jshort) -1234);
        (*env)->SetStaticCharField(env, fieldTargetCls, sfidChar, (jchar) 'X');
        (*env)->SetStaticFloatField(env, fieldTargetCls, sfidFloat, (jfloat) 1.25f);
        (*env)->SetStaticDoubleField(env, fieldTargetCls, sfidDouble, (jdouble) 9.99);

        jstring jsStatic = (*env)->NewStringUTF(env, "static-object");
        (*env)->SetStaticObjectField(env, fieldTargetCls, sfidObj, jsStatic);

        // GetStatic*Field
        jint sint = (*env)->GetStaticIntField(env, fieldTargetCls, sfidInt);
        jlong slong = (*env)->GetStaticLongField(env, fieldTargetCls, sfidLong);
        jboolean sbool = (*env)->GetStaticBooleanField(env, fieldTargetCls, sfidBool);
        jbyte sbyte = (*env)->GetStaticByteField(env, fieldTargetCls, sfidByte);
        jshort sshort = (*env)->GetStaticShortField(env, fieldTargetCls, sfidShort);
        jchar schar = (*env)->GetStaticCharField(env, fieldTargetCls, sfidChar);
        jfloat sfloat = (*env)->GetStaticFloatField(env, fieldTargetCls, sfidFloat);
        jdouble sdouble = (*env)->GetStaticDoubleField(env, fieldTargetCls, sfidDouble);
        jobject sobj = (*env)->GetStaticObjectField(env, fieldTargetCls, sfidObj);

        LOGI("Static staticIntField = %d", (int) sint);
        LOGI("Static staticLongField = %lld", (long long) slong);
        LOGI("Static staticBoolField = %s", sbool ? "true" : "false");
        LOGI("Static staticByteField = %d", (int) sbyte);
        LOGI("Static staticShortField = %d", (int) sshort);
        LOGI("Static staticCharField = '%c'", (char) schar);
        LOGI("Static staticFloatField = %f", sfloat);
        LOGI("Static staticDoubleField = %f", sdouble);

        if (sobj != NULL) {
            const char *cstr = (*env)->GetStringUTFChars(env, (jstring) sobj, NULL);
            LOGI("Static staticObjectField = \"%s\"", cstr ? cstr : "<null>");
            if (cstr) {
                (*env)->ReleaseStringUTFChars(env, (jstring) sobj, cstr);
            }
        }
    }

    LOGI("=== EnvMethodsFieldsTests: done ===");
}