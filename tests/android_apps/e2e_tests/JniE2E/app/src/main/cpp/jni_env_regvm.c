#include <jni.h>
#include <android/log.h>
#include <pthread.h>
#include <stdlib.h>

#define LOG_TAG "JNI_ENV_REGVM"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * EnvRegistrationVmTests for jni_trace.ts hooks:
 *
 *  RegisterNatives / UnregisterNatives:
 *    - RegisterNatives (in JNI_OnLoad)
 *    - UnregisterNatives (in runNativeTests)
 *
 *  JavaVM methods:
 *    - GetEnv
 *    - AttachCurrentThread
 *    - DetachCurrentThread
 *    - AttachCurrentThreadAsDaemon
 *
 *  NOTE: DestroyJavaVM is intentionally not called.
 */

static JavaVM *g_vm = NULL;
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

/* Simple native for RegistrationTarget.nativeSimple(String) */

static void native_simple(JNIEnv *env, jclass clazz, jstring msg) {
    (void) clazz;
    if (msg != NULL) {
        const char *c = (*env)->GetStringUTFChars(env, msg, NULL);
        LOGI("native_simple called from Java with: \"%s\"", c ? c : "<null>");
        if (c) {
            (*env)->ReleaseStringUTFChars(env, msg, c);
        }
    } else {
        LOGI("native_simple called with NULL msg");
    }
}

/* JNI_OnLoad: store JavaVM and RegisterNatives for RegistrationTarget */

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    g_vm = vm;

    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        LOGE("JNI_OnLoad: GetEnv failed");
        return JNI_ERR;
    }

    jclass clazz = (*env)->FindClass(env, "com/test/jnie2e/RegistrationTarget");
    if (clazz == NULL) {
        LOGE("JNI_OnLoad: FindClass(RegistrationTarget) failed");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return JNI_ERR;
    }

    static const JNINativeMethod methods[] = {
        { "nativeSimple", "(Ljava/lang/String;)V", (void *) native_simple }
    };

    if ((*env)->RegisterNatives(env, clazz, methods,
                                (jint)(sizeof(methods)/sizeof(methods[0]))) != 0) {
        LOGE("JNI_OnLoad: RegisterNatives failed");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return JNI_ERR;
    }

    LOGI("JNI_OnLoad: RegisterNatives successful for RegistrationTarget.nativeSimple");
    return JNI_VERSION_1_6;
}

/* Test 1: UnregisterNatives (and optionally re-register) */

static void test_register_unregister(JNIEnv *env) {
    LOGI("");
    LOGI("=== Reg/VM tests: RegisterNatives / UnregisterNatives ===");

    jclass clazz = (*env)->FindClass(env, "com/test/jnie2e/RegistrationTarget");
    if (clazz == NULL) {
        LOGE("FindClass(RegistrationTarget) failed in test_register_unregister");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return;
    }

    // UnregisterNatives
    jint rc = (*env)->UnregisterNatives(env, clazz);
    TEST_ASSERT(rc == 0, "UnregisterNatives returned JNI_OK");

    // Optional: re-register to prove we can reattach methods (and generate another RegisterNatives event)
    static const JNINativeMethod methods[] = {
        { "nativeSimple", "(Ljava/lang/String;)V", (void *) native_simple }
    };

    rc = (*env)->RegisterNatives(env, clazz, methods,
                                 (jint)(sizeof(methods)/sizeof(methods[0])));
    TEST_ASSERT(rc == 0, "Re-RegisterNatives returned JNI_OK");
}

/* JavaVM: GetEnv on main thread */

static void test_javavm_getenv(JNIEnv *env_main) {
    LOGI("");
    LOGI("=== Reg/VM tests: JavaVM::GetEnv on main thread ===");

    if (g_vm == NULL) {
        LOGE("g_vm is NULL in test_javavm_getenv");
        return;
    }

    JNIEnv *env2 = NULL;
    jint rc = (*g_vm)->GetEnv(g_vm, (void **)&env2, JNI_VERSION_1_6);
    TEST_ASSERT(rc == JNI_OK, "JavaVM::GetEnv returns JNI_OK");
    TEST_ASSERT(env2 == env_main, "JavaVM::GetEnv returns same JNIEnv* as caller");
}

/*
 * JavaVM GetEnv failure paths: verify that an initially NULL output remains
 * NULL for an unsupported JNI version and for an unattached native thread.
 */

typedef struct {
    jint rc;
    JNIEnv *env;
} GetEnvFailureResult;

static void test_javavm_getenv_unsupported_version(void) {
    LOGI("");
    LOGI("=== Reg/VM tests: GetEnv unsupported version ===");

    if (g_vm == NULL) {
        TEST_ASSERT(0, "GetEnv unsupported version: g_vm non-NULL");
        return;
    }

    JNIEnv *env = NULL;
    jint rc = (*g_vm)->GetEnv(g_vm, (void **)&env, (jint)0x7fffffff);

    LOGI("GetEnv unsupported version: rc=%d, env=%p", (int)rc, (void *)env);
    TEST_ASSERT(rc == JNI_EVERSION,
                "GetEnv unsupported version returns JNI_EVERSION");
    TEST_ASSERT(env == NULL,
                "GetEnv unsupported version leaves output NULL");
}

static void *thread_getenv_unattached_fn(void *arg) {
    (void)arg;

    GetEnvFailureResult *result = malloc(sizeof(*result));
    if (result == NULL) {
        return NULL;
    }

    result->env = NULL;
    result->rc = (*g_vm)->GetEnv(
        g_vm, (void **)&result->env, JNI_VERSION_1_6
    );

    /* Deliberately do not attach or call through result->env. */
    return result;
}

static void test_javavm_getenv_unattached_thread(void) {
    LOGI("");
    LOGI("=== Reg/VM tests: GetEnv on unattached thread ===");

    if (g_vm == NULL) {
        TEST_ASSERT(0, "GetEnv unattached thread: g_vm non-NULL");
        return;
    }

    pthread_t thread;
    int err = pthread_create(
        &thread, NULL, thread_getenv_unattached_fn, NULL
    );

    TEST_ASSERT(err == 0, "pthread_create for unattached GetEnv succeeded");
    if (err != 0) {
        return;
    }

    void *thread_result = NULL;
    err = pthread_join(thread, &thread_result);
    TEST_ASSERT(err == 0, "pthread_join for unattached GetEnv succeeded");
    if (err != 0) {
        return;
    }

    GetEnvFailureResult *result = thread_result;
    if (result == NULL) {
        TEST_ASSERT(0, "GetEnv unattached thread result allocation succeeded");
        return;
    }

    LOGI("GetEnv unattached thread: rc=%d, env=%p",
         (int)result->rc, (void *)result->env);
    TEST_ASSERT(result->rc == JNI_EDETACHED,
                "GetEnv unattached thread returns JNI_EDETACHED");
    TEST_ASSERT(result->env == NULL,
                "GetEnv unattached thread leaves output NULL");

    free(result);
}

/* Thread for AttachCurrentThread */

static void *thread_attach_fn(void *arg) {
    (void) arg;

    if (g_vm == NULL) {
        LOGE("thread_attach_fn: g_vm is NULL");
        return NULL;
    }

    JNIEnv *env = NULL;
    jint rc = (*g_vm)->AttachCurrentThread(g_vm, &env, NULL);
    LOGI("thread_attach_fn: AttachCurrentThread rc=%d, env=%p", rc, env);

    if (rc == JNI_OK && env != NULL) {
        // simple JNI call for coverage
        jint version = (*env)->GetVersion(env);
        LOGI("thread_attach_fn: GetVersion=0x%x", version);
    }

    (*g_vm)->DetachCurrentThread(g_vm);
    LOGI("thread_attach_fn: DetachCurrentThread done");
    return NULL;
}

/* Thread for AttachCurrentThreadAsDaemon */

static void *thread_daemon_fn(void *arg) {
    (void) arg;

    if (g_vm == NULL) {
        LOGE("thread_daemon_fn: g_vm is NULL");
        return NULL;
    }

    JNIEnv *env = NULL;
    jint rc = (*g_vm)->AttachCurrentThreadAsDaemon(g_vm, &env, NULL);
    LOGI("thread_daemon_fn: AttachCurrentThreadAsDaemon rc=%d, env=%p", rc, env);

    if (rc == JNI_OK && env != NULL) {
        jint version = (*env)->GetVersion(env);
        LOGI("thread_daemon_fn: GetVersion=0x%x", version);
    }

    (*g_vm)->DetachCurrentThread(g_vm);
    LOGI("thread_daemon_fn: DetachCurrentThread (daemon) done");
    return NULL;
}

/* Test 2: AttachCurrentThread / DetachCurrentThread */

static void test_attach_detach_thread(void) {
    LOGI("");
    LOGI("=== Reg/VM tests: AttachCurrentThread / DetachCurrentThread ===");

    pthread_t t;
    int err = pthread_create(&t, NULL, thread_attach_fn, NULL);
    TEST_ASSERT(err == 0, "pthread_create for AttachCurrentThread succeeded");

    if (err == 0) {
        pthread_join(t, NULL);
    }
}

/* Test 3: AttachCurrentThreadAsDaemon / DetachCurrentThread */

static void test_attach_detach_daemon(void) {
    LOGI("");
    LOGI("=== Reg/VM tests: AttachCurrentThreadAsDaemon / DetachCurrentThread ===");

    pthread_t t;
    int err = pthread_create(&t, NULL, thread_daemon_fn, NULL);
    TEST_ASSERT(err == 0, "pthread_create for AttachCurrentThreadAsDaemon succeeded");

    if (err == 0) {
        pthread_join(t, NULL);
    }
}

/* Native entry: called from EnvRegistrationVmTests.runTests() */

JNIEXPORT void JNICALL
Java_com_test_jnie2e_EnvRegistrationVmTests_runNativeTests(JNIEnv *env, jclass clazz) {
    (void) clazz;

    tests_passed = 0;
    tests_failed = 0;

    LOGI("========================================");
    LOGI("EnvRegistrationVmTests: starting");
    LOGI("========================================");

    if (g_vm == NULL) {
        LOGE("EnvRegistrationVmTests: g_vm is NULL");
        return;
    }

    test_register_unregister(env);
    test_javavm_getenv(env);
    test_javavm_getenv_unsupported_version();
    test_javavm_getenv_unattached_thread();
    test_attach_detach_thread();
    test_attach_detach_daemon();

    LOGI("========================================");
    LOGI("EnvRegistrationVmTests summary: %d passed, %d failed", tests_passed, tests_failed);
    LOGI("========================================");
}