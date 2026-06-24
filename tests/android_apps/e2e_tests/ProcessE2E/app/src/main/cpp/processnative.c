#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>

extern char **environ;

#define LOG_TAG "PROCESS_NATIVE"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * Native triggers for hooks in process.ts and nativelibrary.ts:
 *
 *   fork()               -> process.fork.attempt, process.fork.result (parent only)
 *   execve()             -> process.execve.attempt (child, before exec);
 *                           process.execve.result fires only on execve failure -
 *                           on success the child image is replaced and onLeave
 *                           never returns in the child
 *   system()             -> process.system.call, process.system.result
 *   dlopen()             -> native.library.load, native.library.loaded (or load_failed)
 *   android_dlopen_ext() -> may also fire if the dynamic linker routes through it
 *                           internally on API 24+ for app-side dlopen calls
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

/* Test 1: fork() + execve() */
static void test_fork_execve(void) {
    LOGI("");
    LOGI("=== test_fork_execve ===");

    pid_t pid = fork();
    TEST_ASSERT(pid >= 0, "fork() returns >= 0");

    if (pid < 0) {
        LOGE("fork failed: %s", strerror(errno));
        return;
    }

    if (pid == 0) {
        /* child: exec into /system/bin/sh; process image replaced on success */
        char *argv[] = { "/system/bin/sh", "-c", "echo native_execve_child", NULL };
        execve("/system/bin/sh", argv, environ);
        /* execve only returns on failure */
        _exit(1);
    }

    /* parent: wait for child to avoid zombie */
    int status = 0;
    waitpid(pid, &status, 0);
    LOGI("fork child pid=%d exited with status=%d", (int)pid, WEXITSTATUS(status));
    TEST_ASSERT(WIFEXITED(status), "fork child exited normally");
}

/* Test 2: system() */
static void test_system(void) {
    LOGI("");
    LOGI("=== test_system ===");

    int r = system("echo native_system_call");
    LOGI("system() returned %d", r);
    TEST_ASSERT(r == 0, "system() returns 0");
}

/* Test 3: dlopen() */
static void test_dlopen(void) {
    LOGI("");
    LOGI("=== test_dlopen ===");

    /*
     * Load libprocesschild.so by short name - the dynamic linker resolves it
     * from the app's native library directory. On API 24+ namespace isolation
     * restricts cross-library dlopen; within the same app namespace short names
     * are resolvable.
     */
    void *handle = dlopen("libprocesschild.so", RTLD_NOW);
    if (handle == NULL) {
        LOGE("dlopen libprocesschild.so failed: %s", dlerror());
        TEST_ASSERT(0, "dlopen(libprocesschild.so) returns non-NULL");
        return;
    }

    LOGI("dlopen libprocesschild.so succeeded: handle=%p", handle);
    TEST_ASSERT(1, "dlopen(libprocesschild.so) returns non-NULL");

    dlclose(handle);
    TEST_ASSERT(1, "dlclose(libprocesschild.so) ok");
}

JNIEXPORT void JNICALL
Java_com_test_processe2e_NativeEntry_runNativeProcessTests(JNIEnv *env, jclass clazz) {
    (void)clazz;
    (void)env;

    tests_passed = 0;
    tests_failed = 0;

    LOGI("========================================");
    LOGI("ProcessNative: starting");
    LOGI("========================================");

    LOGI("");
    LOGI(">> Running test_fork_execve...");
    test_fork_execve();

    LOGI("");
    LOGI(">> Running test_system...");
    test_system();

    LOGI("");
    LOGI(">> Running test_dlopen...");
    test_dlopen();

    LOGI("========================================");
    LOGI("ProcessNative summary: %d passed, %d failed", tests_passed, tests_failed);
    LOGI("========================================");
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    LOGI("processnative JNI_OnLoad called");
    return JNI_VERSION_1_6;
}