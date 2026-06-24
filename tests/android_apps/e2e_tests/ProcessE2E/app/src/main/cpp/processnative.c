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
 *   execve() - success   -> process.execve.attempt (child, before exec);
 *                           process.execve.result does NOT fire on success -
 *                           the child image is replaced and onLeave never returns
 *   execve() - failure   -> process.execve.attempt + process.execve.result
 *                           (onLeave fires only when execve returns, i.e. on error)
 *   system()             -> process.system.call, process.system.result
 *   dlopen() - success   -> native.library.load, native.library.loaded
 *   dlopen() - failure   -> native.library.load, native.library.load_failed
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

/* Test 1: fork() + execve() - success path */
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

/* Test 3: dlopen() - success path and failure path */
static void test_dlopen(void) {
    LOGI("");
    LOGI("=== test_dlopen ===");

    /*
     * Success path: load libprocesschild.so by short name.
     * The dynamic linker resolves it from the app's native library directory.
     * On API 24+ namespace isolation restricts cross-library dlopen;
     * within the same app namespace short names are resolvable.
     * Triggers: native.library.load + native.library.loaded
     */
    void *handle = dlopen("libprocesschild.so", RTLD_NOW);
    if (handle == NULL) {
        LOGE("dlopen libprocesschild.so failed: %s", dlerror());
        TEST_ASSERT(0, "dlopen(libprocesschild.so) returns non-NULL");
    } else {
        LOGI("dlopen libprocesschild.so succeeded: handle=%p", handle);
        TEST_ASSERT(1, "dlopen(libprocesschild.so) returns non-NULL");
        dlclose(handle);
        TEST_ASSERT(1, "dlclose(libprocesschild.so) ok");
    }

    /*
     * Failure path: intentionally load a non-existent library.
     * Triggers: native.library.load + native.library.load_failed
     */
    void *bad_handle = dlopen("libdoesnotexist_e2e.so", RTLD_NOW);
    LOGI("dlopen(non-existent) returned %p (expect NULL)", bad_handle);
    TEST_ASSERT(bad_handle == NULL, "dlopen(non-existent) returns NULL (load_failed trigger)");
    if (bad_handle != NULL) dlclose(bad_handle);
}

/* Test 4: execve() - failure path */
static void test_execve_fail(void) {
    LOGI("");
    LOGI("=== test_execve_fail ===");

    /*
     * Trigger process.execve.result (failure path).
     * execve onLeave only fires when execve returns - i.e. only on failure.
     * On success the process image is replaced and onLeave never runs in the child.
     * Using a path that does not exist guarantees execve returns -1 in the caller.
     */
    char *argv[] = { "/no/such/binary/e2e", NULL };
    int r = execve("/no/such/binary/e2e", argv, NULL);
    LOGI("execve of non-existent binary returned %d errno=%d (expect -1)", r, errno);
    TEST_ASSERT(r == -1, "execve of non-existent binary returns -1");
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

    /* test_fork_execve disabled during hooked runs: fork() in a Frida-instrumented
     * process causes the child to inherit Frida's internal threads in an inconsistent
     * state; waitpid() in the parent then hangs indefinitely. Trigger confirmed
     * working in baseline. Hook-side fix required in process.ts before re-enabling. */
#ifdef ENABLE_FORK_TEST
    LOGI("");
    LOGI(">> Running test_fork_execve...");
    test_fork_execve();
#else
    LOGI("");
    LOGI(">> Skipping test_fork_execve (disabled for hooked runs - see comment)");
#endif

    LOGI("");
    LOGI(">> Running test_system...");
    test_system();

    LOGI("");
    LOGI(">> Running test_dlopen...");
    test_dlopen();

    LOGI("");
    LOGI(">> Running test_execve_fail...");
    test_execve_fail();

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