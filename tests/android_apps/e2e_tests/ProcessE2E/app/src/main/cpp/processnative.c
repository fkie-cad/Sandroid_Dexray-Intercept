// tests/android_apps/e2e_tests/ProcessE2E/app/src/main/cpp/processnative.c
#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <dlfcn.h>

extern char **environ;

#define LOG_TAG "PROCESS_NATIVE"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static void call_fork_execve(void) {
    pid_t pid = fork();
    if (pid < 0) {
        LOGE("fork failed");
        return;
    }
    if (pid == 0) {
        char *argv[] = { "/system/bin/sh", "-c", "echo native_execve", NULL };
        execve("/system/bin/sh", argv, environ);
        _exit(1);
    }
}

static void call_system(void) {
    int r = system("echo native_system");
    LOGI("system() returned %d", r);
}

static void call_dlopen_child(void) {
    void *handle = dlopen("libprocesschild.so", RTLD_NOW);
    if (handle == NULL) {
        LOGE("dlopen libprocesschild.so failed");
        return;
    }
    dlclose(handle);
}

JNIEXPORT void JNICALL
Java_com_test_processe2e_NativeEntry_runNativeProcessTests(JNIEnv *env, jclass clazz) {
    LOGI("runNativeProcessTests: start");
    call_fork_execve();
    call_system();
    call_dlopen_child();
    LOGI("runNativeProcessTests: done");
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGI("processnative JNI_OnLoad called");
    return JNI_VERSION_1_6;
}