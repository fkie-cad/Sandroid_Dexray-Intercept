package com.test.jnie2e;

public final class EnvCoreTests {

    static {
        // Loads libjni_env_core.so
        System.loadLibrary("jni_env_core");
    }

    // Native entry:
    // Java_com_test_jnie2e_EnvCoreTests_runTests in jni_env_core.c
    public static native void runTests();

    private EnvCoreTests() {
        // No instances
    }
}