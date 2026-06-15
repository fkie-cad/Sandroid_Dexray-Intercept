package com.test.jnie2e;

public final class EnvCallsTests {

    static {
        // Loads libjni_env_calls.so
        System.loadLibrary("jni_env_calls");
    }

    // Native entry:
    // Java_com_test_jnie2e_EnvCallsTests_runTests in jni_env_calls.c
    public static native void runTests();

    private EnvCallsTests() {
        // No instances
    }
}