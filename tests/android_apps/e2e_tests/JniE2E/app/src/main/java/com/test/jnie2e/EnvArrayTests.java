package com.test.jnie2e;

public final class EnvArrayTests {

    static {
        // Loads libjni_env_arrays.so
        System.loadLibrary("jni_env_arrays");
    }

    // Native entry:
    // Java_com_test_jnie2e_EnvArrayTests_runTests in jni_env_arrays.c
    public static native void runTests();

    private EnvArrayTests() {
        // No instances
    }
}