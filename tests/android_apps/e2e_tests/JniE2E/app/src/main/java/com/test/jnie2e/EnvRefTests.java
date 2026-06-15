package com.test.jnie2e;

public final class EnvRefTests {

    static {
        // Loads libjni_env_refs.so
        System.loadLibrary("jni_env_refs");
    }

    // Native entry:
    // Java_com_test_jnie2e_EnvRefTests_runTests in jni_env_refs.c
    public static native void runTests();

    private EnvRefTests() {
        // No instances
    }
}