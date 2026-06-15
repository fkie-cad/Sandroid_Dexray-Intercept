package com.test.jnie2e;

public final class EnvExceptionTests {

    static {
        // Loads libjni_env_exceptions.so
        System.loadLibrary("jni_env_exceptions");
    }

    // Native entry:
    // Java_com_test_jnie2e_EnvExceptionTests_runTests in jni_env_exceptions.c
    public static native void runTests();

    private EnvExceptionTests() {
        // No instances
    }
}