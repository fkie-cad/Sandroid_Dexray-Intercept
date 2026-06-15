package com.test.jnie2e;

public final class EnvMethodsFieldsTests {

    static {
        // Loads libjni_env_methods_fields.so
        System.loadLibrary("jni_env_methods_fields");
    }

    // Native entry:
    // Java_com_test_jnie2e_EnvMethodsFieldsTests_runTests in jni_env_methods_fields.c
    public static native void runTests();

    private EnvMethodsFieldsTests() {
        // No instances
    }
}