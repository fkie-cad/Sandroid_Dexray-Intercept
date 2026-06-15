package com.test.jnie2e;

public final class EnvStringTests {

    static {
        // Loads libjni_env_strings.so
        System.loadLibrary("jni_env_strings");
    }

    // Native entry:
    // Java_com_test_jnie2e_EnvStringTests_runTests in jni_env_strings.c
    public static native void runTests();

    private EnvStringTests() {
        // No instances
    }
}