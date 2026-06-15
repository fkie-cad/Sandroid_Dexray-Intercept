package com.test.jnie2e;

import android.util.Log;

public final class EnvRegistrationVmTests {

    private static final String TAG = "JNI_ENV_REGVM_JAVA";

    static {
        // Loads libjni_env_regvm.so
        System.loadLibrary("jni_env_regvm");
    }

    // Native entry:
    // Java_com_test_jnie2e_EnvRegistrationVmTests_runNativeTests in jni_env_regvm.c
    public static native void runNativeTests();

    /**
     * Java-side entry used by MainActivity:
     *  - Calls a method registered via RegisterNatives (nativeSimple)
     *  - Then runs native tests for RegisterNatives/UnregisterNatives and JavaVM methods.
     */
    public static void runTests() {
        try {
            // 1) Call the registered native method from Java
            //    -> jni_trace.ts: RegisterNatives event (in JNI_OnLoad)
            //       CallStaticObjectMethod / etc. are not needed; just ensure the native works.
            RegistrationTarget.nativeSimple("from Java");
            Log.i(TAG, "RegistrationTarget.nativeSimple(\"from Java\") completed");
        } catch (Throwable t) {
            Log.e(TAG, "Error calling RegistrationTarget.nativeSimple", t);
        }

        // 2) Run native VM / registration tests (RegisterNatives, UnregisterNatives, JavaVM)
        runNativeTests();
    }

    private EnvRegistrationVmTests() {
        // No instances
    }
}