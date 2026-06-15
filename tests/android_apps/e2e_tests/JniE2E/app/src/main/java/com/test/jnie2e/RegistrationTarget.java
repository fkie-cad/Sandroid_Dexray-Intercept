package com.test.jnie2e;

/**
 * Class used by EnvRegistrationVmTests for RegisterNatives / UnregisterNatives.
 * The native implementation is registered in JNI_OnLoad of libjni_env_regvm.so.
 */
public class RegistrationTarget {

    // Registered in JNI_OnLoad via RegisterNatives
    public static native void nativeSimple(String msg);
}