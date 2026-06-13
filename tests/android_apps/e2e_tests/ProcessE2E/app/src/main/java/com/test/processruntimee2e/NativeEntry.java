// tests/android_apps/e2e_tests/ProcessE2E/app/src/main/java/com/test/processe2e/NativeEntry.java
package com.test.processe2e;

public final class NativeEntry {

    static {
        System.loadLibrary("processnative");
    }

    private NativeEntry() {
    }

    public static native void runNativeProcessTests();
}