// tests/android_apps/e2e_tests/ProcessRuntimeE2E/app/src/main/java/com/test/processruntimee2e/NativeEntry.java
package com.test.processruntimee2e;

public final class NativeEntry {

    static {
        System.loadLibrary("processnative");
    }

    private NativeEntry() {
    }

    public static native void runNativeProcessTests();
}