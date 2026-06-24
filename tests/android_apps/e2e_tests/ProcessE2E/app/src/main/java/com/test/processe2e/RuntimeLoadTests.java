package com.test.processe2e;

import android.util.Log;

// Triggers Runtime.load and Runtime.loadLibrary overloads in runtime.ts.
//
// Note: System.loadLibrary(String) delegates through Runtime.loadLibrary0
// (a package-private method), not through the public Runtime.loadLibrary(String)
// overload that runtime.ts hooks via .overloads.forEach. System.loadLibrary fires
// the dex/load_library.ts hook instead. Runtime.getRuntime().loadLibrary() calls
// the public overload directly and is the correct trigger for runtime.ts.
public class RuntimeLoadTests {

    private static final String TAG = "PROCESS_RUNTIME_E2E";
    private int passed = 0;
    private int failed = 0;

    public void runTests() {
        testRuntimeLoadLibrary();
        testRuntimeLoad();
        Log.i(TAG, "RuntimeLoadTests summary: " + passed + " passed, " + failed + " failed");
    }

    // Runtime.loadLibrary(String) -> hook runtime.load_library
    private void testRuntimeLoadLibrary() {
        try {
            Runtime.getRuntime().loadLibrary("log");
            Log.i(TAG, "Runtime.loadLibrary(\"log\"): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Runtime.loadLibrary failed", t);
            failed++;
        }
    }

    // Runtime.load(String) -> hook runtime.load
    // Tries system paths for liblog.so; first successful path wins.
    private void testRuntimeLoad() {
        String[] candidates = {
                "/system/lib64/liblog.so",
                "/system/lib/liblog.so"
        };
        boolean loaded = false;
        for (String path : candidates) {
            try {
                Runtime.getRuntime().load(path);
                Log.i(TAG, "Runtime.load(\"" + path + "\"): ok");
                passed++;
                loaded = true;
                break;
            } catch (Throwable t) {
                Log.w(TAG, "Runtime.load(" + path + ") failed, trying next");
            }
        }
        if (!loaded) {
            Log.e(TAG, "Runtime.load: all candidate paths failed");
            failed++;
        }
    }
}