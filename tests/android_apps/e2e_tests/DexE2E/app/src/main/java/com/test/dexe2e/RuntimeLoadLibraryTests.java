package com.test.dexe2e;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.util.Log;

import java.io.File;

/**
 * Covers:
 *   load_library.ts -> install_runtime_library_hooks() ->
 *     Runtime.load(String)          - full filesystem path to .so
 *     Runtime.loadLibrary(String)   - bare library name
 *
 * Runtime.load and Runtime.loadLibrary are the instance-method equivalents
 * of System.load / System.loadLibrary. Both are public API on Android.
 * System.load/loadLibrary delegate internally to Runtime, but the hooks are
 * on separate method objects so both sets need independent triggering.
 *
 * Expected events:
 *   library.runtime.load_library   (method: "Runtime.loadLibrary(String)")
 *   library.runtime.load           (method: "Runtime.load(String)")
 */
public class RuntimeLoadLibraryTests {

    private static final String TAG = "DEX_RT_LOADLIB";

    private int passed = 0;
    private int failed = 0;
    private final Context context;

    public RuntimeLoadLibraryTests(Context context) {
        this.context = context;
    }

    private void pass(String name) {
        Log.i(TAG, "  PASS: " + name);
        passed++;
    }

    private void fail(String name, String reason) {
        Log.e(TAG, "  FAIL: " + name + " - " + reason);
        failed++;
    }

    public void runTests() {
        Log.i(TAG, "========================================");
        Log.i(TAG, "RuntimeLoadLibraryTests: starting");
        Log.i(TAG, "========================================");

        test_runtime_load_library();
        test_runtime_load();

        Log.i(TAG, "========================================");
        Log.i(TAG, "RuntimeLoadLibraryTests summary: " + passed + " passed, " + failed + " failed");
        Log.i(TAG, "========================================");
    }

    private void test_runtime_load_library() {
        Log.i(TAG, "");
        Log.i(TAG, "=== Runtime.loadLibrary(String) ===");

        try {
            Runtime.getRuntime().loadLibrary("dexe2e_native");
            pass("Runtime.getRuntime().loadLibrary(\"dexe2e_native\")");
        } catch (Throwable t) {
            fail("Runtime.loadLibrary(\"dexe2e_native\")", t.toString());
        }
    }

    private void test_runtime_load() {
        Log.i(TAG, "");
        Log.i(TAG, "=== Runtime.load(String) ===");

        ApplicationInfo ai = context.getApplicationInfo();
        String libPath = ai.nativeLibraryDir + File.separator + "libdexe2e_native.so";
        Log.i(TAG, "Full library path: " + libPath);

        if (!new File(libPath).exists()) {
            fail("Runtime.load - lib file exists", "not found at " + libPath);
            return;
        }

        try {
            Runtime.getRuntime().load(libPath);
            pass("Runtime.getRuntime().load(\"" + libPath + "\")");
        } catch (Throwable t) {
            fail("Runtime.load(fullPath)", t.toString());
        }
    }
}