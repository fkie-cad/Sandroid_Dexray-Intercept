package com.test.dexe2e;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.util.Log;

import java.io.File;

/**
 * Covers:
 *   load_library.ts -> install_system_library_hooks() ->
 *     System.load(String)          - full filesystem path to .so
 *     System.loadLibrary(String)   - bare library name (no lib prefix, no .so suffix)
 *
 * libdexe2e_native.so is the bundled native library built via CMake.
 * Loading it multiple times on Android is safe (no-op after first load),
 * so both load variants can target the same library without conflicts.
 *
 * Expected events:
 *   library.system.load_library   (method: "System.loadLibrary(String)")
 *   library.system.load           (method: "System.load(String)")
 */
public class SystemLoadLibraryTests {

    private static final String TAG = "DEX_SYS_LOADLIB";

    private int passed = 0;
    private int failed = 0;
    private final Context context;

    public SystemLoadLibraryTests(Context context) {
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
        Log.i(TAG, "SystemLoadLibraryTests: starting");
        Log.i(TAG, "========================================");

        test_system_load_library();
        test_system_load();

        Log.i(TAG, "========================================");
        Log.i(TAG, "SystemLoadLibraryTests summary: " + passed + " passed, " + failed + " failed");
        Log.i(TAG, "========================================");
    }

    private void test_system_load_library() {
        Log.i(TAG, "");
        Log.i(TAG, "=== System.loadLibrary(String) ===");

        try {
            System.loadLibrary("dexe2e_native");
            pass("System.loadLibrary(\"dexe2e_native\")");
        } catch (Throwable t) {
            fail("System.loadLibrary(\"dexe2e_native\")", t.toString());
        }
    }

    private void test_system_load() {
        Log.i(TAG, "");
        Log.i(TAG, "=== System.load(String) ===");

        // Resolve full path from the app's native library directory
        ApplicationInfo ai = context.getApplicationInfo();
        String libPath = ai.nativeLibraryDir + File.separator + "libdexe2e_native.so";
        Log.i(TAG, "Full library path: " + libPath);

        if (!new File(libPath).exists()) {
            fail("System.load - lib file exists", "not found at " + libPath);
            return;
        }

        try {
            System.load(libPath);
            pass("System.load(\"" + libPath + "\")");
        } catch (Throwable t) {
            fail("System.load(fullPath)", t.toString());
        }
    }
}