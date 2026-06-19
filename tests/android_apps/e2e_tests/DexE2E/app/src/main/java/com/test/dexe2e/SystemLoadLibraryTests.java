package com.test.dexe2e;

import android.content.Context;
import android.util.Log;

/**
 * Covers:
 *   load_library.ts -> install_system_library_hooks() ->
 *     System.load(String)          - full filesystem path to .so
 *     System.loadLibrary(String)   - bare library name (no lib prefix, no .so suffix)
 *
 * Test order matters: test_system_load_library() runs first so that
 * libdexe2e_native.so is already mapped before resolveNativeLibPath()
 * scans /proc/self/maps to find its path for the System.load call.
 *
 * On Android (default extractNativeLibs="false", minSdk >= 23) the .so is
 * mapped directly from inside the APK - there is no extracted copy on the
 * filesystem. resolveNativeLibPath handles both cases:
 *   - extracted: returns nativeLibraryDir path directly
 *   - APK-embedded: reads /proc/self/maps to find the base.apk!entry path,
 *     then extracts the zip entry to filesDir to get a real filesystem path
 *
 * System.load on an already-loaded library is a linker no-op, but the Java
 * method call still happens so the hook fires correctly.
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

        // loadLibrary must run before load so the library is mapped
        // and resolveNativeLibPath can find it in /proc/self/maps
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

        // Resolve the real filesystem path of the already-loaded library.
        // Works for both extracted and APK-embedded (non-extracted) cases.
        String libPath = DexTestUtils.resolveNativeLibPath(context, "dexe2e_native");
        if (libPath == null) {
            fail("resolveNativeLibPath(dexe2e_native)", "returned null");
            return;
        }
        Log.i(TAG, "Resolved library path: " + libPath);

        try {
            // Library is already loaded - linker no-ops, but the Java method
            // call is made and the hook fires
            System.load(libPath);
            pass("System.load(\"" + libPath + "\")");
        } catch (Throwable t) {
            fail("System.load(libPath)", t.toString());
        }
    }
}